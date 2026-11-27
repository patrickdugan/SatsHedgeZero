//! Host of the DLC batch wrap guest (SP1 6.9.0).
//!
//! - `dlc-batch-guest elf OUT.elf` — write the guest ELF (built by build.rs) and print its SHA-256.
//! - `dlc-batch-guest vkey` — print the program's verifying-key hash (the SP1 Groth16 `vkey_hash`).
//! - `dlc-batch-guest execute GUEST_DIR OUT.json` — run the guest in SP1's executor on
//!   `GUEST_DIR/{clearing_vk.bin, clearing_proof.bin, guest_in.bin}`, check exit code 0 and that the
//!   public values are `GUEST_DIR/expected_statement.bin`, then run refusal cases (a tampered
//!   settlement, a batch row changed by one sat, a flipped proof byte) and write a receipt.
use anyhow::{ensure, Result};
use lightninger_dlc_batch_relation::GuestIn;
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::{path::Path, time::Instant};

const ELF: Elf = include_elf!("lightninger-dlc-batch-guest");

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn stdin(vk: &[u8], proof: &[u8], g: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write_vec(vk.to_vec());
    s.write_vec(proof.to_vec());
    s.write_vec(g.to_vec());
    s
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("elf") if a.len() == 3 => {
            std::fs::write(&a[2], ELF.as_ref())?;
            println!("{}", sha_hex(ELF.as_ref()));
        }
        Some("vkey") => {
            let client = ProverClient::builder().cpu().build().await;
            let pk = client.setup(ELF).await?;
            println!("{}", pk.verifying_key().bytes32());
        }
        Some("execute") if a.len() == 4 => {
            let d = Path::new(&a[2]);
            let vk = std::fs::read(d.join("clearing_vk.bin"))?;
            let proof = std::fs::read(d.join("clearing_proof.bin"))?;
            let gin = std::fs::read(d.join("guest_in.bin"))?;
            let want = std::fs::read(d.join("expected_statement.bin"))?;
            let client = ProverClient::builder().light().build().await;
            let t = Instant::now();
            let (pv, report) = client.execute(ELF, stdin(&vk, &proof, &gin)).await?;
            let secs = t.elapsed().as_secs_f64();
            ensure!(report.exit_code == 0, "guest exited with code {}", report.exit_code);
            let ok = pv.as_slice() == want.as_slice();
            ensure!(ok, "public values differ from the expected statement");
            eprintln!("honest: {} instructions, {secs:.1}s, statement {}", report.total_instruction_count(), sha_hex(pv.as_slice()));
            // refusals: each must exit non-zero (guest panic) or fail to execute; DLC_GUEST_SKIP_REFUSALS=1 skips them
            let skip = std::env::var("DLC_GUEST_SKIP_REFUSALS").map(|v| v == "1").unwrap_or(false);
            let g: GuestIn = bincode::deserialize(&gin)?;
            let mut cases = Vec::new();
            let mut g1 = g.clone();
            let n = g1.manifest.accounts.len();
            // account 3's payout lowered by one sat, the operator's change raised by one (re-serialized)
            let mut raw = g1.settlement.clone();
            let tx = lightninger_dlc_batch_relation::parse_tx(&raw).map_err(anyhow::Error::msg)?;
            let mut off = None;
            let want3 = tx.outputs[3].0.to_le_bytes();
            for i in 0..raw.len() - 8 {
                if raw[i..i + 8] == want3 && raw[i + 8] as usize == tx.outputs[3].1.len() && raw[i + 9..i + 9 + tx.outputs[3].1.len()] == tx.outputs[3].1[..] {
                    off = Some(i);
                    break;
                }
            }
            let o = off.expect("output 3 in the raw settlement");
            raw[o..o + 8].copy_from_slice(&(tx.outputs[3].0 - 1).to_le_bytes());
            g1.settlement = raw;
            cases.push(("settlement pays account 3 one sat less", bincode::serialize(&g1)?, proof.clone()));
            let mut g2 = g.clone();
            let k = g2.batches.iter().position(|b| b.rows.iter().any(|r| r.net != 0)).unwrap();
            let r = g2.batches[k].rows.iter().position(|r| r.net != 0).unwrap();
            g2.batches[k].rows[r].net += 1;
            cases.push(("one batch row's net changed by one sat", bincode::serialize(&g2)?, proof.clone()));
            let mut p3 = proof.clone();
            let mid = p3.len() / 2;
            p3[mid] ^= 1;
            cases.push(("clearing proof with one bit flipped", gin.clone(), p3));
            let mut g4 = g.clone();
            g4.tap_zk[3][0] ^= 1;
            cases.push(("TapSighash z_K naming another transaction", bincode::serialize(&g4)?, proof.clone()));
            let _ = n;
            let mut refusals = Vec::new();
            for (name, gb, pb) in cases.into_iter().filter(|_| !skip) {
                let r = client.execute(ELF, stdin(&vk, &pb, &gb)).await;
                let (refused, code, err) = match r {
                    Ok((_, rep)) => (rep.exit_code != 0, Some(rep.exit_code), None),
                    Err(e) => (true, None, Some(e.to_string())),
                };
                eprintln!("{name}: refused {refused}");
                ensure!(refused, "{name}: guest accepted");
                refusals.push(serde_json::json!({"case": name, "refused": refused, "exit_code": code, "error": err}));
            }
            let out = serde_json::json!({
                "status": "executed_unproved", "sp1": "6.9.0", "elf_sha256": sha_hex(ELF.as_ref()),
                "clearing_vk_sha256": sha_hex(&vk), "clearing_proof_sha256": sha_hex(&proof), "guest_in_sha256": sha_hex(&gin),
                "instruction_count": report.total_instruction_count(), "execute_seconds": secs, "exit_code": report.exit_code,
                "public_values_hex": hex::encode(pv.as_slice()), "public_values_sha256": sha_hex(pv.as_slice()),
                "public_values_equal_expected_statement": ok, "refusals": refusals,
            });
            std::fs::write(&a[3], serde_json::to_string_pretty(&out)?)?;
        }
        _ => anyhow::bail!("usage: dlc-batch-guest elf OUT.elf | vkey | execute GUEST_DIR OUT.json"),
    }
    Ok(())
}
