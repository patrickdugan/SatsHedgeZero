use std::fs;
use std::path::Path;

use serde_json::json;
use shz_nova_bitvm::mnr04::fixture::Fixture;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fixture(path: &str) -> Result<Fixture> {
    Fixture::from_trusted_archive(&fs::read_to_string(path)?)
}

pub fn run(command: &str, args: &[String]) -> Result<()> {
    let values: Vec<_> = args.iter().map(String::as_str).collect();
    let result = match (command, values.as_slice()) {
        ("mnr04-oracle-external", [envelope, registry, trusted_digest, observed]) => {
            let receipt = shz_nova_bitvm::mnr04::fixture::verify_external_oracle(
                &fs::read(envelope)?,
                &fs::read(registry)?,
                trusted_digest,
                observed.parse()?,
            )?;
            json!({"external_oracle_native": receipt, "linked_to_clearing": false})
        }
        ("mnr04-native", [trusted]) => {
            let fixture = fixture(trusted)?;
            json!({
                "native": fixture.verify(&fixture.raw)?,
                "native_negative_controls": fixture.probe_transactions()?,
                "fresh_core_replay": false,
                "operational_pyth_provenance_verified": false,
            })
        }
        ("mnr04-regtest", [bitcoind, export]) => {
            let bitcoind = Path::new(bitcoind);
            let version = std::process::Command::new(bitcoind).arg("--version").output()?;
            let stdout = String::from_utf8(version.stdout)?;
            if !version.status.success()
                || stdout.lines().next() != Some("Bitcoin Core daemon version v31.1.0 bitcoind")
            {
                return Err("mnr04-regtest requires Bitcoin Core 31.1.0".into());
            }
            let core = crate::mnr03_harness::run_mnr03_core_regtest(bitcoind, None, None);
            let trusted = serde_json::to_string_pretty(&core)?;
            let fixture = Fixture::from_trusted_archive(&trusted)?;
            let native = fixture.verify(&fixture.raw)?;
            let confirmed = &core.core_confirmed_bob_offline_clearing_tx;
            let accepted = serde_json::to_value(confirmed)?;
            if accepted["txid"] != native.txid || accepted["wtxid"] != native.wtxid
                || !core.bitcoin_spend_enforced
                || !core.unilateral_cltv_fallback_verified
                || !core.cpfp_anchor_child_confirmed
                || !core.reorg_watchtower_drill_passed
            {
                return Err("Core replay did not establish the expected clearing and safety drills".into());
            }
            use std::io::Write;
            fs::OpenOptions::new().write(true).create_new(true).open(export)?.write_all(trusted.as_bytes())?;
            json!({
                "native": native,
                "native_negative_controls": fixture.probe_transactions()?,
                "core_version": core.core_version,
                "fresh_core_replay": true,
                "consensus_accepted": core.bitcoin_spend_enforced,
                "unilateral_fallback": core.unilateral_cltv_fallback_verified,
                "cpfp_anchor_confirmed": core.cpfp_anchor_child_confirmed,
                "reorg_watchtower_frozen": core.reorg_watchtower_drill_passed,
                "core_negative_controls": core.adversarial_probes,
                "operational_pyth_provenance_verified": false,
                "public_transactions_broadcast": false,
            })
        }
        #[cfg(feature = "mnr04-nova")]
        ("mnr04-prove", [trusted, out]) => {
            let fixture = fixture(trusted)?;
            json!(shz_nova_bitvm::mnr04::nova::prove(&fixture, &fixture.raw, Path::new(out))?)
        }
        #[cfg(feature = "mnr04-nova")]
        ("mnr04-verify", [trusted, out, pinned_hash]) => {
            let fixture = fixture(trusted)?;
            json!(shz_nova_bitvm::mnr04::nova::verify_saved(&fixture, &fixture.raw, Path::new(out), pinned_hash)?)
        }
        #[cfg(feature = "mnr04-nova")]
        ("mnr04-key-hash", [trusted]) => {
            let fixture = fixture(trusted)?;
            json!({"vk_sha256": shz_nova_bitvm::mnr04::nova::key_hash(&fixture, &fixture.raw)?})
        }
        _ => return Err(concat!(
            "usage: mnr04-native TRUSTED_ARCHIVE | mnr04-regtest BITCOIND EXPORT_ARCHIVE | ",
            "mnr04-prove TRUSTED_ARCHIVE NEW_PROOF_DIR | mnr04-key-hash TRUSTED_ARCHIVE | ",
            "mnr04-verify TRUSTED_ARCHIVE PROOF_DIR TRUSTED_VK_SHA256. ",
            "mnr04-oracle-external ENVELOPE REGISTRY TRUSTED_REGISTRY_SHA256 OBSERVED_AT_US. ",
            "The proof commands require --features mnr04-nova."
        ).into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
