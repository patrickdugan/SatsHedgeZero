use super::{Policy, Receipt, parse_transaction, verify};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shz_oracle::pyth_lazer::{
    PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS, PinnedPythSignerRegistry,
    PythProBtcUsdPolicy, VerifiedPythProBtcUsdReceipt, build_signed_pyth_pro_btc_usd_envelope,
    verify_pyth_pro_btc_usd_solana_envelope,
};
use shz_utxoref::mnr02::inverse_long_pnl_trunc_sats;
use shz_utxoref::mnr03::Mnr03ScaleParams;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Funding {
    txid: bitcoin::Txid,
    vout: u32,
    sats: u64,
    script_pubkey_hex: String,
}

#[derive(Deserialize)]
struct Epoch {
    feed_id: u32,
    channel_id: u8,
    publish_time_us: u64,
    feed_update_time_us: u64,
    price_e8: u64,
    whole_price_usd: u64,
    confidence_e8: u64,
    registry_epoch: u64,
    signer_pubkey_hex: String,
    signed_payload_sha256_hex: String,
    receipt_hash_hex: String,
    session_hash_hex: String,
}

#[derive(Deserialize)]
struct Clearing {
    atomic_clearing_txid_hex: bitcoin::Txid,
    atomic_clearing_wtxid_hex: bitcoin::Wtxid,
    settled_price_usd: u64,
    miner_fee_sats: u64,
}

#[derive(Deserialize)]
struct Report {
    network: String,
    anchor_block_hash_hex: String,
    pyth_pro_epoch: Epoch,
    mnr03_clearing: Clearing,
    mnr03_atomic_clearing_raw_segwit_tx_hex: String,
}

#[derive(Deserialize)]
struct Archive {
    funded_dlc_utxos: [Funding; 3],
    oracle_bound_nova_report: Report,
}

/// Receipts come from an independently selected MNR-03 evidence file or fresh
/// Core run. A caller must never let the prover choose this policy source.
pub struct Fixture {
    pub raw: Vec<u8>,
    pub policy: Policy,
}

impl Fixture {
    pub fn from_trusted_archive(data: &str) -> Result<Self> {
        // The frozen regtest capture includes diagnostic lines outside its JSON.
        let start = data.find('{').ok_or("missing trusted archive JSON")?;
        let archive = serde_json::Deserializer::from_str(&data[start..])
            .into_iter::<Archive>()
            .next()
            .ok_or("missing trusted archive payload")??;
        let report = archive.oracle_bound_nova_report;
        let (network, scale, event, published, price_e8, confidence) = match report.network.as_str() {
            "bitcoin-regtest" => (
                Network::Regtest, Mnr03ScaleParams::macro_regtest_33k(150), 1u64,
                1_795_500_000_000_000, 6_000_000_000_000, 1_200_000_000,
            ),
            "bitcoin-testnet4" => (
                Network::Testnet4, Mnr03ScaleParams::micro_testnet4_live(0), 177u64,
                1_795_600_000_000_000, 12_500_000_000_000, 1_500_000_000,
            ),
            _ => return Err("unsupported trusted archive network".into()),
        };
        let (envelope, key) = build_signed_pyth_pro_btc_usd_envelope(
            &[0x88; 32], published, published, PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID, price_e8, -8, confidence,
        );
        let registry = PinnedPythSignerRegistry::new_static(vec![key])?;
        let policy = PythProBtcUsdPolicy::default();
        let oracle = verify_pyth_pro_btc_usd_solana_envelope(
            &envelope, &registry, &policy, published + 1_000_000,
        )?;
        let epoch = report.pyth_pro_epoch;
        let clearing = report.mnr03_clearing;
        if epoch.feed_id != oracle.feed_id
            || epoch.channel_id != oracle.channel_id
            || epoch.publish_time_us != oracle.publish_time_us
            || epoch.feed_update_time_us != oracle.feed_update_time_us
            || epoch.price_e8 != oracle.price_e8
            || epoch.whole_price_usd != oracle.whole_price_usd
            || i64::try_from(epoch.confidence_e8)? != oracle.confidence_mantissa
            || epoch.registry_epoch != oracle.registry_epoch
            || epoch.signer_pubkey_hex != oracle.signer_pubkey_hex
            || epoch.signed_payload_sha256_hex != hex::encode(oracle.signed_payload_sha256)
            || epoch.receipt_hash_hex != hex::encode(oracle.receipt_hash)
            || clearing.settled_price_usd != oracle.whole_price_usd
        {
            return Err("deterministic Pyth fixture differs from trusted epoch or price".into());
        }

        let mut session = Vec::with_capacity(136);
        session.extend_from_slice(&event.to_le_bytes());
        session.extend_from_slice(&oracle.receipt_hash);
        session.extend_from_slice(&oracle.signed_payload_sha256);
        session.extend_from_slice(&hex::decode(clearing.atomic_clearing_txid_hex.to_string())?);
        session.extend_from_slice(&hex::decode(&report.anchor_block_hash_hex)?);
        let epoch_context = crate::statement::tagged_hash("SHZ/MNR03-ORACLE-CLEARING-EPOCH/V1", &session);
        if epoch.session_hash_hex != hex::encode(epoch_context) {
            return Err("clearing session differs from recomputed epoch commitment".into());
        }

        let raw = hex::decode(report.mnr03_atomic_clearing_raw_segwit_tx_hex)?;
        let tx = parse_transaction(&raw)?;
        let mut outputs: [TxOut; 5] = tx.output.try_into().map_err(|_| "trusted fixture output layout")?;
        let price = oracle.whole_price_usd;
        let ab = inverse_long_pnl_trunc_sats(scale.notional_usd, scale.entry_ab_usd, price);
        let bc = inverse_long_pnl_trunc_sats(scale.notional_usd, scale.entry_bc_usd, price);
        let ca = inverse_long_pnl_trunc_sats(scale.notional_usd, scale.entry_ca_usd, price);
        let fee = scale.atomic_clearing_miner_fee_sats;
        if clearing.miner_fee_sats != fee {
            return Err("trusted fixture fee differs from the settlement schedule".into());
        }
        let deduction = i128::from(fee + super::ANCHOR_SATS);
        let payouts = [
            i128::from(scale.bob_ab_margin_sats) - ab,
            i128::from(scale.bob_bc_margin_sats) + bc,
            i128::from(scale.alice_ab_margin_sats) + i128::from(scale.alice_ca_margin_sats)
                + ab - ca - deduction / 2,
            i128::from(scale.carol_bc_margin_sats) + i128::from(scale.carol_ca_margin_sats)
                + ca - bc - (deduction - deduction / 2),
            i128::from(super::ANCHOR_SATS),
        ];
        for (output, amount) in outputs.iter_mut().zip(payouts) {
            output.value = Amount::from_sat(u64::try_from(amount)?);
        }
        let funding = [scale.ab_funding_sats(), scale.bc_funding_sats(), scale.ca_funding_sats()];
        let mut prevouts = Vec::with_capacity(3);
        for (record, agreed_sats) in archive.funded_dlc_utxos.into_iter().zip(funding) {
            if record.sats != agreed_sats {
                return Err("funded original DLC value differs from the fixture schedule".into());
            }
            prevouts.push((
                OutPoint::new(record.txid, record.vout),
                TxOut {
                    script_pubkey: ScriptBuf::from_hex(&record.script_pubkey_hex)?,
                    value: Amount::from_sat(record.sats),
                },
            ));
        }
        let policy = Policy {
            network, prevouts: prevouts.try_into().map_err(|_| "trusted funding layout")?,
            outputs, txid: clearing.atomic_clearing_txid_hex, wtxid: clearing.atomic_clearing_wtxid_hex,
            lock_time: tx.lock_time.to_consensus_u32(), fee_sats: fee, epoch_context,
        };
        let fixture = Self { raw, policy };
        fixture.verify(&fixture.raw)?;
        Ok(fixture)
    }

    pub fn verify(&self, candidate: &[u8]) -> std::result::Result<Receipt, super::Error> {
        verify(candidate, &self.policy)
    }
}



/// Check an external envelope with a verifier-selected registry digest.
/// Authenticating the registry and observation time belongs to the evidence profile.
pub fn verify_external_oracle(
    envelope: &[u8],
    registry_bytes: &[u8],
    trusted_registry_sha256: &str,
    observed_at_us: u64,
) -> Result<VerifiedPythProBtcUsdReceipt> {
    if hex::encode(Sha256::digest(registry_bytes)) != trusted_registry_sha256 {
        return Err("external Pyth registry differs from independently pinned digest".into());
    }
    let registry: PinnedPythSignerRegistry = serde_json::from_slice(registry_bytes)?;
    let receipt = verify_pyth_pro_btc_usd_solana_envelope(
        envelope,
        &registry,
        &PythProBtcUsdPolicy::default(),
        observed_at_us,
    )?;
    if receipt.signer_pubkey_hex == "b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc" {
        return Err("the deterministic MNR-03 test signer cannot supply external evidence".into());
    }
    Ok(receipt)
}

#[derive(serde::Serialize)]
pub struct Probe {
    pub case: &'static str,
    pub rejection: String,
}

impl Fixture {
    pub fn probe_transactions(&self) -> Result<Vec<Probe>> {
        use super::Error;
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::serialize;

        let tx = parse_transaction(&self.raw)?;
        let mut results = Vec::new();
        let mut probe = |case, candidate: bitcoin::Transaction, expected| {
            let rejection = match self.verify(&serialize(&candidate)) {
                Ok(_) => return Err(format!("{case} accepted despite mutation")),
                Err(error) => error,
            };
            if rejection != expected {
                return Err(format!("{case} rejected for {rejection}; expected {expected}"));
            }
            results.push(Probe { case, rejection: rejection.to_string() });
            Ok(())
        };
        for (index, label) in ["bob_ab_minus_one_sat", "bob_bc_minus_one_sat"].into_iter().enumerate() {
            let mut changed = tx.clone();
            changed.output[index].value -= Amount::ONE_SAT;
            probe(label, changed, Error::Signature(index))?;
        }
        let mut changed = tx.clone();
        changed.output.swap(0, 1);
        probe("bob_outputs_swapped", changed, Error::Signature(0))?;
        let mut changed = tx.clone();
        changed.input.swap(0, 1);
        probe("ordered_inputs_swapped", changed, Error::Outpoint)?;
        let mut changed = tx.clone();
        changed.input[0].previous_output.vout ^= 1 << 31;
        probe("funding_outpoint_substituted", changed, Error::Outpoint)?;
        let mut changed = tx.clone();
        changed.input[1].previous_output = tx.input[0].previous_output;
        probe("funding_outpoint_double_consumed", changed, Error::DoubleSpend)?;
        let mut changed = tx.clone();
        changed.output[4].value += Amount::ONE_SAT;
        probe("anchor_and_fee_changed", changed, Error::Fee)?;
        let mut changed = tx.clone();
        changed.output[2].value += Amount::ONE_SAT;
        probe("online_payout_and_fee_changed", changed, Error::Signature(0))?;
        let mut changed = tx.clone();
        changed.lock_time = LockTime::from_consensus(tx.lock_time.to_consensus_u32() + 1);
        probe("locktime_changed", changed, Error::Timing)?;
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGTEST: &str = include_str!("../../../../evidence/mnr03_bob_offline_core_nova_receipt.json");
    const TESTNET4: &str = include_str!("../../../../evidence/mnr03_testnet4_bob_offline_receipt.json");

    #[test]
    fn archived_exact_clearings_and_mutations() {
        let regtest = Fixture::from_trusted_archive(REGTEST).unwrap();
        let native = regtest.verify(&regtest.raw).unwrap();
        assert_eq!(native.payout_sats, [55_000_000, 35_000_000, 71_498_500, 82_498_500, 330]);
        assert_eq!(native.fee_sats, 2670);
        assert_eq!(regtest.probe_transactions().unwrap().len(), 9);

        let testnet4 = Fixture::from_trusted_archive(TESTNET4).unwrap();
        let native = testnet4.verify(&testnet4.raw).unwrap();
        assert_eq!(native.txid, "ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1");
        assert_eq!(native.wtxid, "3ffb76424476f676055bd9e549cf6759196528cfcd51e761ee7f37132db847cd");
        assert_eq!(native.payout_sats, [450, 550, 1050, 910, 330]);
        assert_eq!(testnet4.probe_transactions().unwrap().len(), 9);
    }

    #[test]
    fn external_evidence_rejects_the_test_signer_and_unpinned_registry() {
        let publish = 1_795_600_000_000_000;
        let (raw, key) = build_signed_pyth_pro_btc_usd_envelope(
            &[0x88; 32], publish, publish, PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID, 12_500_000_000_000, -8, 1_500_000_000,
        );
        let registry = serde_json::to_vec(&PinnedPythSignerRegistry::new_static(vec![key]).unwrap()).unwrap();
        let pin = hex::encode(Sha256::digest(&registry));
        let wrong_pin = verify_external_oracle(&raw, &registry, &"0".repeat(64), publish + 1_000_000).unwrap_err();
        assert!(wrong_pin.to_string().contains("independently pinned digest"));
        let test_signer = verify_external_oracle(&raw, &registry, &pin, publish + 1_000_000).unwrap_err();
        assert!(test_signer.to_string().contains("deterministic MNR-03 test signer"));
    }
    #[test]
    fn rejects_oracle_epoch_and_clearing_price_changes() {
        let epoch_swapped = TESTNET4.replace(
            "7a0a6d8d97a231fd0adcef7892d29232d131adfe8c92391deb228b9dd598e51e",
            "da9a2bf4500b22e346c75553ea41f2ea0d240e50f8c8bd708594dafe763d39c3",
        );
        assert_ne!(epoch_swapped, TESTNET4);
        assert!(Fixture::from_trusted_archive(&epoch_swapped).is_err());
        let price_changed = TESTNET4.replace("\"settled_price_usd\": 125000", "\"settled_price_usd\": 125001");
        assert_ne!(price_changed, TESTNET4);
        assert!(Fixture::from_trusted_archive(&price_changed).is_err());
    }
}
