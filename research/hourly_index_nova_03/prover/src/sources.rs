//! Authentic Pyth Pro (`pyth-lazer`) and Chainlink Data Streams v3 BTC/USD source
//! verification, operational Solana Mainnet signer-registry parsing, DON secp256k1
//! `ecrecover` quorum verification, and anti-cherry-picking window selection.
//!
//! Strictly separates `OperationalMainnetPinned` provenance from `SyntheticTestOnly`
//! test profiles: synthetic keys NEVER set `operational_source_authenticated: true`.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey as EdVerifyingKey;
use k256::ecdsa::{RecoveryId, Signature as SecpSignature, SigningKey as SecpSigningKey, VerifyingKey as SecpVerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use shz_oracle::pyth_lazer::{
    PinnedPythSignerEntry, PinnedPythSignerRegistry, PythProBtcUsdPolicy,
    PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS,
    build_signed_pyth_pro_btc_usd_envelope, verify_pyth_pro_btc_usd_solana_envelope,
};

/// Official Solana Mainnet `pyth-lazer` program ID (`pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt`).
pub const PYTH_LAZER_SOLANA_PROGRAM_ID: &str = "pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt";

/// Official Solana Mainnet `pyth-lazer` `Storage` PDA (`3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL`).
pub const PYTH_LAZER_SOLANA_STORAGE_PDA: &str = "3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL";

/// Anchor 8-byte account discriminator for `pyth_lazer_solana_contract::Storage`.
pub const PYTH_LAZER_STORAGE_DISCRIMINATOR: [u8; 8] = [0xd1, 0x75, 0xff, 0xb9, 0xc4, 0xaf, 0x44, 0x09];

/// Captured live `381`-byte Solana Mainnet `Storage` PDA account data (`3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL`).
pub const PYTH_LAZER_MAINNET_STORAGE_SNAPSHOT_HEX: &str = concat!(
    "d175ffb9c4af4409",
    "5635979a221c34931e32620b9293a463065555ea71fe97cd6237ade875b12e9e",
    "ecfa08ad5971de28f8dce8d352d91d8e83f99cde4ffb827ec4874139011fb575",
    "0100000000000000",
    "01",
    "80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c",
    "b956587a00000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "01",
    "26fb61a864c758ae9fba027a96010480658385b9",
    "5975ab7a00000000",
    "00000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
);

/// Official archived signed Pyth Pro (`pyth-lazer`) `Crypto.BTC/USD` Solana wire envelope
/// from `pyth-network/pyth-lazer-public`, signed by operational Solana Mainnet key `80efc1f4...`.
pub const OFFICIAL_PYTH_PRO_BTC_USD_WIRE_HEX: &str = concat!(
    "b9011a82c7887f3aaa5845b20d6bf5ca6609953b57650fa4579a4b4d34a4980ba608a9f76a825a446",
    "f3d6c1fd9daca1c5e3fc46980f14ef89c1a886c6e9e5c510872d30f80efc1f480c5615af3fb673d422",
    "87e993da9fbc3506b6e41dfa32950820c2e6c620075d3c7934077d115064b06000301010000000d009",
    "032fc171b060000014e3a0cff1a06000002bcda8a211b06000003120004f8ff05fc0b7159000000000",
    "600070008000900000aa06616362e0600000b804f93312e0600000c014077d115064b0600"
);

/// Official Chainlink Data Streams v3 Feed ID for `BTC/USD-RefPrice-DS-Premium-Global-003`.
pub const CHAINLINK_BTC_USD_V3_FEED_ID_HEX: &str =
    "00032cb071237a34710156d953df013bf366115982705b76615b3c3b064375b8";

/// Official Arbitrum One `VerifierProxy` contract address for Chainlink Data Streams.
pub const CHAINLINK_ARBITRUM_ONE_VERIFIER_PROXY: &str =
    "0x478Aa2aC9F6D65F84e09D9185d126c3a17c2a93C";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProfile {
    OperationalMainnetPinned,
    SyntheticTestOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSolanaPythLazerStorage {
    pub program_id: String,
    pub storage_pda: String,
    pub top_authority_hex: String,
    pub treasury_hex: String,
    pub single_update_fee_lamports: u64,
    pub trusted_ed25519_signers: Vec<(String, u64)>,
    pub trusted_ecdsa_evm_signers: Vec<(String, u64)>,
}

/// Parses and authenticates the `381`-byte Anchor `Storage` account from Solana Mainnet `pyth-lazer`.
pub fn parse_solana_pyth_lazer_storage_account(raw: &[u8]) -> Result<ParsedSolanaPythLazerStorage, String> {
    if raw.len() != 381 {
        return Err(format!("expected 381-byte Solana pyth-lazer Storage account, got {}", raw.len()));
    }
    if raw[0..8] != PYTH_LAZER_STORAGE_DISCRIMINATOR {
        return Err("wrong Anchor Storage discriminator".into());
    }
    let top_authority_hex = hex::encode(&raw[8..40]);
    let treasury_hex = hex::encode(&raw[40..72]);
    let single_update_fee_lamports = u64::from_le_bytes(raw[72..80].try_into().unwrap());
    let num_ed = raw[80] as usize;
    if num_ed == 0 || num_ed > 5 {
        return Err("invalid num_trusted_signers in Solana Storage".into());
    }
    let mut trusted_ed25519_signers = Vec::with_capacity(num_ed);
    for i in 0..num_ed {
        let off = 81 + i * 40;
        let pk: [u8; 32] = raw[off..off + 32].try_into().unwrap();
        EdVerifyingKey::from_bytes(&pk).map_err(|_| "invalid Ed25519 pubkey in Solana Storage")?;
        let expires_sec = i64::from_le_bytes(raw[off + 32..off + 40].try_into().unwrap());
        if expires_sec <= 0 {
            return Err("non-positive signer expiry in Solana Storage".into());
        }
        trusted_ed25519_signers.push((hex::encode(pk), expires_sec as u64));
    }
    let ecdsa_off = 81 + 5 * 40;
    let num_ecdsa = raw[ecdsa_off] as usize;
    if num_ecdsa > 2 {
        return Err("invalid num_trusted_ecdsa_signers in Solana Storage".into());
    }
    let mut trusted_ecdsa_evm_signers = Vec::with_capacity(num_ecdsa);
    for i in 0..num_ecdsa {
        let off = ecdsa_off + 1 + i * 28;
        let addr = hex::encode(&raw[off..off + 20]);
        let expires_sec = i64::from_le_bytes(raw[off + 20..off + 28].try_into().unwrap());
        if expires_sec > 0 {
            trusted_ecdsa_evm_signers.push((format!("0x{addr}"), expires_sec as u64));
        }
    }
    Ok(ParsedSolanaPythLazerStorage {
        program_id: PYTH_LAZER_SOLANA_PROGRAM_ID.into(),
        storage_pda: PYTH_LAZER_SOLANA_STORAGE_PDA.into(),
        top_authority_hex,
        treasury_hex,
        single_update_fee_lamports,
        trusted_ed25519_signers,
        trusted_ecdsa_evm_signers,
    })
}

pub fn build_operational_pyth_registry_from_solana_storage(
    storage_bytes: &[u8],
    registry_epoch: u64,
) -> Result<(PinnedPythSignerRegistry, ParsedSolanaPythLazerStorage), String> {
    let parsed = parse_solana_pyth_lazer_storage_account(storage_bytes)?;
    let mut entries = Vec::with_capacity(parsed.trusted_ed25519_signers.len());
    for (pk_hex, exp_sec) in &parsed.trusted_ed25519_signers {
        let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        entries.push(PinnedPythSignerEntry {
            pubkey: pk,
            valid_from_us: 0,
            valid_until_us: Some(exp_sec.saturating_mul(1_000_000)),
            revoked: false,
        });
    }
    let mut reg = PinnedPythSignerRegistry::new_static(
        entries.iter().map(|e| e.pubkey).collect(),
    )
    .map_err(|e| e.to_string())?;
    reg.registry_epoch = registry_epoch;
    reg.signers = entries;
    Ok((reg, parsed))
}

/// Chainlink Data Streams DON configuration (`Verifier.sol` `VerifierConfig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainlinkDonVerifierConfig {
    pub profile: SourceProfile,
    pub config_digest: [u8; 32],
    pub feed_id: [u8; 32],
    /// Fault tolerance `f`: valid report requires `>= f + 1` distinct authorized DON signers.
    pub f: u8,
    /// Authorized 20-byte Ethereum addresses (`keccak256(uncompressed_pubkey[1..65])[12..32]`).
    pub signers: Vec<[u8; 20]>,
}

/// Decoded Chainlink Data Streams v3 Crypto Report (`smartcontractkit/data-streams-sdk/go/report/v3`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedChainlinkV3Report {
    pub config_digest: [u8; 32],
    pub epoch_and_round: [u8; 32],
    pub extra_hash: [u8; 32],
    pub feed_id: [u8; 32],
    pub valid_from_timestamp_sec: u64,
    pub observations_timestamp_sec: u64,
    pub native_fee_wei: u128,
    pub link_fee_wei: u128,
    pub expires_at_sec: u64,
    pub benchmark_price_e18: i128,
    pub bid_e18: i128,
    pub ask_e18: i128,
    pub price_e8: u64,
    pub observations_timestamp_us: u64,
    pub verified_don_signers: Vec<String>,
    /// `SHA256(full_report_bytes)` — exact 32-byte digest committed in the `INDEX-01` hourly leaf!
    pub full_report_sha256: [u8; 32],
    /// `keccak256(abi.encode(keccak256(reportBlob), reportContext))` signed by the DON.
    pub don_signing_hash_keccak256: [u8; 32],
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn evm_address_from_secp_vk(vk: &SecpVerifyingKey) -> [u8; 20] {
    let uncompressed = vk.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    assert_eq!(bytes.len(), 65);
    let digest = keccak256(&bytes[1..65]);
    digest[12..32].try_into().unwrap()
}

fn read_word32(buf: &[u8], offset: usize) -> Result<[u8; 32], String> {
    let end = offset.checked_add(32).ok_or("ABI offset overflow")?;
    buf.get(offset..end)
        .ok_or_else(|| "truncated Chainlink ABI payload".to_owned())
        .map(|s| s.try_into().unwrap())
}

fn word_to_usize(w: &[u8; 32]) -> Result<usize, String> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err("ABI offset/length exceeds u64".into());
    }
    let v = u64::from_be_bytes(w[24..32].try_into().unwrap());
    usize::try_from(v).map_err(|_| "ABI usize overflow".into())
}

fn word_to_u64(w: &[u8; 32]) -> Result<u64, String> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err("ABI uint64 high bytes non-zero".into());
    }
    Ok(u64::from_be_bytes(w[24..32].try_into().unwrap()))
}

fn word_to_u128_from_u192(w: &[u8; 32]) -> Result<u128, String> {
    if w[..16].iter().any(|&b| b != 0) {
        return Err("ABI fee exceeds u128".into());
    }
    Ok(u128::from_be_bytes(w[16..32].try_into().unwrap()))
}

fn word_to_positive_i128_from_int192(w: &[u8; 32]) -> Result<i128, String> {
    // Reject negative int256/int192 (MSB sign bit set) or values overflowing positive i128
    if (w[0] & 0x80) != 0 {
        return Err("negative Chainlink int192 price".into());
    }
    if w[..16].iter().any(|&b| b != 0) || (w[16] & 0x80) != 0 {
        return Err("Chainlink int192 price overflows i128".into());
    }
    let v = i128::from_be_bytes(w[16..32].try_into().unwrap());
    if v <= 0 {
        return Err("non-positive Chainlink price".into());
    }
    Ok(v)
}

/// Strictly decodes and verifies a Chainlink Data Streams v3 `fullReport` against `don_cfg`,
/// reproducing `smartcontractkit/chainlink`'s `Verifier.sol` + `data-streams-sdk/go/report/v3`.
pub fn verify_chainlink_v3_full_report(
    full_report: &[u8],
    don_cfg: &ChainlinkDonVerifierConfig,
) -> Result<DecodedChainlinkV3Report, String> {
    if don_cfg.f == 0 && don_cfg.signers.is_empty() {
        return Err("empty Chainlink DON signer set".into());
    }
    let min_signers = usize::from(don_cfg.f)
        .checked_add(1)
        .ok_or("DON f overflow")?;
    if don_cfg.signers.len() < min_signers || don_cfg.signers.len() > 31 {
        return Err("invalid Chainlink DON signer count (must be in f+1..=31)".into());
    }
    if full_report.len() < 224 || full_report.len() > 16_384 || full_report.len() % 32 != 0 {
        return Err("invalid Chainlink fullReport ABI byte length".into());
    }

    // Outer ABI head (`224` bytes = 7 words):
    // [0..32]   reportContext[0] (configDigest)
    // [32..64]  reportContext[1] (epochAndRound)
    // [64..96]  reportContext[2] (extraHash)
    // [96..128] offset to reportBlob (bytes)
    // [128..160] offset to rawRs (bytes32[])
    // [160..192] offset to rawSs (bytes32[])
    // [192..224] rawVs (bytes32)
    let config_digest = read_word32(full_report, 0)?;
    let epoch_and_round = read_word32(full_report, 32)?;
    let extra_hash = read_word32(full_report, 64)?;
    if config_digest != don_cfg.config_digest {
        return Err("Chainlink report configDigest mismatch".into());
    }

    let blob_off = word_to_usize(&read_word32(full_report, 96)?)?;
    let rs_off = word_to_usize(&read_word32(full_report, 128)?)?;
    let ss_off = word_to_usize(&read_word32(full_report, 160)?)?;
    let raw_vs = read_word32(full_report, 192)?;

    if blob_off != 224 {
        return Err("non-canonical Chainlink reportBlob ABI offset".into());
    }
    let blob_len = word_to_usize(&read_word32(full_report, blob_off)?)?;
    if blob_len != 288 {
        return Err(format!("expected 288-byte v3 reportBlob, got {blob_len}"));
    }
    let report_blob = &full_report[blob_off + 32..blob_off + 32 + 288];
    if rs_off != blob_off + 32 + 288 {
        return Err("non-canonical Chainlink rawRs ABI offset".into());
    }

    let rs_len = word_to_usize(&read_word32(full_report, rs_off)?)?;
    if rs_len < min_signers || rs_len > 31 {
        return Err(format!(
            "insufficient Chainlink DON signatures: got {rs_len}, need >= {min_signers}"
        ));
    }
    let expected_ss_off = rs_off + 32 + rs_len * 32;
    if ss_off != expected_ss_off {
        return Err("non-canonical Chainlink rawSs ABI offset".into());
    }
    let ss_len = word_to_usize(&read_word32(full_report, ss_off)?)?;
    if ss_len != rs_len {
        return Err("Chainlink rawRs / rawSs length mismatch".into());
    }
    let expected_total_len = ss_off + 32 + ss_len * 32;
    if full_report.len() != expected_total_len {
        return Err("trailing or truncated bytes in Chainlink fullReport".into());
    }
    // Unused trailing rawVs bytes must be zero
    if raw_vs[rs_len..].iter().any(|&b| b != 0) {
        return Err("non-zero trailing bytes in Chainlink rawVs".into());
    }

    // Compute exact Verifier.sol signing digest:
    // h = keccak256(abi.encode(keccak256(reportBlob), reportContext))
    let report_keccak = keccak256(report_blob);
    let mut sig_preimage = [0u8; 128];
    sig_preimage[0..32].copy_from_slice(&report_keccak);
    sig_preimage[32..64].copy_from_slice(&config_digest);
    sig_preimage[64..96].copy_from_slice(&epoch_and_round);
    sig_preimage[96..128].copy_from_slice(&extra_hash);
    let signing_hash = keccak256(&sig_preimage);

    // Recover and authorize every DON signer via secp256k1 ECDSA recovery (strictly unique!)
    let allowed: BTreeSet<[u8; 20]> = don_cfg.signers.iter().copied().collect();
    let mut seen_signers = BTreeSet::new();
    let mut verified_don_signers = Vec::with_capacity(rs_len);

    for i in 0..rs_len {
        let r_bytes = read_word32(full_report, rs_off + 32 + i * 32)?;
        let s_bytes = read_word32(full_report, ss_off + 32 + i * 32)?;
        let v_raw = raw_vs[i];
        let v_id = match v_raw {
            0 | 1 => v_raw,
            27 | 28 => v_raw - 27,
            _ => return Err("invalid Chainlink ECDSA recovery id v".into()),
        };
        let mut sig64 = [0u8; 64];
        sig64[0..32].copy_from_slice(&r_bytes);
        sig64[32..64].copy_from_slice(&s_bytes);
        let sig = SecpSignature::from_slice(&sig64).map_err(|_| "invalid secp256k1 r/s")?;
        // Enforce EIP-2 low-S malleability protection
        if bool::from(sig.normalize_s().is_some()) {
            return Err("high-S malleable Chainlink DON signature rejected".into());
        }
        let recid = RecoveryId::from_byte(v_id).ok_or("invalid RecoveryId")?;
        let vk = SecpVerifyingKey::recover_from_prehash(&signing_hash, &sig, recid)
            .map_err(|_| "Chainlink secp256k1 ecrecover failed")?;
        let addr = evm_address_from_secp_vk(&vk);
        if !allowed.contains(&addr) {
            return Err(format!("unauthorized Chainlink DON signer 0x{}", hex::encode(addr)));
        }
        if !seen_signers.insert(addr) {
            return Err("duplicate Chainlink DON signer in quorum".into());
        }
        verified_don_signers.push(format!("0x{}", hex::encode(addr)));
    }

    // Decode inner 288-byte v3.Data ONLY after DON signature quorum verification succeeds!
    let feed_id = read_word32(report_blob, 0)?;
    if feed_id[0..2] != [0x00, 0x03] {
        return Err("Chainlink reportBlob feedId is not schema v3 (0x0003)".into());
    }
    if feed_id != don_cfg.feed_id {
        return Err("Chainlink feedId mismatch".into());
    }
    let valid_from_sec = word_to_u64(&read_word32(report_blob, 32)?)?;
    let observations_sec = word_to_u64(&read_word32(report_blob, 64)?)?;
    let native_fee_wei = word_to_u128_from_u192(&read_word32(report_blob, 96)?)?;
    let link_fee_wei = word_to_u128_from_u192(&read_word32(report_blob, 128)?)?;
    let expires_at_sec = word_to_u64(&read_word32(report_blob, 160)?)?;
    let benchmark_price_e18 = word_to_positive_i128_from_int192(&read_word32(report_blob, 192)?)?;
    let bid_e18 = word_to_positive_i128_from_int192(&read_word32(report_blob, 224)?)?;
    let ask_e18 = word_to_positive_i128_from_int192(&read_word32(report_blob, 256)?)?;

    if observations_sec < valid_from_sec || expires_at_sec <= observations_sec {
        return Err("invalid Chainlink v3 timestamp ordering (validFrom <= obs < expiresAt)".into());
    }
    if ask_e18 < bid_e18 || benchmark_price_e18 < bid_e18 || benchmark_price_e18 > ask_e18 {
        return Err("Chainlink v3 bid/benchmark/ask ordering violated".into());
    }

    // Normalize 1e18 USD -> 1e8 USD (floor integer division by 10^10)
    let price_e8_i128 = benchmark_price_e18 / 10_000_000_000i128;
    let price_e8 = u64::try_from(price_e8_i128).map_err(|_| "Chainlink price_e8 overflow")?;
    if price_e8 == 0 || price_e8 > 10_000_000_000_000_000 {
        return Err("Chainlink price_e8 out of SHZ bounds".into());
    }
    let observations_timestamp_us = observations_sec
        .checked_mul(1_000_000)
        .ok_or("Chainlink observations_us overflow")?;

    Ok(DecodedChainlinkV3Report {
        config_digest,
        epoch_and_round,
        extra_hash,
        feed_id,
        valid_from_timestamp_sec: valid_from_sec,
        observations_timestamp_sec: observations_sec,
        native_fee_wei,
        link_fee_wei,
        expires_at_sec,
        benchmark_price_e18,
        bid_e18,
        ask_e18,
        price_e8,
        observations_timestamp_us,
        verified_don_signers,
        full_report_sha256: sha256(full_report),
        don_signing_hash_keccak256: signing_hash,
    })
}

/// Deterministic test-only encoder for a signed Chainlink Data Streams v3 `fullReport`.
/// Used exclusively under `SourceProfile::SyntheticTestOnly`.
#[allow(clippy::too_many_arguments)]
pub fn encode_and_sign_synthetic_chainlink_v3_report(
    config_digest: [u8; 32],
    epoch: u32,
    round: u8,
    feed_id: [u8; 32],
    valid_from_sec: u64,
    observations_sec: u64,
    expires_at_sec: u64,
    price_e8: u64,
    half_spread_e8: u64,
    oracle_secret_keys: &[[u8; 32]],
) -> Vec<u8> {
    let mut epoch_and_round = [0u8; 32];
    epoch_and_round[27..31].copy_from_slice(&epoch.to_be_bytes());
    epoch_and_round[31] = round;
    let extra_hash = [0u8; 32];

    let benchmark_e18 = u128::from(price_e8) * 10_000_000_000u128;
    let bid_e18 = u128::from(price_e8.saturating_sub(half_spread_e8)) * 10_000_000_000u128;
    let ask_e18 = u128::from(price_e8.saturating_add(half_spread_e8)) * 10_000_000_000u128;

    let put_u64 = |buf: &mut Vec<u8>, v: u64| {
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&v.to_be_bytes());
        buf.extend_from_slice(&w);
    };
    let put_u128 = |buf: &mut Vec<u8>, v: u128| {
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&v.to_be_bytes());
        buf.extend_from_slice(&w);
    };

    let mut report_blob = Vec::with_capacity(288);
    report_blob.extend_from_slice(&feed_id);
    put_u64(&mut report_blob, valid_from_sec);
    put_u64(&mut report_blob, observations_sec);
    put_u128(&mut report_blob, 0); // nativeFee
    put_u128(&mut report_blob, 0); // linkFee
    put_u64(&mut report_blob, expires_at_sec);
    put_u128(&mut report_blob, benchmark_e18);
    put_u128(&mut report_blob, bid_e18);
    put_u128(&mut report_blob, ask_e18);
    assert_eq!(report_blob.len(), 288);

    let report_keccak = keccak256(&report_blob);
    let mut sig_preimage = [0u8; 128];
    sig_preimage[0..32].copy_from_slice(&report_keccak);
    sig_preimage[32..64].copy_from_slice(&config_digest);
    sig_preimage[64..96].copy_from_slice(&epoch_and_round);
    sig_preimage[96..128].copy_from_slice(&extra_hash);
    let signing_hash = keccak256(&sig_preimage);

    let k = oracle_secret_keys.len();
    let mut rs = Vec::with_capacity(k);
    let mut ss = Vec::with_capacity(k);
    let mut raw_vs = [0u8; 32];

    for (i, sk_bytes) in oracle_secret_keys.iter().enumerate() {
        let sk = SecpSigningKey::from_bytes(sk_bytes.into()).expect("valid secp256k1 secret");
        let (sig, recid) = sk
            .sign_prehash_recoverable(&signing_hash)
            .expect("recoverable DON sig");
        let sig_bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        rs.push(r);
        ss.push(s);
        raw_vs[i] = recid.to_byte();
    }

    let blob_off = 224u64;
    let rs_off = blob_off + 32 + 288;
    let ss_off = rs_off + 32 + (k as u64) * 32;

    let mut out = Vec::with_capacity((ss_off as usize) + 32 + k * 32);
    out.extend_from_slice(&config_digest);
    out.extend_from_slice(&epoch_and_round);
    out.extend_from_slice(&extra_hash);
    put_u64(&mut out, blob_off);
    put_u64(&mut out, rs_off);
    put_u64(&mut out, ss_off);
    out.extend_from_slice(&raw_vs);

    put_u64(&mut out, 288);
    out.extend_from_slice(&report_blob);

    put_u64(&mut out, k as u64);
    for r in &rs {
        out.extend_from_slice(r);
    }
    put_u64(&mut out, k as u64);
    for s in &ss {
        out.extend_from_slice(s);
    }
    out
}

/// Authenticated Hourly Source Bundle binding raw signed Pyth Pro & Chainlink v3 reports
/// to an `INDEX-01` hourly observation or necessary `HOLD` candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedHourSourceBundle {
    pub profile: SourceProfile,
    pub operational_source_authenticated: bool,
    pub hour_id: u64,
    pub pyth_present: bool,
    pub chainlink_present: bool,
    pub pyth_raw_envelope_hex: Option<String>,
    pub chainlink_full_report_hex: Option<String>,
    pub pyth_registry_epoch: u64,
    pub chainlink_config_digest_hex: String,
    pub candidate_pyth_price_e8: u64,
    pub candidate_chainlink_price_e8: u64,
    pub candidate_pyth_publish_us: u64,
    pub candidate_chainlink_publish_us: u64,
    pub candidate_pyth_report_sha256_hex: String,
    pub candidate_chainlink_report_sha256_hex: String,
}

/// Canonical domain for committing an hour's authenticated source-candidate summary.
pub const SOURCE_CANDIDATE_DOMAIN: &[u8] = b"SHZ/SOURCE/CAND/V1";
pub const SOURCE_NODE_DOMAIN: &[u8] = b"SHZ/SOURCE/NODE/V1";

pub fn source_candidate_leaf_bytes(
    hour_id: u64,
    pyth_present: bool,
    chainlink_present: bool,
    pyth_e8: u64,
    chainlink_e8: u64,
    pyth_us: u64,
    chainlink_us: u64,
    pyth_sha256: &[u8; 32],
    chainlink_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(SOURCE_CANDIDATE_DOMAIN.len() + 8 + 2 + 32 + 64);
    b.extend_from_slice(SOURCE_CANDIDATE_DOMAIN);
    b.extend_from_slice(&hour_id.to_le_bytes());
    b.push(u8::from(pyth_present));
    b.push(u8::from(chainlink_present));
    for v in [pyth_e8, chainlink_e8, pyth_us, chainlink_us] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(pyth_sha256);
    b.extend_from_slice(chainlink_sha256);
    b
}

/// Verifies an `AuthenticatedHourSourceBundle` from raw signed bytes and enforces
/// canonical window eligibility (`[cutoff - 300s, cutoff]`).
pub fn verify_hour_source_bundle(
    bundle: &AuthenticatedHourSourceBundle,
    pyth_reg: &PinnedPythSignerRegistry,
    don_cfg: &ChainlinkDonVerifierConfig,
) -> Result<[u8; 32], String> {
    if bundle.profile != don_cfg.profile {
        return Err("mixed operational/synthetic source profiles rejected".into());
    }
    if bundle.profile == SourceProfile::SyntheticTestOnly && bundle.operational_source_authenticated {
        return Err("synthetic profile must never claim operational_source_authenticated".into());
    }
    if bundle.pyth_registry_epoch != pyth_reg.registry_epoch {
        return Err("Pyth signer registry epoch mismatch".into());
    }
    if bundle.chainlink_config_digest_hex != hex::encode(don_cfg.config_digest) {
        return Err("Chainlink DON configDigest mismatch".into());
    }

    let p_sha = if bundle.pyth_present {
        let raw_hex = bundle
            .pyth_raw_envelope_hex
            .as_ref()
            .ok_or("missing Pyth raw envelope")?;
        let raw = hex::decode(raw_hex).map_err(|_| "invalid Pyth hex")?;
        // Verify Ed25519 envelope & BTC/USD feed=1, channel=3
        let mut pol = PythProBtcUsdPolicy::default();
        pol.max_age_us = u64::MAX / 2;
        pol.max_carry_forward_us = 10_000_000;
        let cutoff_us = (bundle.hour_id + 1) * 3_600_000_000;
        let receipt = verify_pyth_pro_btc_usd_solana_envelope(&raw, pyth_reg, &pol, cutoff_us)
            .map_err(|e| format!("Pyth verification failed: {e}"))?;
        let envelope_sha = sha256(&raw);
        if bundle.candidate_pyth_price_e8 != receipt.price_e8
            || bundle.candidate_pyth_publish_us != receipt.publish_time_us
            || bundle.candidate_pyth_report_sha256_hex != hex::encode(envelope_sha)
        {
            return Err("Pyth candidate fields do not match verified signed envelope".into());
        }
        envelope_sha
    } else {
        if bundle.pyth_raw_envelope_hex.is_some()
            || bundle.candidate_pyth_price_e8 != 0
            || bundle.candidate_pyth_publish_us != 0
            || bundle.candidate_pyth_report_sha256_hex != "00".repeat(32)
        {
            return Err("absent Pyth candidate must be zeroed".into());
        }
        [0u8; 32]
    };

    let c_sha = if bundle.chainlink_present {
        let raw_hex = bundle
            .chainlink_full_report_hex
            .as_ref()
            .ok_or("missing Chainlink fullReport")?;
        let raw = hex::decode(raw_hex).map_err(|_| "invalid Chainlink hex")?;
        let decoded = verify_chainlink_v3_full_report(&raw, don_cfg)?;
        if bundle.candidate_chainlink_price_e8 != decoded.price_e8
            || bundle.candidate_chainlink_publish_us != decoded.observations_timestamp_us
            || bundle.candidate_chainlink_report_sha256_hex != hex::encode(decoded.full_report_sha256)
        {
            return Err("Chainlink candidate fields do not match verified DON report".into());
        }
        decoded.full_report_sha256
    } else {
        if bundle.chainlink_full_report_hex.is_some()
            || bundle.candidate_chainlink_price_e8 != 0
            || bundle.candidate_chainlink_publish_us != 0
            || bundle.candidate_chainlink_report_sha256_hex != "00".repeat(32)
        {
            return Err("absent Chainlink candidate must be zeroed".into());
        }
        [0u8; 32]
    };

    Ok(sha256(&source_candidate_leaf_bytes(
        bundle.hour_id,
        bundle.pyth_present,
        bundle.chainlink_present,
        bundle.candidate_pyth_price_e8,
        bundle.candidate_chainlink_price_e8,
        bundle.candidate_pyth_publish_us,
        bundle.candidate_chainlink_publish_us,
        &p_sha,
        &c_sha,
    )))
}

/// Anti-cherry-picking canonical selection rule:
/// Within `[cutoff_us - 300_000_000, cutoff_us]`, the canonical observation for a source is
/// the authenticated report with the STRICTLY MAXIMAL timestamp `<= cutoff_us`.
/// Returns `Ok(true)` if `challenger_raw_report` objectively proves that `selected_timestamp_us`
/// skipped a newer eligible observation in `(selected_timestamp_us, cutoff_us]`.
pub fn verify_pyth_cherry_pick_fraud_proof(
    hour_id: u64,
    selected_pyth_publish_us: u64,
    challenger_raw_pyth_envelope: &[u8],
    pyth_reg: &PinnedPythSignerRegistry,
) -> Result<bool, String> {
    let cutoff_us = (hour_id + 1)
        .checked_mul(3_600_000_000)
        .ok_or("hour overflow")?;
    let window_start_us = cutoff_us - 300_000_000;
    let mut pol = PythProBtcUsdPolicy::default();
    pol.max_age_us = 300_000_000;
    pol.max_future_skew_us = 0;
    let receipt =
        verify_pyth_pro_btc_usd_solana_envelope(challenger_raw_pyth_envelope, pyth_reg, &pol, cutoff_us)
            .map_err(|e| format!("invalid challenger Pyth report: {e}"))?;
    Ok(receipt.publish_time_us >= window_start_us
        && receipt.publish_time_us <= cutoff_us
        && receipt.publish_time_us > selected_pyth_publish_us)
}

pub fn verify_chainlink_cherry_pick_fraud_proof(
    hour_id: u64,
    selected_chainlink_publish_us: u64,
    challenger_full_report: &[u8],
    don_cfg: &ChainlinkDonVerifierConfig,
) -> Result<bool, String> {
    let cutoff_us = (hour_id + 1)
        .checked_mul(3_600_000_000)
        .ok_or("hour overflow")?;
    let window_start_us = cutoff_us - 300_000_000;
    let decoded = verify_chainlink_v3_full_report(challenger_full_report, don_cfg)?;
    Ok(decoded.observations_timestamp_us >= window_start_us
        && decoded.observations_timestamp_us <= cutoff_us
        && decoded.observations_timestamp_us > selected_chainlink_publish_us)
}

/// Deterministic helper building a complete 8-hour synthetic-profile signed Pyth + Chainlink
/// fixture (7 `VALID` hours + 1 necessary `HOLD` hour due to >50 bps spread at offset 4).
pub fn build_synthetic_authenticated_8h_bundles(
    start_hour: u64,
) -> (
    PinnedPythSignerRegistry,
    ChainlinkDonVerifierConfig,
    Vec<AuthenticatedHourSourceBundle>,
    [u8; 32],
    Vec<[[u8; 32]; 3]>,
) {
    let pyth_sk = [0x61u8; 32];
    let (_, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
        &pyth_sk,
        1_792_803_595_000_000,
        1_792_803_595_000_000,
        PYTH_PRO_CHANNEL_FIXED_200MS,
        PYTH_PRO_BTC_USD_FEED_ID,
        10_000_000_000_000,
        -8,
        1_000_000_000,
    );
    let mut pyth_reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();
    pyth_reg.registry_epoch = 7;

    let don_sks = [[0x71u8; 32], [0x72u8; 32], [0x73u8; 32], [0x74u8; 32]];
    let don_addrs: Vec<[u8; 20]> = don_sks
        .iter()
        .map(|sk| {
            let k = SecpSigningKey::from_bytes(sk.into()).unwrap();
            evm_address_from_secp_vk(k.verifying_key())
        })
        .collect();
    let feed_id: [u8; 32] = hex::decode(CHAINLINK_BTC_USD_V3_FEED_ID_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let config_digest = sha256(b"SHZ/SYNTHETIC-TEST-CHAINLINK-DON-CONFIG/V1");
    let don_cfg = ChainlinkDonVerifierConfig {
        profile: SourceProfile::SyntheticTestOnly,
        config_digest,
        feed_id,
        f: 1, // requires f + 1 = 2 of 4 DON signers
        signers: don_addrs,
    };

    let mut bundles = Vec::with_capacity(8);
    let mut leaves = Vec::with_capacity(8);

    for offset in 0..8u64 {
        let hour_id = start_hour + offset;
        let cutoff_sec = (hour_id + 1) * 3_600;
        let pyth_us = (cutoff_sec - 5) * 1_000_000;
        let cl_sec = cutoff_sec - 20;
        let cl_us = cl_sec * 1_000_000;

        let pyth_price_e8 = (100_000 + offset * 10) * 100_000_000;
        // At offset 4, Chainlink diverges by +80 bps (> 50 bps) -> forces HOLD (reason = 2)!
        let cl_price_e8 = if offset == 4 {
            (100_850 + offset * 10) * 100_000_000
        } else {
            (100_200 + offset * 10) * 100_000_000
        };

        let (pyth_env, _) = build_signed_pyth_pro_btc_usd_envelope(
            &pyth_sk,
            pyth_us,
            pyth_us,
            PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID,
            pyth_price_e8 as i64,
            -8,
            1_000_000_000,
        );
        let cl_report = encode_and_sign_synthetic_chainlink_v3_report(
            config_digest,
            100 + offset as u32,
            1,
            feed_id,
            cl_sec - 10,
            cl_sec,
            cl_sec + 3_600,
            cl_price_e8,
            500_000_000,
            &don_sks[0..2],
        );
        let p_sha = sha256(&pyth_env);
        let c_sha = sha256(&cl_report);

        let bundle = AuthenticatedHourSourceBundle {
            profile: SourceProfile::SyntheticTestOnly,
            operational_source_authenticated: false,
            hour_id,
            pyth_present: true,
            chainlink_present: true,
            pyth_raw_envelope_hex: Some(hex::encode(&pyth_env)),
            chainlink_full_report_hex: Some(hex::encode(&cl_report)),
            pyth_registry_epoch: pyth_reg.registry_epoch,
            chainlink_config_digest_hex: hex::encode(config_digest),
            candidate_pyth_price_e8: pyth_price_e8,
            candidate_chainlink_price_e8: cl_price_e8,
            candidate_pyth_publish_us: pyth_us,
            candidate_chainlink_publish_us: cl_us,
            candidate_pyth_report_sha256_hex: hex::encode(p_sha),
            candidate_chainlink_report_sha256_hex: hex::encode(c_sha),
        };
        let leaf = verify_hour_source_bundle(&bundle, &pyth_reg, &don_cfg).unwrap();
        leaves.push(leaf);
        bundles.push(bundle);
    }

    let (root, paths) = merkle_tree_8(&leaves, SOURCE_NODE_DOMAIN);
    (pyth_reg, don_cfg, bundles, root, paths)
}

pub fn merkle_tree_8(leaves: &[[u8; 32]], node_domain: &[u8]) -> ([u8; 32], Vec<[[u8; 32]; 3]>) {
    assert_eq!(leaves.len(), 8);
    let hash_pair = |l: &[u8; 32], r: &[u8; 32]| -> [u8; 32] {
        let mut b = Vec::with_capacity(node_domain.len() + 64);
        b.extend_from_slice(node_domain);
        b.extend_from_slice(l);
        b.extend_from_slice(r);
        sha256(&b)
    };
    let lvl1: Vec<[u8; 32]> = (0..4).map(|i| hash_pair(&leaves[2 * i], &leaves[2 * i + 1])).collect();
    let lvl2: Vec<[u8; 32]> = (0..2).map(|i| hash_pair(&lvl1[2 * i], &lvl1[2 * i + 1])).collect();
    let root = hash_pair(&lvl2[0], &lvl2[1]);
    let paths = (0..8)
        .map(|pos| {
            [
                leaves[pos ^ 1],
                lvl1[(pos >> 1) ^ 1],
                lvl2[(pos >> 2) ^ 1],
            ]
        })
        .collect();
    (root, paths)
}
