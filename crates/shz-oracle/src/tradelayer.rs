//! TradeLayer L1/meta-layer Volume-Weighted Average Price (VWAP) oracle feed
//! with wash-trade filtering, median outlier bounds, and SHA-256 Merkle proofs.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, tagged_hash};

use crate::OracleError;

/// A native TradeLayer DEX fill anchored on Bitcoin/Litecoin L1.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TradeLayerFill {
    pub txid: [u8; 32],
    pub block_height: u64,
    pub property_pair: String,
    pub price_usd: u64,
    pub volume_sats: u64,
    pub maker_id: [u8; 20],
    pub taker_id: [u8; 20],
}

impl TradeLayerFill {
    pub fn leaf_hash(&self) -> [u8; 32] {
        let encoded = borsh::to_vec(self).expect("TradeLayerFill Borsh serialization infallible");
        tagged_hash(b"SatsHedgeZero/TradeLayerFillLeaf/v0", &encoded)
    }
}

/// Binary SHA-256 Merkle inclusion proof for an individual TradeLayer fill.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct MerkleInclusionProof {
    pub leaf_index: u32,
    pub leaf_hash: [u8; 32],
    /// `(sibling_hash, sibling_is_right)` from bottom leaf to root.
    pub siblings: Vec<([u8; 32], bool)>,
}

impl MerkleInclusionProof {
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut acc = self.leaf_hash;
        for &(sib, sib_is_right) in &self.siblings {
            acc = if sib_is_right {
                merkle_branch(&acc, &sib)
            } else {
                merkle_branch(&sib, &acc)
            };
        }
        &acc == expected_root
    }
}

fn merkle_branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SatsHedgeZero/MerkleBranch/v0");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Computes a binary Merkle root and per-leaf inclusion proofs.
pub fn compute_merkle_tree(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<MerkleInclusionProof>) {
    if leaves.is_empty() {
        return ([0u8; 32], Vec::new());
    }
    let mut proofs: Vec<MerkleInclusionProof> = leaves
        .iter()
        .enumerate()
        .map(|(idx, &leaf_hash)| MerkleInclusionProof {
            leaf_index: idx as u32,
            leaf_hash,
            siblings: Vec::new(),
        })
        .collect();

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    // Track which original leaf indices belong to each node in `level`.
    let mut groups: Vec<Vec<usize>> = (0..leaves.len()).map(|i| vec![i]).collect();

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut next_groups = Vec::with_capacity(level.len().div_ceil(2));

        for chunk_idx in (0..level.len()).step_by(2) {
            let left_hash = level[chunk_idx];
            let (right_hash, right_group) = if chunk_idx + 1 < level.len() {
                (level[chunk_idx + 1], groups[chunk_idx + 1].clone())
            } else {
                (left_hash, Vec::new())
            };

            for &orig_idx in &groups[chunk_idx] {
                proofs[orig_idx].siblings.push((right_hash, true));
            }
            for &orig_idx in &right_group {
                proofs[orig_idx].siblings.push((left_hash, false));
            }

            let mut merged = groups[chunk_idx].clone();
            merged.extend(right_group);
            next_groups.push(merged);
            next_level.push(merkle_branch(&left_hash, &right_hash));
        }

        level = next_level;
        groups = next_groups;
    }

    (level[0], proofs)
}

/// Filter policy for computing manipulation-resistant TradeLayer VWAP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TradeLayerVwapConfig {
    pub min_fill_sats: u64,
    pub min_qualifying_fills: usize,
    /// Rejects fills deviating more than `max_median_deviation_bps` from unweighted median.
    pub max_median_deviation_bps: u64,
}

impl Default for TradeLayerVwapConfig {
    fn default() -> Self {
        Self {
            min_fill_sats: 10_000,
            min_qualifying_fills: 2,
            max_median_deviation_bps: 1_500, // 15% outlier circuit breaker
        }
    }
}

/// Borsh-serializable TradeLayer VWAP window proof verifiable by NEAR fraud-proof contracts.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TradeLayerVwapProof {
    pub property_pair: String,
    pub start_block: u64,
    pub end_block: u64,
    pub window_close_unix: u64,
    pub vwap_price_usd: u64,
    pub total_volume_sats: u64,
    pub qualifying_fill_count: u32,
    pub fills_merkle_root: [u8; 32],
    pub witness_pubkeys_x: Vec<[u8; 32]>,
    pub witness_signatures: Vec<Bip340Signature>,
}

impl TradeLayerVwapProof {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&(self.property_pair.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.property_pair.as_bytes());
        buf.extend_from_slice(&self.start_block.to_le_bytes());
        buf.extend_from_slice(&self.end_block.to_le_bytes());
        buf.extend_from_slice(&self.window_close_unix.to_le_bytes());
        buf.extend_from_slice(&self.vwap_price_usd.to_le_bytes());
        buf.extend_from_slice(&self.total_volume_sats.to_le_bytes());
        buf.extend_from_slice(&self.qualifying_fill_count.to_le_bytes());
        buf.extend_from_slice(&self.fills_merkle_root);
        tagged_hash(b"SatsHedgeZero/TradeLayerVwapDigest/v0", &buf)
    }

    /// Verifies that at least `min_witnesses` trusted TradeLayer indexers signed this VWAP window.
    pub fn verify_witness_quorum(
        &self,
        trusted_witnesses: &[[u8; 32]],
        min_witnesses: usize,
    ) -> Result<(), OracleError> {
        if self.witness_pubkeys_x.len() != self.witness_signatures.len()
            || self.witness_pubkeys_x.len() < min_witnesses
        {
            return Err(OracleError::InsufficientQuorum {
                got: self.witness_pubkeys_x.len(),
                required: min_witnesses,
            });
        }
        let digest = self.signing_digest();
        let mut seen = Vec::with_capacity(self.witness_pubkeys_x.len());
        for (pk, sig) in self.witness_pubkeys_x.iter().zip(&self.witness_signatures) {
            if !trusted_witnesses.contains(pk) || seen.contains(pk) {
                return Err(OracleError::UntrustedFeedSigner);
            }
            bip340_verify(pk, &digest, sig)?;
            seen.push(*pk);
        }
        Ok(())
    }
}

/// Computes filtered TradeLayer VWAP, Merkle tree proofs, and witness-signed `TradeLayerVwapProof`.
pub fn build_tradelayer_vwap_proof(
    property_pair: &str,
    start_block: u64,
    end_block: u64,
    window_close_unix: u64,
    raw_fills: &[TradeLayerFill],
    cfg: &TradeLayerVwapConfig,
    witness_secrets: &[[u8; 32]],
) -> Result<(TradeLayerVwapProof, Vec<MerkleInclusionProof>), OracleError> {
    // Pass 1: block range, pair, dust, and self-cross wash trade filter.
    let prefiltered: Vec<&TradeLayerFill> = raw_fills
        .iter()
        .filter(|f| {
            f.property_pair == property_pair
                && f.block_height >= start_block
                && f.block_height <= end_block
                && f.volume_sats >= cfg.min_fill_sats
                && f.price_usd > 0
                && f.maker_id != f.taker_id
        })
        .collect();

    if prefiltered.len() < cfg.min_qualifying_fills {
        return Err(OracleError::InsufficientLiquidity {
            fills: prefiltered.len(),
            required: cfg.min_qualifying_fills,
        });
    }

    // Pass 2: median outlier filter.
    let mut prices: Vec<u64> = prefiltered.iter().map(|f| f.price_usd).collect();
    prices.sort_unstable();
    let median = prices[prices.len() / 2];

    let qualifying: Vec<&TradeLayerFill> = prefiltered
        .into_iter()
        .filter(|f| {
            let diff = f.price_usd.abs_diff(median) as u128;
            let bps = (diff * 10_000) / (median as u128);
            bps <= cfg.max_median_deviation_bps as u128
        })
        .collect();

    if qualifying.len() < cfg.min_qualifying_fills {
        return Err(OracleError::InsufficientLiquidity {
            fills: qualifying.len(),
            required: cfg.min_qualifying_fills,
        });
    }

    let mut weighted_sum: u128 = 0;
    let mut total_vol: u128 = 0;
    let mut leaf_hashes = Vec::with_capacity(qualifying.len());

    for fill in &qualifying {
        weighted_sum += (fill.price_usd as u128) * (fill.volume_sats as u128);
        total_vol += fill.volume_sats as u128;
        leaf_hashes.push(fill.leaf_hash());
    }

    let vwap_price_usd = ((weighted_sum + (total_vol / 2)) / total_vol) as u64;
    let (fills_merkle_root, inclusion_proofs) = compute_merkle_tree(&leaf_hashes);

    let mut proof = TradeLayerVwapProof {
        property_pair: property_pair.to_string(),
        start_block,
        end_block,
        window_close_unix,
        vwap_price_usd,
        total_volume_sats: total_vol as u64,
        qualifying_fill_count: qualifying.len() as u32,
        fills_merkle_root,
        witness_pubkeys_x: Vec::with_capacity(witness_secrets.len()),
        witness_signatures: Vec::with_capacity(witness_secrets.len()),
    };

    let digest = proof.signing_digest();
    for sk in witness_secrets {
        let pk_x = shz_dlc::pubkey_x_from_secret(sk)?;
        let sig = bip340_sign(sk, &digest)?;
        proof.witness_pubkeys_x.push(pk_x);
        proof.witness_signatures.push(sig);
    }

    Ok((proof, inclusion_proofs))
}
