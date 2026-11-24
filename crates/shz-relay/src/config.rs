//! Relay/collator configuration. Secrets never live in this file: signing
//! keys and provider credentials are read from environment variables (or a
//! file path named by an environment variable, e.g. a mounted secret).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use shz_oracle::hft_packets::Policy;

use crate::{client::ClientEntry, envelope::{Hash, SecurityMode}, schedule::ReleasePolicy};

pub const ENV_RELAY_KEY: &str = "SHZ_RELAY_SIGNING_KEY";
pub const ENV_RELAY_KEY_FILE: &str = "SHZ_RELAY_SIGNING_KEY_FILE";
pub const ENV_PYTH_TOKEN: &str = "PYTH_LAZER_ACCESS_TOKEN";
pub const ENV_CHAINLINK_ID: &str = "CHAINLINK_DS_CLIENT_ID";
pub const ENV_CHAINLINK_SECRET: &str = "CHAINLINK_DS_CLIENT_SECRET";
pub const ENV_DEV_FEDERATION: &str = "SHZ_DEV_FEDERATION";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub network: String,
    pub market: String,
    pub epoch: u64,
    /// Unix microseconds of slot 1. 0 = next whole second after start + 2 s.
    #[serde(default)]
    pub origin_us: u64,
    pub members: [String; 5],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceConfig {
    /// Deterministic synthetic signed reports generated in-process (dev/CI).
    Synthetic { seed: u64 },
    /// Replay a JSONL recording of RawReport lines, rebased to `origin_us`.
    Recorded { path: PathBuf, recorded_origin_us: u64 },
    /// Live provider sockets (requires the `live` feature and credentials).
    Live {
        pyth_url: String,
        chainlink_url: String,
        chainlink_feed_id: String,
        /// Pinned Pyth Ed25519 signer keys (hex).
        pyth_signers: Vec<String>,
        /// Pinned DON configuration(s) loaded from the deployed Verifier.
        chainlink_don: Vec<shz_oracle::chainlink_streams::DonConfig>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub mode: SecurityMode,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub release: ReleasePolicy,
    pub ws_listen: String,
    pub http_listen: String,
    pub state_dir: PathBuf,
    #[serde(default = "default_history")]
    pub history: usize,
    #[serde(default = "default_queue")]
    pub subscriber_queue: usize,
    pub clients: Vec<ClientEntry>,
    pub source: SourceConfig,
    /// FROST maturity attestation group key (hex); packet keys must differ.
    #[serde(default)]
    pub frost_maturity_group_key: Option<String>,
}
fn default_history() -> usize {
    3_000
}
fn default_queue() -> usize {
    256
}

pub fn h32(s: &str) -> Result<Hash, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?.try_into().map_err(|_| format!("expected 32-byte hex: {s}"))
}

impl RelayConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: Self = serde_json::from_str(&raw).map_err(|e| format!("config: {e}"))?;
        cfg.release.validate().map_err(|e| format!("release policy: {e:?}"))?;
        let mut ids = std::collections::BTreeSet::new();
        for c in &cfg.clients {
            if !ids.insert(&c.id) {
                return Err(format!("duplicate client id {}", c.id));
            }
            h32(&c.pubkey).map_err(|e| format!("client {}: {e}", c.id))?;
        }
        Ok(cfg)
    }
    pub fn packet_policy(&self, origin_us: u64) -> Result<Policy, String> {
        let p = Policy {
            network: h32(&self.policy.network)?,
            market: h32(&self.policy.market)?,
            epoch: self.policy.epoch,
            origin_us,
            members: [
                h32(&self.policy.members[0])?,
                h32(&self.policy.members[1])?,
                h32(&self.policy.members[2])?,
                h32(&self.policy.members[3])?,
                h32(&self.policy.members[4])?,
            ],
        };
        p.id().map_err(|e| format!("packet policy: {e:?}"))?;
        Ok(p)
    }
}

/// Read the relay signing key from `SHZ_RELAY_SIGNING_KEY` (hex) or the file
/// named by `SHZ_RELAY_SIGNING_KEY_FILE`. The key is never logged.
pub fn relay_signing_key() -> Result<Hash, String> {
    if let Ok(v) = std::env::var(ENV_RELAY_KEY) {
        return h32(v.trim()).map_err(|_| format!("{ENV_RELAY_KEY} is not 32-byte hex"));
    }
    if let Ok(p) = std::env::var(ENV_RELAY_KEY_FILE) {
        let v = std::fs::read_to_string(&p).map_err(|e| format!("{ENV_RELAY_KEY_FILE}: {e}"))?;
        return h32(v.trim()).map_err(|_| format!("{ENV_RELAY_KEY_FILE} does not contain 32-byte hex"));
    }
    Err(format!("set {ENV_RELAY_KEY} or {ENV_RELAY_KEY_FILE}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_config_parses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/hft06/relay.local.json");
        let cfg = RelayConfig::load(&path).unwrap();
        assert!(cfg.packet_policy(1_000_000).is_ok());
        assert_eq!(cfg.mode, SecurityMode::TrustedRelay);
    }
}
