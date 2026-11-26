//! LDK-backed channel adapter for the venue's multilateral clearing (gate G-LN-1a).
//!
//! * [`journal`]: the wrapping `Persist` that journals one [`journal::MonitorRecord`] per
//!   durable monitor write, the only place LDK exposes commitment progress.
//! * [`node`]: a regtest LDK node (`ChannelManager`, `ChainMonitor`, loopback peers, Bitcoin
//!   Core as chain source and wallet).
//! * [`adapter`]: [`adapter::LdkSettlement`] moves each `ClearingRow::net` through its lane's
//!   channel, waits until both parties' persisted monitors show the cleared balance, and
//!   builds the lane's acknowledgement with the monitor evidence; [`adapter::attest`] is the
//!   check each signer runs on its own journal before signing.
//!
//! Design and limits: `docs/SHZ_LDK_SETTLEMENT.md`.
pub mod adapter;
pub mod journal;
pub mod node;

pub use adapter::{AttestError, LaneSettlement, LdkSettlement, SettleError, Side, attest};
pub use journal::{JournalingPersist, LaneJournal, MonitorRecord};
pub use node::{Bitcoind, LdkNode};
