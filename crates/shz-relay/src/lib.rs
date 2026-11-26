//! SHZ-HFT-06: oracle collator service and tiered certified-packet relay.
//!
//! * [`envelope`]: trusted-relay vs federated certificates, explicit mode tag.
//! * [`authority`]: durable one-signature-per-slot locks, trusted signer,
//!   federated vote collector, threshold-signer seam, key separation.
//! * [`schedule`]: Premium / Intermediate / Standard release of one packet.
//! * [`hub`]: continuity, replay/equivocation rules, backpressure, catch-up,
//!   checkpoints.
//! * [`client`]: tiered receiver and challenge-response authentication.
//! * [`remote`] / [`member`]: network vote transport between the relay and five
//!   independent federation member processes (gate G-FED-1).
//! * [`server`] / [`service`]: tokio WebSocket + HTTP runtime.
//! * [`bench`]: loopback end-to-end benchmark receipts.
//!
//! `production_ready` is false: live provider access, measured multi-site
//! network performance, authenticated Lightning settlement and independent
//! security review are outstanding gates.

pub mod authority;
pub mod bench;
pub mod client;
pub mod config;
pub mod envelope;
pub mod hub;
#[cfg(feature = "live")]
pub mod live;
pub mod member;
pub mod metrics;
pub mod remote;
pub mod schedule;
pub mod server;
pub mod service;
