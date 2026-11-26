//! One member of the Lightninger FROST price relay and DLC oracle confederation, compatible
//! with `ops/public-relay/frost_signer.py` on the wire (endpoints, JSON bytes, coordinator
//! authentication) and on disk (`share.json`, `nonces.json`, `dlc.json`, `coord_auth.key`).
//! Secret-share and nonce arithmetic runs in k256 `Scalar`s instead of Python big ints.

pub mod auth;
pub mod dlc;
pub mod ec;
pub mod frost;
#[cfg(feature = "test-hooks")]
pub mod hooks;
pub mod json;
pub mod keygen;
pub mod member;
pub mod net;
pub mod server;
pub mod store;
pub mod view;
