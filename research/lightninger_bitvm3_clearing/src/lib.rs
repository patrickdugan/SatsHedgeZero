//! Lightninger BitVM3 clearing circuits: the V3 multilateral clearing of one committed batch
//! as a uniform Nova step ([`clearing_step`]), and a uniform BIP-341 key-path TapSighash
//! step feeding the MNR-05 Secq256k1 BIP-340 accumulator ([`tapsighash_step`]).
#![forbid(unsafe_code)]

pub mod audit;
pub mod clearing_step;
pub mod fold;
pub mod gadgets;
pub mod tapsighash_step;
pub mod trace;
