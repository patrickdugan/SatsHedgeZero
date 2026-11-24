//! Autonomous Two-Sided Market Maker & Live Flow Engine (`shz-hftd`).
//!
//! Quotes deep, tight two-sided BIP-340 signed order ladders (`MM-Alpha` & `MM-Omega`) dynamically
//! centered on the live Pyth + Chainlink two-index midpoint (`mark_price_usd`) every `600 ms`, so
//! interactive traders clicking Buy/Sell on `/` get sub-millisecond fills with `0 bps` fees!
#![forbid(unsafe_code)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use shz_dex::{OracleSettlementPolicy, OrderSide, SignedOrderIntent};
use shz_dlc::{BtcOutPoint, pubkey_x_from_secret};

use crate::engine::HftEngine;

static MM_SEQ: AtomicU64 = AtomicU64::new(100_000);

/// Signs a 16-level two-sided Market Maker ladder (`MM-Alpha` `[0x11; 32]`) + 6-level tight inside
/// arbitrage ladder (`MM-Omega` `[0x13; 32]`) OFF-LOCK, then atomically updates the resting book!
pub fn refresh_market_maker_ladders(engine: &Arc<Mutex<HftEngine>>, tick_counter: u64) {
    let center_px = match engine.lock() {
        Ok(g) => g.mark_price_usd.max(1_000),
        Err(_) => return,
    };

    // 1. Build `MM-Alpha` (`[0x11; 32]`) 8-bid + 8-ask deep institutional ladder OFF-LOCK:
    let alpha_sk = [0x11u8; 32];
    let Ok(alpha_pk) = pubkey_x_from_secret(&alpha_sk) else {
        return;
    };
    let alpha_out = BtcOutPoint {
        txid: [0x11; 32],
        vout: 0,
    };

    let offsets_and_sizes: [(u64, u64, u32, u32); 8] = [
        (6, 5_000, 100_000, 10_000),
        (14, 10_000, 100_000, 10_000),
        (26, 18_000, 50_000, 20_000),
        (42, 28_000, 50_000, 10_000),
        (65, 42_000, 30_000, 20_000),
        (95, 60_000, 100_000, 10_000),
        (140, 85_000, 50_000, 10_000),
        (210, 120_000, 20_000, 10_000),
    ];

    let mut alpha_quotes = Vec::with_capacity(16);
    for (off, sz_usd, bid_lev, ask_lev) in offsets_and_sizes {
        let s1 = MM_SEQ.fetch_add(1, Ordering::Relaxed);
        if let Ok(bid) = SignedOrderIntent::new_signed_v0(
            &alpha_sk,
            alpha_out.clone(),
            OrderSide::Long,
            sz_usd,
            center_px.saturating_sub(off).max(100),
            bid_lev,
            OracleSettlementPolicy::FrostBondedWithFallback,
            s1,
        ) {
            alpha_quotes.push(bid);
        }

        let s2 = MM_SEQ.fetch_add(1, Ordering::Relaxed);
        if let Ok(ask) = SignedOrderIntent::new_signed_v0(
            &alpha_sk,
            alpha_out.clone(),
            OrderSide::Short,
            sz_usd,
            center_px + off,
            ask_lev,
            OracleSettlementPolicy::FrostBondedWithFallback,
            s2,
        ) {
            alpha_quotes.push(ask);
        }
    }

    // 2. Build `MM-Omega` (`[0x13; 32]`) 3-bid + 3-ask tight top-of-book quotes OFF-LOCK:
    let omega_sk = [0x13u8; 32];
    let Ok(omega_pk) = pubkey_x_from_secret(&omega_sk) else {
        return;
    };
    let omega_out = BtcOutPoint {
        txid: [0x13; 32],
        vout: 2,
    };
    let mut omega_quotes = Vec::with_capacity(6);
    for (off, sz_usd) in [(2u64, 3_500u64), (9, 7_500), (19, 14_000)] {
        let s1 = MM_SEQ.fetch_add(1, Ordering::Relaxed);
        if let Ok(bid) = SignedOrderIntent::new_signed_v0(
            &omega_sk,
            omega_out.clone(),
            OrderSide::Long,
            sz_usd,
            center_px.saturating_sub(off).max(100),
            100_000,
            OracleSettlementPolicy::FrostBondedWithFallback,
            s1,
        ) {
            omega_quotes.push(bid);
        }
        let s2 = MM_SEQ.fetch_add(1, Ordering::Relaxed);
        if let Ok(ask) = SignedOrderIntent::new_signed_v0(
            &omega_sk,
            omega_out.clone(),
            OrderSide::Short,
            sz_usd,
            center_px + off,
            10_000,
            OracleSettlementPolicy::FrostBondedWithFallback,
            s2,
        ) {
            omega_quotes.push(ask);
        }
    }

    // Optional periodic background taker fill every 3rd refresh (`~1.8s`) so tape & LN commits breathe:
    let maybe_taker = if tick_counter.is_multiple_of(3) {
        let taker_sk = [0x12u8; 32];
        let side = if tick_counter.is_multiple_of(6) {
            OrderSide::Long
        } else {
            OrderSide::Short
        };
        let px = match side {
            OrderSide::Long => center_px + 4,
            OrderSide::Short => center_px.saturating_sub(4).max(100),
        };
        let s_tk = MM_SEQ.fetch_add(1, Ordering::Relaxed);
        SignedOrderIntent::new_signed_v0(
            &taker_sk,
            BtcOutPoint {
                txid: [0x12; 32],
                vout: 1,
            },
            side,
            500 + ((tick_counter % 4) * 250),
            px,
            100_000,
            OracleSettlementPolicy::FrostBondedWithFallback,
            s_tk,
        )
        .ok()
    } else {
        None
    };

    // 3. Apply pre-verified ladders inside `< 20 µs` critical section:
    if let Ok(mut guard) = engine.lock() {
        let t0 = std::time::Instant::now();
        // Replenish MM channels if low so 24/7 continuous quoting never runs dry:
        for cid in ["ch-maker-mm", "ch-arb-hedger", "ch-taker-hft"] {
            if let Some(ch) = guard.ln_mesh.channels.get_mut(cid)
                && ch.trader_free_sats < 20_000_000
            {
                ch.trader_free_sats = 50_000_000;
            }
        }
        let _ = guard.place_preverified_mass_quote(alpha_pk, alpha_quotes, t0);
        let _ = guard.place_preverified_mass_quote(omega_pk, omega_quotes, std::time::Instant::now());
        if let Some(tk) = maybe_taker {
            let _ = guard.place_preverified_intent(tk, std::time::Instant::now());
        }
        // Keep `mark_price_usd` anchored to the live two-index oracle midpoint!
        guard.mark_price_usd = guard.oracle_index_midpoint_usd();
        guard.refresh_user_positions_mark();
    }
}
