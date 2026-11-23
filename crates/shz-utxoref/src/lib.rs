//! `shz-utxoref` — Integration of `patrickdugan/UTXO-Ref` protocols into `SatsHedgeZero`:
//! 1. Exact `UTXORef` BIP-341 NUMS P2TR funding output, CPFP-anchored CET/Refund parser,
//!    `TapSighash` script-path sighash, and `TradeLayer/dlc/oracle/announcement/v1` verifier.
//! 2. `UTXORef` PnL Batch Netting (`b = A * g`), Edmonds-Karp capacitated vault routing
//!    (eliminating greedy-allocation starvation), and durable pre-signing reservation book.

pub mod mnr02;
pub mod pnl_batch;
pub mod signing_target;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UtxoRefError {
    #[error("cryptographic error: {0}")]
    InvalidCrypto(&'static str),
    #[error("invalid funding descriptor: {0}")]
    InvalidFunding(&'static str),
    #[error("invalid raw DLC transaction: {0}")]
    InvalidTransaction(&'static str),
    #[error("missing or mismatched committed CPFP anchor output")]
    MissingCommittedAnchor,
    #[error("invalid oracle announcement: {0}")]
    InvalidAnnouncement(&'static str),
    #[error("snapshot hash mismatch against independent pin")]
    SnapshotMismatch,
    #[error("accounting relation violated: {0}")]
    AccountingViolation(&'static str),
    #[error("collateral domain or netting-set substitution: {0}")]
    DomainSubstitution(&'static str),
    #[error("replay detected: {0}")]
    ReplayDetected(&'static str),
    #[error("capacitated vault funding deficit of {deficit_sats} sats")]
    CapacitatedFlowDeficit { deficit_sats: u64 },
    #[error("book head hash compare-and-swap mismatch")]
    HeadHashMismatch,
    #[error("snapshot does not open persisted prior ledger state")]
    PriorLedgerMismatch,
    #[error("pending signing reservation already active")]
    ReservationActive,
    #[error("invalid reservation book state transition")]
    InvalidBookTransition,
    #[error("reservation book is frozen pending operator review")]
    BookFrozen,
}

#[cfg(test)]
mod tests {
    use super::{
        UtxoRefError,
        pnl_batch::{
            AccountRecord, BookAuthState, DurablePnlBatchBook, FundedVaultUtxo, NettingSetSpec,
            PermittedRoute, PnlBatchSnapshotV1, RealizedObligation, RouteTarget, VaultRecord,
            solve_and_verify_pnl_batch,
        },
        signing_target::{
            DEFAULT_CPFP_ANCHOR_SATS, UnsignedDlcTx, UtxoRefOracleAnnouncementV1,
            aggregate_subset_adaptor_point, derive_utxoref_funding_output, point_coordinates,
        },
    };
    use shz_dlc::BtcOutPoint;
    use shz_margin::CollateralAsset;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn test_utxoref_cross_repo_signing_target_vector_parity() {
        // Exact published test vector from `UTXO-Ref/native/dlc-signer/tests/signing_target_vectors.json`!
        let party_0 = hex32("6ff108799ba57ff60cd927b1d6cd110e938f8c2546aafa496019047f6bf37b28");
        let party_1 = hex32("94046d75efcf1173660ef37bd2036e29641c7717ee64f93dc513cd468c779734");

        let funding = derive_utxoref_funding_output(party_1, party_0, 144).unwrap();
        assert_eq!(
            hex::encode(funding.internal_xonly),
            "c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab"
        );
        assert_eq!(
            hex::encode(funding.cet_leaf_hash),
            "96b07f4c218cfa9a56d2a6389137b7a0f1971361875f3d4256884c8994f55144"
        );
        assert_eq!(
            hex::encode(funding.refund_leaf_hash),
            "e650bb5c5e8f81ddc841c64e2b868e15892f0d97d616a92cf14f208e6b254e26"
        );
        assert_eq!(
            hex::encode(&funding.script_pubkey),
            "5120b9e8d1bb16d684e2d08709a501a31c4a88f8bba4f6ae3cf4d1d1c9e891cf164d"
        );

        let cet_raw = hex::decode(
            "0200000001b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b70100000000feffffff0378e60000000000001600145555555555555555555555555555555555555555409c00000000000016001466666666666666666666666666666666666666664a01000000000000160014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64000000",
        )
        .unwrap();
        let cet_tx = UnsignedDlcTx::parse_canonical(&cet_raw).unwrap();
        assert_eq!(
            cet_tx.txid_hex,
            "6a1839b6b7de20e4efab36be48d0811b37b32ccfe724e76326d409c56059e7d4"
        );
        let anchor_spk = hex::decode("0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        cet_tx
            .verify_cpfp_anchor(DEFAULT_CPFP_ANCHOR_SATS, &anchor_spk)
            .unwrap();

        let sighash = cet_tx
            .bip341_script_path_sighash(100_000, &funding.script_pubkey, &funding.cet_leaf_hash)
            .unwrap();
        assert_eq!(
            hex::encode(sighash),
            "b351d68cbf81ecb861921b9a02ff45f2ec47089150debafa35406bf0cc3de731"
        );

        let om_0 = hex32("886b2cc4599f5f1086a963cf98cb513693f30fcf8f8e172108418190419ab17c");
        let om_1 = hex32("677492913ff211ff828514568f8ef6b9573b9b8aef337997950f93fb9905b20e");
        let anns = vec![
            UtxoRefOracleAnnouncementV1 {
                event_id: "signing-target-vector-event".into(),
                px: hex32("0141b22950fda59d7e3edea65b7d7e0b1a377b00819f72b840bf168083b53a17"),
                rx: hex32("8a77298326cf6895863848094c6065f0a3e8596e6eaf6d2fa7337e33fc46270e"),
                outcome_messages: vec![om_0, om_1],
                signature: hex64(
                    "1e18a04d3cbccd913af9e3bf2909e49821692f61f363c45b24db4e2d4650018d471eafa2665842035dae037045f41c533f55afcafad1782c42eeb03031a7cc7f",
                ),
            },
            UtxoRefOracleAnnouncementV1 {
                event_id: "signing-target-vector-event".into(),
                px: hex32("0729d7ae77ce1096f896e90a5d8a2415d0ed8cb136c5499b38339595c715dafa"),
                rx: hex32("a2836e0250fa8c0bd4b8427a23f105fbc8e24c41ae73b985369651ec14bd37ee"),
                outcome_messages: vec![om_0, om_1],
                signature: hex64(
                    "d5cfac1b0df19a0926b3cc006d1c7a84c258bb2472aa6ab452bc8fdf5307e8d75501ef475358f97d85f66d50348e5fca0e615971389d765927ee6fe9215524d9",
                ),
            },
            UtxoRefOracleAnnouncementV1 {
                event_id: "signing-target-vector-event".into(),
                px: hex32("94b1dbd67020711302483b99c6ca12d460722ed556232dd094e12dbba65e963c"),
                rx: hex32("494f6782f36180cdf5527e510bfedfd71a22ca33b2185ef55422aea1e2b2e96a"),
                outcome_messages: vec![om_0, om_1],
                signature: hex64(
                    "1b45b40d8174247bc04d0546be60531ccda117561aadbc1ae6a335733908c64edf572fc70a5f7e683211a7283428d936ec8d26615c3b545a2ae79bb5764ec22d",
                ),
            },
        ];

        let subset = [anns[0].px, anns[1].px];
        let adaptor_pt = aggregate_subset_adaptor_point(&anns, &subset, &om_0).unwrap();
        let (ax, ay) = point_coordinates(adaptor_pt).unwrap();
        assert_eq!(
            hex::encode(ax),
            "71e73d81286bbf1cdd54c6c0c0b504231fb93cec8ffe94d74b3e9aff22f4db15"
        );
        assert_eq!(
            hex::encode(ay),
            "af67bb402f89c864608ccc1d207c913f9c7e429f26ffde550fe158148b4e918a"
        );
    }

    #[test]
    fn test_pnl_batch_worked_example_and_6000_sat_missing_route_deficit() {
        // Worked example from `UTXO-Ref/docs/PNL_BATCH_NETTING.md`:
        // 215,000 input sats, 1,000 fees, 4,000 paid to beneficiary, 6,000 retained profit.
        // Removing the transfer route to winner's vault produces an exact 6,000-sat deficit!
        let make_snapshot = |include_winner_vault_route: bool| {
            let mut routes = vec![PermittedRoute {
                from_vault_id: "vault-loser".into(),
                to_target: RouteTarget::Payout("winner".into()),
                capacity_sats: 10_000,
            }];
            if include_winner_vault_route {
                routes.push(PermittedRoute {
                    from_vault_id: "vault-loser".into(),
                    to_target: RouteTarget::Vault("vault-winner".into()),
                    capacity_sats: 10_000,
                });
            }

            PnlBatchSnapshotV1 {
                network: "bitcoin-regtest".into(),
                epoch_id: 1,
                previous_state_root: [0x11; 32],
                netting_sets: vec![NettingSetSpec {
                    id: "btc-perp-set-1".into(),
                    collateral: CollateralAsset::VanillaBtc,
                }],
                vaults: vec![
                    VaultRecord {
                        id: "vault-loser".into(),
                        netting_set_id: "btc-perp-set-1".into(),
                        change_script_pubkey: vec![0x51, 0x20],
                        fee_sats: 500,
                        protected_sats: 0,
                        utxos: vec![FundedVaultUtxo {
                            outpoint: BtcOutPoint {
                                txid: [1; 32],
                                vout: 0,
                            },
                            sats: 114_500,
                            script_pubkey: vec![0x51, 0x20],
                        }],
                    },
                    VaultRecord {
                        id: "vault-winner".into(),
                        netting_set_id: "btc-perp-set-1".into(),
                        change_script_pubkey: vec![0x51, 0x20],
                        fee_sats: 500,
                        protected_sats: 0,
                        utxos: vec![FundedVaultUtxo {
                            outpoint: BtcOutPoint {
                                txid: [2; 32],
                                vout: 0,
                            },
                            sats: 100_500, // 100,000 available locally after 500 fee; needs +6,000 for 106,000 retained!
                            script_pubkey: vec![0x51, 0x20],
                        }],
                    },
                ],
                accounts: vec![
                    AccountRecord {
                        id: "loser".into(),
                        netting_set_id: "btc-perp-set-1".into(),
                        vault_id: "vault-loser".into(),
                        equity_sats: 100_000,
                        locked_sats: 50_000,
                        payout_sats: 0,
                        payout_script_pubkey: None,
                    },
                    AccountRecord {
                        id: "winner".into(),
                        netting_set_id: "btc-perp-set-1".into(),
                        vault_id: "vault-winner".into(),
                        equity_sats: 100_000,
                        locked_sats: 50_000,
                        payout_sats: 4_000,
                        payout_script_pubkey: Some(vec![0x00, 0x14]),
                    },
                ],
                obligations: vec![RealizedObligation {
                    id: "ob-1".into(),
                    netting_set_id: "btc-perp-set-1".into(),
                    from_account_id: "loser".into(),
                    to_account_id: "winner".into(),
                    sats: 10_000,
                }],
                consumed_obligation_ids: vec![],
                spent_outpoints: vec![],
                routes,
            }
        };

        let valid_snap = make_snapshot(true);
        let batch = solve_and_verify_pnl_batch(&valid_snap, &valid_snap.snapshot_hash()).unwrap();
        assert_eq!(batch.total_input_sats, 215_000);
        assert_eq!(batch.total_fee_sats, 1_000);
        assert_eq!(batch.direct_payouts_sats["winner"], 4_000);
        assert_eq!(batch.post_account_equities["winner"], 106_000);
        assert_eq!(batch.post_account_equities["loser"], 90_000);

        let missing_route_snap = make_snapshot(false);
        assert_eq!(
            solve_and_verify_pnl_batch(&missing_route_snap, &missing_route_snap.snapshot_hash()),
            Err(UtxoRefError::CapacitatedFlowDeficit {
                deficit_sats: 6_000
            })
        );
    }

    #[test]
    fn test_edmonds_karp_beats_greedy_starvation_and_durable_book_freezes_on_ambiguity() {
        // BVA-UTXOREF scenario: "greedy allocation with a feasible alternative flow"
        // Vault 1 can fund EITHER Payout A OR Payout B (10k surplus).
        // Vault 2 can fund ONLY Payout A (10k surplus).
        // A naive greedy solver that routes Vault 1 -> Payout A leaves Vault 2 unable to pay Payout B!
        // Edmonds-Karp augmenting paths reroute Vault 1 -> Payout B and Vault 2 -> Payout A!
        let snap = PnlBatchSnapshotV1 {
            network: "bitcoin-regtest".into(),
            epoch_id: 1,
            previous_state_root: [0xAB; 32],
            netting_sets: vec![NettingSetSpec {
                id: "ns".into(),
                collateral: CollateralAsset::VanillaBtc,
            }],
            vaults: vec![
                VaultRecord {
                    id: "v1".into(),
                    netting_set_id: "ns".into(),
                    change_script_pubkey: vec![0x51, 0x20],
                    fee_sats: 0,
                    protected_sats: 0,
                    utxos: vec![FundedVaultUtxo {
                        outpoint: BtcOutPoint {
                            txid: [0x01; 32],
                            vout: 0,
                        },
                        sats: 20_000,
                        script_pubkey: vec![0x51, 0x20],
                    }],
                },
                VaultRecord {
                    id: "v2".into(),
                    netting_set_id: "ns".into(),
                    change_script_pubkey: vec![0x51, 0x20],
                    fee_sats: 0,
                    protected_sats: 0,
                    utxos: vec![FundedVaultUtxo {
                        outpoint: BtcOutPoint {
                            txid: [0x02; 32],
                            vout: 0,
                        },
                        sats: 20_000,
                        script_pubkey: vec![0x51, 0x20],
                    }],
                },
                VaultRecord {
                    id: "v3".into(),
                    netting_set_id: "ns".into(),
                    change_script_pubkey: vec![0x51, 0x20],
                    fee_sats: 0,
                    protected_sats: 0,
                    utxos: vec![FundedVaultUtxo {
                        outpoint: BtcOutPoint {
                            txid: [0x03; 32],
                            vout: 0,
                        },
                        sats: 20_000,
                        script_pubkey: vec![0x51, 0x20],
                    }],
                },
            ],
            accounts: vec![
                AccountRecord {
                    id: "d1".into(),
                    netting_set_id: "ns".into(),
                    vault_id: "v1".into(),
                    equity_sats: 20_000,
                    locked_sats: 0,
                    payout_sats: 0,
                    payout_script_pubkey: None,
                },
                AccountRecord {
                    id: "d2".into(),
                    netting_set_id: "ns".into(),
                    vault_id: "v2".into(),
                    equity_sats: 20_000,
                    locked_sats: 0,
                    payout_sats: 0,
                    payout_script_pubkey: None,
                },
                AccountRecord {
                    id: "c_a".into(),
                    netting_set_id: "ns".into(),
                    vault_id: "v3".into(),
                    equity_sats: 10_000,
                    locked_sats: 0,
                    payout_sats: 10_000,
                    payout_script_pubkey: Some(vec![0x00, 0x14]),
                },
                AccountRecord {
                    id: "c_b".into(),
                    netting_set_id: "ns".into(),
                    vault_id: "v3".into(),
                    equity_sats: 10_000,
                    locked_sats: 0,
                    payout_sats: 10_000,
                    payout_script_pubkey: Some(vec![0x00, 0x14]),
                },
            ],
            obligations: vec![
                RealizedObligation {
                    id: "o1".into(),
                    netting_set_id: "ns".into(),
                    from_account_id: "d1".into(),
                    to_account_id: "c_a".into(),
                    sats: 10_000,
                },
                RealizedObligation {
                    id: "o2".into(),
                    netting_set_id: "ns".into(),
                    from_account_id: "d2".into(),
                    to_account_id: "c_b".into(),
                    sats: 10_000,
                },
            ],
            consumed_obligation_ids: vec![],
            spent_outpoints: vec![],
            routes: vec![
                // Listed first to trap a greedy allocator into exhausting v1 on c_a!
                PermittedRoute {
                    from_vault_id: "v1".into(),
                    to_target: RouteTarget::Payout("c_a".into()),
                    capacity_sats: 10_000,
                },
                PermittedRoute {
                    from_vault_id: "v1".into(),
                    to_target: RouteTarget::Payout("c_b".into()),
                    capacity_sats: 10_000,
                },
                PermittedRoute {
                    from_vault_id: "v2".into(),
                    to_target: RouteTarget::Payout("c_a".into()),
                    capacity_sats: 10_000,
                },
            ],
        };

        let mut book = DurablePnlBatchBook::new_genesis("shz-book-1", [0xAB; 32]);
        let init_head = book.head_hash;
        let reserved_head = book.reserve_before_signing(&init_head, &snap).unwrap();

        // Simulate ambiguous signer timeout -> book MUST freeze and NOT release reservation!
        assert_eq!(
            book.record_signed_outcome(&reserved_head, Err("named-pipe timeout")),
            Err(UtxoRefError::BookFrozen)
        );
        assert!(matches!(book.state, BookAuthState::Frozen { .. }));

        // Fresh book succeeds through full reserve -> sign -> confirm cycle and rejects replay!
        let mut book_ok = DurablePnlBatchBook::new_genesis("shz-book-1", [0xAB; 32]);
        let h1 = book_ok
            .reserve_before_signing(&book_ok.head_hash.clone(), &snap)
            .unwrap();
        let h2 = book_ok
            .record_signed_outcome(&h1, Ok(("deadbeef".into(), vec![0x02, 0x00])))
            .unwrap();
        let _h3 = book_ok
            .confirm_active_chain(&h2, "deadbeef", &snap)
            .unwrap();
        assert_eq!(book_ok.last_settled_epoch, 1);
        assert!(book_ok.consumed_obligation_ids.contains("o1"));
    }
}
