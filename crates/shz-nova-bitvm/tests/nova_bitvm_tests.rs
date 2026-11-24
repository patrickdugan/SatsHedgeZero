use shz_dex::{OracleSettlementPolicy, OrderSide, SignedOrderIntent, ZeroFeeOrderBook};
use shz_dlc::BtcOutPoint;
use shz_nova_bitvm::{
    BITCOIN_REGTEST_GENESIS_HASH_HEX, BITVM3_STATEMENT_LEN, BITVM3_STATEMENT_MAGIC,
    BitcoinNetworkCode, BridgeSignerMaterial, JOURNAL_LEN, NOVA_CUMULATIVE_AMOUNT_LIMIT,
    NOVA_RELATION_VERSION, NOVA_ROW_AMOUNT_LIMIT, NOVA_TRANSCRIPT_LEN, NOVA_TRANSCRIPT_PREFIX,
    NovaExpectedStatement, NovaFoldedState, RowSignatureSlot, SecqBip340Claim, ShzDlcBridgeSpec,
    SparseNullifierTree, UtxoRefL2SettlementStatementV0, VerificationHonestyFlags,
    assemble_and_sign_bridged_batch, batch_consent_message, build_and_verify_all_6_row_claims,
    build_bitvm3_settlement_statement, build_unsigned_row_from_shz_dlc,
    build_verified_nova_bitvm_demo, check_cumulative_amount_56bit, check_row_amount_51bit,
    decode_batch, decode_journal, derive_funding_script, encode_batch, encode_journal,
    encode_signed_row_transcript, fixture, outpoint_nullifier, secq_claim_digest_and_halves,
    sha256, sha256_to_le_u128_halves, split_statement_digest_be_u128, statement_domain,
    summary_digest, tagged_hash, verify_batch, verify_batch_bytes, verify_expected_journal,
    verify_signed_row_transcript,
};

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn test_utxoref_taproot_funding_script_vector_parity() {
    // Exact published vector from UTXO-Ref/native/dlc-signer/tests/signing_target_vectors.json
    let party_0 = hex32("6ff108799ba57ff60cd927b1d6cd110e938f8c2546aafa496019047f6bf37b28");
    let party_1 = hex32("94046d75efcf1173660ef37bd2036e29641c7717ee64f93dc513cd468c779734");
    let spk_ab = derive_funding_script(&party_0, &party_1, 144).unwrap();
    let spk_ba = derive_funding_script(&party_1, &party_0, 144).unwrap();
    assert_eq!(spk_ab, spk_ba);
    assert_eq!(
        hex::encode(spk_ab),
        "5120b9e8d1bb16d684e2d08709a501a31c4a88f8bba4f6ae3cf4d1d1c9e891cf164d"
    );
}

#[test]
fn test_demo_batch_roundtrip_journal_276b_and_pins() {
    let batch = fixture::demo_batch(2).unwrap();
    let encoded = encode_batch(&batch).unwrap();
    let decoded = decode_batch(&encoded).unwrap();
    assert_eq!(decoded, batch);

    let journal_bytes = verify_batch_bytes(&encoded).unwrap();
    assert_eq!(journal_bytes.len(), JOURNAL_LEN);

    let pins = fixture::journal_pins(&batch.context);
    let journal = verify_expected_journal(&journal_bytes, &pins).unwrap();
    assert_eq!(journal.row_count, 2);
    assert_eq!(journal.total_collateral_sats, 802_660);
    assert_eq!(journal.total_payout_sats, 800_660);
    assert_eq!(journal.total_fee_sats, 2_000);
    assert_eq!(encode_journal(&journal), journal_bytes);
    assert_eq!(decode_journal(&journal_bytes).unwrap(), journal);

    // Trailing byte rejection
    let mut with_trailing = encoded.clone();
    with_trailing.push(0x00);
    assert!(decode_batch(&with_trailing).is_err());

    // Tampered pin rejection
    let mut bad_pins = pins;
    bad_pins.epoch += 1;
    assert!(verify_expected_journal(&journal_bytes, &bad_pins).is_err());
}

#[test]
fn test_sparse_nullifier_tree_and_replay_rejection() {
    let mut tree = SparseNullifierTree::new();
    let keys = [
        [0u8; 32],
        [0xffu8; 32],
        {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        },
        {
            let mut k = [0u8; 32];
            k[0] = 0x80;
            k
        },
    ];
    for key in keys {
        assert!(!tree.contains(&key));
        tree.insert(&key).unwrap();
        assert!(tree.contains(&key));
        assert!(tree.insert(&key).is_err());
    }

    // Batch-level nullifier replay attack: take a verified 2-row batch, advance old_nullifier_root
    // to already include row 0's outpoint nullifier, update batch context & resign, and verify rejection.
    let mut batch = fixture::demo_batch(2).unwrap();
    let n0 = outpoint_nullifier(&batch.rows[0].summary);
    let mut pre_consumed_tree = SparseNullifierTree::new();
    pre_consumed_tree.insert(&n0).unwrap();
    batch.context.old_nullifier_root = pre_consumed_tree.root();
    batch.rows[0].nullifier_siblings = pre_consumed_tree.proof(&n0);
    fixture::resign_batch(&mut batch).unwrap();

    let err = verify_batch(&batch).unwrap_err();
    assert!(
        err.to_string().contains("already consumed") || err.to_string().contains("nonmembership"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_adversarial_forged_row_amounts_and_conservation() {
    let mut batch = fixture::demo_batch(2).unwrap();
    // Forge trader_sats upward by +1000 while keeping summary collateral unchanged
    batch.rows[0].outcome.trader_sats += 1_000;
    fixture::resign_batch(&mut batch).unwrap();
    assert!(verify_batch(&batch).is_err());
    assert!(encode_signed_row_transcript(&batch.context, &batch.rows[0]).is_err());

    // Forge trader_sats +1000 AND maker_sats -1000 so collateral still sums,
    // but outcome Merkle inclusion against signed outcome_root MUST catch the forgery!
    let mut batch_swap = fixture::demo_batch(2).unwrap();
    batch_swap.rows[0].outcome.trader_sats += 1_000;
    batch_swap.rows[0].outcome.maker_sats -= 1_000;
    fixture::resign_batch(&mut batch_swap).unwrap();
    let err = verify_batch(&batch_swap).unwrap_err();
    assert!(
        err.to_string().contains("outcome root"),
        "expected outcome root failure, got: {err}"
    );
}

#[test]
fn test_adversarial_51bit_row_and_56bit_cumulative_overflow_and_33rd_step() {
    // Exact 51-bit boundary checks
    assert!(check_row_amount_51bit(NOVA_ROW_AMOUNT_LIMIT - 1, "max_51").is_ok());
    assert!(check_row_amount_51bit(NOVA_ROW_AMOUNT_LIMIT, "overflow_51").is_err());

    // Exact 56-bit boundary checks
    assert!(check_cumulative_amount_56bit(NOVA_CUMULATIVE_AMOUNT_LIMIT - 1, "max_56").is_ok());
    assert!(check_cumulative_amount_56bit(NOVA_CUMULATIVE_AMOUNT_LIMIT, "overflow_56").is_err());

    // Row transcript rejects >= 2^51 amount
    let mut batch = fixture::demo_batch(1).unwrap();
    batch.rows[0].outcome.trader_sats = NOVA_ROW_AMOUNT_LIMIT;
    batch.rows[0].summary.collateral_sats = batch.rows[0].outcome.trader_sats
        + batch.rows[0].outcome.maker_sats
        + batch.rows[0].outcome.anchor_sats
        + batch.rows[0].outcome.fee_sats;
    assert!(encode_signed_row_transcript(&batch.context, &batch.rows[0]).is_err());

    // Cumulative 56-bit overflow rejected by NovaFoldedState::step
    let valid_batch = fixture::demo_batch(1).unwrap();
    let journal = verify_batch(&valid_batch).unwrap();
    let j_sha = sha256(&encode_journal(&journal));
    let transcript = encode_signed_row_transcript(&valid_batch.context, &valid_batch.rows[0]).unwrap();

    let mut near_overflow = NovaFoldedState::initial(&j_sha, valid_batch.context.epoch);
    near_overflow.total_collateral = NOVA_CUMULATIVE_AMOUNT_LIMIT - 1;
    let err = near_overflow
        .step(&valid_batch.context, &valid_batch.rows[0], &transcript)
        .unwrap_err();
    assert!(
        err.to_string().contains("56-bit"),
        "expected 56-bit overflow error, got: {err}"
    );

    // 5-bit count bound: input count == 32 cannot take a 33rd step!
    let mut at_max_steps = NovaFoldedState::initial(&j_sha, valid_batch.context.epoch);
    at_max_steps.count = 32;
    let err_steps = at_max_steps
        .step(&valid_batch.context, &valid_batch.rows[0], &transcript)
        .unwrap_err();
    assert!(
        err_steps.to_string().contains("5-bit"),
        "expected 5-bit count bound error, got: {err_steps}"
    );
}

#[test]
fn test_adversarial_wrong_oracle_ordering_and_duplicate_oracle() {
    // Reversed oracle indices [2, 0]
    let mut batch_rev = fixture::demo_batch(2).unwrap();
    batch_rev.rows[0].oracle_attestations.swap(0, 1);
    let err_rev = verify_batch(&batch_rev).unwrap_err();
    assert!(
        err_rev.to_string().contains("sorted pinned oracle"),
        "unexpected error: {err_rev}"
    );

    // Duplicate oracle index [0, 0]
    let mut batch_dup = fixture::demo_batch(2).unwrap();
    batch_dup.rows[0].oracle_attestations[1] = batch_dup.rows[0].oracle_attestations[0].clone();
    let err_dup = verify_batch(&batch_dup).unwrap_err();
    assert!(
        err_dup.to_string().contains("sorted pinned oracle"),
        "unexpected error: {err_dup}"
    );

    // Out-of-range oracle index [0, 3]
    let mut batch_oob = fixture::demo_batch(2).unwrap();
    batch_oob.rows[0].oracle_attestations[1].oracle_index = 3;
    assert!(verify_batch(&batch_oob).is_err());

    // Unsorted summary.oracle_keys
    let mut batch_keys = fixture::demo_batch(1).unwrap();
    batch_keys.rows[0].summary.oracle_keys.swap(0, 1);
    fixture::resign_batch(&mut batch_keys).unwrap();
    let err_keys = verify_batch(&batch_keys).unwrap_err();
    assert!(
        err_keys.to_string().contains("distinct and sorted"),
        "unexpected error: {err_keys}"
    );
}

#[test]
fn test_600b_transcript_exact_byte_offsets_and_corrupt_tieout() {
    let batch = fixture::demo_batch(2).unwrap();
    let row = &batch.rows[0];
    let t = encode_signed_row_transcript(&batch.context, row).unwrap();
    assert_eq!(t.len(), NOVA_TRANSCRIPT_LEN);

    // Verify every byte offset documented in SOUNDNESS.md
    assert_eq!(&t[0..46], NOVA_TRANSCRIPT_PREFIX);
    assert_eq!(&t[46..78], &summary_digest(&row.summary));
    assert_eq!(&t[78..110], &batch_consent_message(&batch.context, &row.summary));
    assert_eq!(&t[110..174], &row.summary_signatures[0]);
    assert_eq!(&t[174..238], &row.summary_signatures[1]);
    assert_eq!(&t[238..302], &row.batch_signatures[0]);
    assert_eq!(&t[302..366], &row.batch_signatures[1]);
    assert_eq!(t[366], row.oracle_attestations[0].oracle_index);
    assert_eq!(&t[367..431], &row.oracle_attestations[0].signature);
    assert_eq!(t[431], row.oracle_attestations[1].oracle_index);
    assert_eq!(&t[432..496], &row.oracle_attestations[1].signature);
    assert_eq!(&t[496..500], &row.outcome.index.to_le_bytes());
    assert_eq!(&t[500..532], &row.outcome.message);
    assert_eq!(&t[532..540], &row.outcome.trader_sats.to_le_bytes());
    assert_eq!(&t[540..548], &row.outcome.maker_sats.to_le_bytes());
    assert_eq!(&t[548..556], &row.outcome.anchor_sats.to_le_bytes());
    assert_eq!(&t[556..564], &row.outcome.fee_sats.to_le_bytes());
    assert_eq!(&t[564..596], &row.summary.funding_txid);
    assert_eq!(&t[596..600], &row.summary.funding_vout.to_le_bytes());

    let digest = verify_signed_row_transcript(&t, &batch.context, row).unwrap();
    assert_eq!(digest, sha256(&t));

    // Flip 1 bit in each critical region -> must fail tie-out!
    for offset in [0usize, 46, 78, 120, 250, 366, 431, 496, 510, 532, 564, 599] {
        let mut corrupt = t;
        corrupt[offset] ^= 0x01;
        assert!(
            verify_signed_row_transcript(&corrupt, &batch.context, row).is_err(),
            "corruption at byte {offset} should have been rejected"
        );
    }
    // Wrong length
    assert!(verify_signed_row_transcript(&t[..599], &batch.context, row).is_err());
}

#[test]
fn test_nova_8_field_expected_json_and_honesty_flags() {
    let batch = fixture::demo_batch(2).unwrap();
    let (journal, transcripts, expected) =
        NovaExpectedStatement::from_verified_batch(&batch).unwrap();
    assert_eq!(transcripts.len(), 2);
    assert_eq!(expected.relation_version, NOVA_RELATION_VERSION);
    assert_eq!(expected.step_count, 2);
    assert_eq!(expected.initial_state.count, 0);
    assert_eq!(expected.final_state.count, 2);
    assert_eq!(expected.final_state.total_collateral, journal.total_collateral_sats);
    assert_eq!(expected.final_state.total_payout, journal.total_payout_sats);
    assert_eq!(expected.final_state.total_fee, journal.total_fee_sats);
    assert_eq!(expected.final_state.epoch, journal.epoch);
    assert_eq!(expected.honesty, VerificationHonestyFlags::native_only());
    assert!(expected.honesty.native_statement_verified);
    assert!(!expected.honesty.nova_snark_verified);
    assert!(!expected.honesty.bitvm3_onchain_verified);
    assert!(!expected.honesty.production_ready);

    // JSON roundtrip & unknown-field rejection
    let json = expected.to_expected_json_pretty().unwrap();
    let parsed = NovaExpectedStatement::from_expected_json(&json).unwrap();
    assert_eq!(parsed, expected);

    let mut with_unknown: serde_json::Value = serde_json::from_str(&json).unwrap();
    with_unknown
        .as_object_mut()
        .unwrap()
        .insert("forged_extra_field".into(), serde_json::json!(true));
    assert!(NovaExpectedStatement::from_expected_json(&with_unknown.to_string()).is_err());

    // Tampered final_state rejected by verify_against_journal_bytes
    let mut bad_expected = expected.clone();
    bad_expected.final_state.total_fee += 1;
    bad_expected.final_state_fields = bad_expected.final_state.to_8_fields();
    assert!(bad_expected
        .verify_against_journal_bytes(&encode_journal(&journal))
        .is_err());
}

#[test]
fn test_secq_bip340_3_field_claim_and_row_slot_authorization() {
    let batch = fixture::demo_batch(1).unwrap();
    let row = &batch.rows[0];

    let claims = build_and_verify_all_6_row_claims(&batch.context, row).unwrap();
    assert_eq!(claims.len(), 6);

    // Manually check 3-field claim formula for slot 0 (SummaryTrader)
    let expected_msg = summary_digest(&row.summary);
    let (digest, low, high) = secq_claim_digest_and_halves(
        &row.summary.trader_key,
        &expected_msg,
        &row.summary_signatures[0],
    );
    assert_eq!(claims[0].claim_digest_hex, hex::encode(digest));
    assert_eq!(
        claims[0].state_3_fields,
        ["1".to_owned(), low.to_string(), high.to_string()]
    );

    // Cross-slot substitution attack: valid trader summary claim presented as Maker or BatchConsent
    assert!(claims[0]
        .verify_against_row_slot(&batch.context, row, RowSignatureSlot::SummaryMaker)
        .is_err());
    assert!(claims[0]
        .verify_against_row_slot(&batch.context, row, RowSignatureSlot::BatchConsentTrader)
        .is_err());

    // Rogue validly-signed claim by an unauthorized key (fixture key 99) fails row-slot check
    let rogue_pk = fixture::fixture_pubkey(99);
    let rogue_sig = fixture::fixture_sign(99, &expected_msg);
    let rogue_claim = SecqBip340Claim::from_raw(&rogue_pk, &expected_msg, &rogue_sig).unwrap();
    assert!(rogue_claim.verify_standalone().is_ok());
    assert!(rogue_claim
        .verify_against_row_slot(&batch.context, row, RowSignatureSlot::SummaryTrader)
        .is_err());

    // step_count != 1 rejected
    let mut bad_step = claims[0].clone();
    bad_step.step_count = 2;
    assert!(bad_step.verify_standalone().is_err());
}

#[test]
fn test_bitvm3_304b_statement_layout_and_be_public_input_vector() {
    let regtest_genesis = hex32(BITCOIN_REGTEST_GENESIS_HASH_HEX);
    let stmt = UtxoRefL2SettlementStatementV0 {
        network_code: BitcoinNetworkCode::Regtest,
        chain_genesis_hash: regtest_genesis,
        contract_id: [0x11; 32],
        commitment_hash: [0x22; 32],
        assertion_txid: [0x33; 32],
        settlement_txid: [0x44; 32],
        program_hash: [0x55; 32],
        verifying_key_hash: [0x66; 32],
        policy_hash: [0x77; 32],
        epoch_id: 42,
        assertion_vout: 7,
    };
    stmt.validate_nonzero().unwrap();

    let encoded = stmt.encode();
    assert_eq!(encoded.len(), BITVM3_STATEMENT_LEN);
    assert_eq!(&encoded[0..33], BITVM3_STATEMENT_MAGIC);
    assert_eq!(&encoded[33..35], &[0x00, 0x00]);
    assert_eq!(encoded[35], 0u8); // STATEMENT.md: regtest=0; testnet4=1
    assert_eq!(&encoded[36..68], &regtest_genesis);
    assert_eq!(&encoded[68..100], &[0x11; 32]);
    assert_eq!(&encoded[100..132], &[0x22; 32]);
    assert_eq!(&encoded[132..164], &[0x33; 32]);
    assert_eq!(&encoded[164..196], &[0x44; 32]);
    assert_eq!(&encoded[196..228], &[0x55; 32]);
    assert_eq!(&encoded[228..260], &[0x66; 32]);
    assert_eq!(&encoded[260..292], &[0x77; 32]);
    assert_eq!(&encoded[292..300], &42u64.to_le_bytes());
    assert_eq!(&encoded[300..304], &7u32.to_le_bytes());

    assert_eq!(UtxoRefL2SettlementStatementV0::decode(&encoded).unwrap(), stmt);

    // Verify exact BE u128 public input splitting (distinct from Nova's LE u128!)
    let digest = sha256(&encoded);
    let be_limbs = stmt.public_inputs_be();
    assert_eq!(be_limbs, split_statement_digest_be_u128(&digest));
    assert_eq!(be_limbs[0], u128::from_be_bytes(digest[0..16].try_into().unwrap()));
    assert_eq!(be_limbs[1], u128::from_be_bytes(digest[16..32].try_into().unwrap()));
    let (le_low, le_high) = sha256_to_le_u128_halves(&digest);
    assert_ne!(be_limbs, [le_low, le_high]);

    // Adversarial decode checks
    assert!(UtxoRefL2SettlementStatementV0::decode(&encoded[..303]).is_err());
    let mut bad_magic = encoded;
    bad_magic[32] = b'X';
    assert!(UtxoRefL2SettlementStatementV0::decode(&bad_magic).is_err());

    let mut bad_reserved = encoded;
    bad_reserved[33] = 1;
    assert!(UtxoRefL2SettlementStatementV0::decode(&bad_reserved).is_err());

    let mut bad_net = encoded;
    bad_net[35] = 2; // mainnet/unknown codes >= 2 rejected in v0
    assert!(UtxoRefL2SettlementStatementV0::decode(&bad_net).is_err());

    let mut zero_field = stmt.clone();
    zero_field.policy_hash = [0u8; 32];
    assert!(zero_field.validate_nonzero().is_err());
}

#[test]
fn test_shz_matched_dlc_ticket_and_full_demo_determinism() {
    // Match a real SatsHedgeZero P2P inverse order via shz-dex and bridge it into a verified Row + BitVM3 statement
    let alice_sk = [0x11u8; 32];
    let bob_sk = [0x22u8; 32];
    let mut book = ZeroFeeOrderBook::new();
    let bob_ask = SignedOrderIntent::new_signed_v0(
        &bob_sk,
        BtcOutPoint {
            txid: [0xAA; 32],
            vout: 0,
        },
        OrderSide::Short,
        1_000,
        100_000,
        10_000,
        OracleSettlementPolicy::FrostBondedWithFallback,
        1,
    )
    .unwrap();
    book.submit_order(bob_ask).unwrap();
    let alice_bid = SignedOrderIntent::new_signed_v0(
        &alice_sk,
        BtcOutPoint {
            txid: [0xBB; 32],
            vout: 1,
        },
        OrderSide::Long,
        1_000,
        100_000,
        100_000,
        OracleSettlementPolicy::FrostBondedWithFallback,
        2,
    )
    .unwrap();
    let ticket = book.submit_order(alice_bid).unwrap().remove(0);

    let signers = BridgeSignerMaterial {
        trader_sk: alice_sk,
        maker_sk: bob_sk,
        oracle_sks: [[0x31; 32], [0x32; 32], [0x33; 32]],
        trader_script: fixture::fixture_p2tr_script(21),
        maker_script: fixture::fixture_p2tr_script(22),
        anchor_script: fixture::fixture_p2tr_script(23),
    };
    let bridge_spec = ShzDlcBridgeSpec::from_matched_ticket(
        &ticket,
        vec![95_000, 100_000, 108_200],
        2,
        330,
        1_000,
        890_100,
        890_300,
        144,
        tagged_hash("test-event", b"matched-ticket-0"),
    );
    let row = build_unsigned_row_from_shz_dlc(&bridge_spec, &signers).unwrap();
    let mut smt = SparseNullifierTree::new();
    let (batch, journal) = assemble_and_sign_bridged_batch(
        vec![(row, signers)],
        &mut smt,
        1,
        tagged_hash("test-batch", b"matched-ticket-batch"),
        890_110,
        890_200,
    )
    .unwrap();
    assert_eq!(journal.row_count, 1);

    let bitvm3 = build_bitvm3_settlement_statement(
        BitcoinNetworkCode::Regtest,
        hex32(BITCOIN_REGTEST_GENESIS_HASH_HEX),
        &batch.rows[0],
        &journal,
        batch.rows[0].summary.funding_txid,
        batch.rows[0].summary.funding_vout,
        tagged_hash("prog", b"v2"),
        tagged_hash("vk", b"unpinned"),
        statement_domain(),
    )
    .unwrap();
    assert_eq!(bitvm3.encode().len(), BITVM3_STATEMENT_LEN);

    // End-to-end demo determinism & structural checks
    let demo_a = build_verified_nova_bitvm_demo().unwrap();
    let demo_b = build_verified_nova_bitvm_demo().unwrap();
    assert_eq!(demo_a, demo_b);
    assert_eq!(demo_a.row_count, 2);
    assert_eq!(demo_a.journal.journal_276b_hex.len(), JOURNAL_LEN * 2);
    assert_eq!(demo_a.row_transcripts_600b_hex.len(), 2);
    assert_eq!(demo_a.row_transcripts_600b_hex[0].len(), NOVA_TRANSCRIPT_LEN * 2);
    assert_eq!(demo_a.row_transcripts_600b_hex[1].len(), NOVA_TRANSCRIPT_LEN * 2);
    assert_eq!(demo_a.secq_row0_claims.len(), 6);
    assert_eq!(
        demo_a.bitvm3_settlement_statement.statement_304b_hex.len(),
        BITVM3_STATEMENT_LEN * 2
    );
    assert_eq!(demo_a.honesty, VerificationHonestyFlags::native_only());
    assert_eq!(demo_a.mnr02_bridge.honesty, VerificationHonestyFlags::native_only());
}

#[test]
fn test_three_party_three_trade_dlc_collation_pnl_routing_and_collateral_release() {
    let cfg = shz_nova_bitvm::ThreePartyClearingConfig::default();
    let art_a = shz_nova_bitvm::build_three_party_clearing_ceremony(&cfg).unwrap();
    let art_b = shz_nova_bitvm::build_three_party_clearing_ceremony(&cfg).unwrap();
    assert_eq!(art_a.report, art_b.report);
    assert_eq!(art_a.batch_witness_bytes, art_b.batch_witness_bytes);

    let rep = &art_a.report;
    assert_eq!(rep.network, "bitcoin-testnet4");
    assert_eq!(rep.trades.len(), 3);
    assert_eq!(rep.trades[0].execution_price_usd, 50_000);
    assert_eq!(rep.trades[1].execution_price_usd, 55_000);
    assert_eq!(rep.trades[2].execution_price_usd, 60_000);
    assert!(rep.trades.iter().all(|t| t.protocol_fee_sats == 0));

    // Winner Alice closed on Trade 3 ($50k -> $60k): +11,000,000 sats routed PnL (6M Bob + 5M Carol)
    assert_eq!(rep.utxoref_pnl_clearing.bob_to_alice_routed_pnl_sats, 6_000_000);
    assert_eq!(rep.utxoref_pnl_clearing.carol_to_alice_routed_pnl_sats, 5_000_000);
    assert_eq!(rep.utxoref_pnl_clearing.total_winner_routed_pnl_sats, 11_000_000);
    assert_eq!(rep.utxoref_pnl_clearing.alice_total_cleared_payout_sats, 71_500_000);

    // Loser Bob's remaining collateral (90,000,000 of 96,000,000 sats = 93.75%) is freed immediately
    assert_eq!(rep.utxoref_pnl_clearing.bob_locked_margin_before_clearing_sats, 96_000_000);
    assert_eq!(rep.utxoref_pnl_clearing.bob_freed_collateral_sats, 90_000_000);
    assert_eq!(rep.utxoref_pnl_clearing.bob_freed_collateral_bps, 9_375);
    assert_eq!(rep.utxoref_pnl_clearing.carol_freed_collateral_sats, 82_500_000);
    assert_eq!(rep.utxoref_pnl_clearing.durable_book_settled_epoch, 1);

    // 3-row LNMBAT01 + 276B LNMJNL01 + 3 x 600B Nova v2 transcripts + 18 Secq claims + 304B Testnet4 BitVM3
    assert_eq!(rep.journal.row_count, 3);
    assert_eq!(rep.journal.total_collateral_sats, 244_003_990);
    assert_eq!(rep.journal.total_payout_sats, 244_000_990);
    assert_eq!(rep.journal.total_fee_sats, 3_000);
    assert_eq!(rep.row_transcripts_600b_hex.len(), 3);
    assert_eq!(rep.secq_claims_verified_count, 18);
    assert_eq!(
        rep.bitvm3_testnet4_statement.network_code,
        BitcoinNetworkCode::Testnet4
    );
    let raw_304 = hex::decode(&rep.bitvm3_testnet4_statement.statement_304b_hex).unwrap();
    assert_eq!(raw_304.len(), BITVM3_STATEMENT_LEN);
    assert_eq!(raw_304[35], 1u8); // Testnet4 = 1

    // Exact atomic clearing SegwitTx txid ties out to journal.batch_txid & BitVM3 settlement_txid
    assert_eq!(rep.atomic_clearing_txid_hex, rep.journal.batch_txid_hex);
    assert_eq!(
        rep.atomic_clearing_txid_hex,
        rep.bitvm3_testnet4_statement.settlement_txid_hex
    );
    let mut sorted_outs = rep.atomic_clearing_outputs_sats.clone();
    sorted_outs.sort_unstable();
    assert_eq!(sorted_outs, vec![990, 71_500_000, 82_500_000, 90_000_000]);
}
