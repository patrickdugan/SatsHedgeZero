import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {buildCloseoutProposal} from '../src/channels.mjs';
import {
  openClearingEpoch,
  approveChannel,
  canonicalWalletApproval,
  requestChannelCloseout,
  canonicalNearObservation,
} from '../src/closeout_epoch.mjs';
import {INNER_MAGIC, verifyNativePythBtcUsd} from '../src/pyth_payload.mjs';
import {
  SIGHASH_DEFAULT,
  SIGHASH_ALL,
  SIGHASH_SINGLE_ANYONECANPAY,
  pubkeyXFromSecretHex,
  bip340Sign,
  bip340Verify,
  deriveUtxoRefNumsInternalKeyHex,
  buildMnr02ChannelDescriptor,
  buildInteractiveChannelDescriptor,
  singleOutputDigestHex,
  computeBip341TapSighash,
  encodeWitnessSigHex,
  authorizeBroadcastReadySettlement,
  confirmBitcoinSettlement,
} from '../src/wallet_settlement.mjs';

const sha256Hex = s => createHash('sha256').update(s).digest('hex');

function signedPythPrice() {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const signer = publicKey.export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
  const b = Buffer.alloc(4 + 8 + 1 + 1 + 4 + 1 + 9 + 3 + 9 + 10);
  let i = 0;
  b.writeUInt32LE(INNER_MAGIC, i); i += 4;
  b.writeBigUInt64LE(1795000000000000n, i); i += 8;
  b[i++] = 3;
  b[i++] = 1;
  b.writeUInt32LE(1, i); i += 4;
  b[i++] = 4;
  b[i++] = 0; b.writeBigInt64LE(12500000000000n, i); i += 8;
  b[i++] = 4; b.writeInt16LE(-8, i); i += 2;
  b[i++] = 5; b.writeBigInt64LE(1500000000n, i); i += 8;
  b[i++] = 12; b[i++] = 1; b.writeBigUInt64LE(1795000000000000n, i); i += 8;
  const payload = b.subarray(0, i);
  const outer = Buffer.alloc(payload.length + 102);
  outer.writeUInt32LE(2182742457);
  sign(null, payload, privateKey).copy(outer, 4);
  Buffer.from(signer, 'hex').copy(outer, 68);
  outer.writeUInt16LE(payload.length, 100);
  payload.copy(outer, 102);
  return {
    envelopeHex: outer.toString('hex'),
    signerKeys: [signer],
    policy: {
      feedId: 1,
      allowedChannelIds: [3],
      maxAgeUs: '4000000',
      maxCarryForwardUs: '1000000',
      maxFutureSkewUs: '0',
      maxConfBps: '100',
    },
    nowUs: '1795000001000000',
  };
}

function buildFullSettlementFixture() {
  // Deterministic Bitcoin BIP-340 secret keys (Bob's key is ONLY used at t=0 origination!)
  const aliceBtcSk = '11'.repeat(32);
  const bobBtcSkAtOriginationOnly = '22'.repeat(32);
  const carolBtcSk = '23'.repeat(32);
  const guardBtcSk = '24'.repeat(32);

  const alicePk = pubkeyXFromSecretHex(aliceBtcSk);
  const bobPk = pubkeyXFromSecretHex(bobBtcSkAtOriginationOnly);
  const carolPk = pubkeyXFromSecretHex(carolBtcSk);
  const guardPk = pubkeyXFromSecretHex(guardBtcSk);

  const aliceOutSpk = '5120' + pubkeyXFromSecretHex('41'.repeat(32));
  const bobOutSpk = '5120' + pubkeyXFromSecretHex('42'.repeat(32));
  const carolOutSpk = '5120' + pubkeyXFromSecretHex('43'.repeat(32));
  const anchorOutSpk = '5120' + pubkeyXFromSecretHex('44'.repeat(32));

  const maturityHeight = 175;
  const graceBlocks = 30; // graceEndHeight = 205
  const refundDelayBlocks = 70; // refundHeight = 245
  const refundCsv = 144;

  // Origination Taproot descriptors
  const abDesc = buildMnr02ChannelDescriptor({
    counterpartyPubkeyXHex: alicePk,
    bobPubkeyXHex: bobPk,
    routerGuardPubkeyXHex: guardPk,
    maturityHeight,
    graceBlocks,
    refundDelayBlocks,
  });
  const bcDesc = buildMnr02ChannelDescriptor({
    counterpartyPubkeyXHex: carolPk,
    bobPubkeyXHex: bobPk,
    routerGuardPubkeyXHex: guardPk,
    maturityHeight,
    graceBlocks,
    refundDelayBlocks,
  });
  const caDesc = buildInteractiveChannelDescriptor({
    partyAPubkeyXHex: carolPk,
    partyBPubkeyXHex: alicePk,
    refundCsv,
  });

  const txidAB = sha256Hex('funding-AB');
  const txidBC = sha256Hex('funding-BC');
  const txidCA = sha256Hex('funding-CA');

  // Bob's exact pinned outputs at vout[0] (from AB) and vout[1] (from BC)
  const bobAbOutSats = 775;
  const bobBcOutSats = 475;
  const aliceWinnerSats = 1475;
  const carolFreedSats = 825;
  const anchorSats = 330;

  // Step t = 0 (Bob Online at Origination): Bob signs 1-in/1-out 0x83 templates for AB and BC,
  // then Bob's secret key is discarded and NEVER passed into clearing!
  const abTemplate0x83 = {
    version: 2,
    locktime: maturityHeight,
    inputs: [
      {
        txid: txidAB,
        vout: 0,
        sequence: 0xfffffffe,
        prevoutValueSats: 2095,
        prevoutScriptPubKeyHex: abDesc.scriptPubKeyHex,
      },
    ],
    outputs: [{valueSats: bobAbOutSats, scriptPubKeyHex: bobOutSpk}],
  };
  const bobAbSig0x83Hex = encodeWitnessSigHex(
    bip340Sign(
      bobBtcSkAtOriginationOnly,
      computeBip341TapSighash(abTemplate0x83, 0, SIGHASH_SINGLE_ANYONECANPAY, abDesc.routeLeafHashHex),
    ),
    SIGHASH_SINGLE_ANYONECANPAY,
  );

  const bcTemplate0x83 = {
    version: 2,
    locktime: maturityHeight,
    inputs: [
      {
        txid: txidBC,
        vout: 1,
        sequence: 0xfffffffe,
        prevoutValueSats: 1595,
        prevoutScriptPubKeyHex: bcDesc.scriptPubKeyHex,
      },
    ],
    outputs: [{valueSats: bobBcOutSats, scriptPubKeyHex: bobOutSpk}],
  };
  const bobBcSig0x83Hex = encodeWitnessSigHex(
    bip340Sign(
      bobBtcSkAtOriginationOnly,
      computeBip341TapSighash(bcTemplate0x83, 0, SIGHASH_SINGLE_ANYONECANPAY, bcDesc.routeLeafHashHex),
    ),
    SIGHASH_SINGLE_ANYONECANPAY,
  );

  // Interactive CA prior commitment revocation secret
  const caPriorRevocationSecret = Buffer.alloc(32, 0x99);
  const caRevocationDigest = sha256Hex(caPriorRevocationSecret);

  const trades = [
    {id: 'AB', long: 'Alice', short: 'Bob', notionalUsd: '1', entryUsd: '80000', longMarginSats: '625', shortMarginSats: '1000', fundingTxid: txidAB, fundingVout: 0},
    {id: 'BC', long: 'Bob', short: 'Carol', notionalUsd: '1', entryUsd: '100000', longMarginSats: '500', shortMarginSats: '625', fundingTxid: txidBC, fundingVout: 1},
    {id: 'CA', long: 'Carol', short: 'Alice', notionalUsd: '1', entryUsd: '125000', longMarginSats: '400', shortMarginSats: '400', fundingTxid: txidCA, fundingVout: 2},
  ];
  const vaults = [
    {id: 'bob', owner: 'Bob', nettingSetId: 'btc', fundedSats: '1500', protectedSats: '0'},
    {id: 'carol', owner: 'Carol', nettingSetId: 'btc', fundedSats: '1025', protectedSats: '0'},
  ];
  const policyDigest = 'aa'.repeat(32);
  const routes = [
    {fromVaultId: 'bob', toParty: 'Alice', capacitySats: '250', policyDigest},
    {fromVaultId: 'carol', toParty: 'Alice', capacitySats: '200', policyDigest},
  ];
  const channelHops = [
    {channelId: 'AB', commitmentTxid: txidAB, timeoutHeight: 240, originalPeerOffline: true, authorizationMode: 'mnr02-0x83-at-maturity', preauthorizationPackageDigest: sha256Hex('AB preauth')},
    {channelId: 'BC', commitmentTxid: txidBC, timeoutHeight: 220, originalPeerOffline: true, authorizationMode: 'mnr02-0x83-at-maturity', preauthorizationPackageDigest: sha256Hex('BC preauth')},
    {channelId: 'CA', commitmentTxid: txidCA, timeoutHeight: 200, authorizationMode: 'interactive-bilateral'},
  ];

  const pythSignedUpdate = signedPythPrice();
  const oracleImport = verifyNativePythBtcUsd(pythSignedUpdate);
  const proposal = buildCloseoutProposal({
    routeId: 'triangle-mnr03',
    markUsd: '125000',
    oracleImport,
    trades,
    vaults,
    routes,
    channelHops,
    currentHeight: 120,
  });

  const channelPolicies = [
    {
      channelId: 'AB',
      authorizationMode: 'mnr02-0x83-at-maturity',
      cetPackageDigest: abDesc.routeLeafHashHex,
      refundPackageDigest: abDesc.refundLeafHashHex,
      revocationPackageDigest: sha256Hex('AB L1 no-revocation'),
      routePolicyDigest: sha256Hex('AB policy'),
      activationHeight: 119,
      expiryHeight: 240,
      requiredWalletIds: ['Alice', 'Guard'],
      originationPreauthorizationDigest: sha256Hex('AB preauth'),
      bobPinnedOutputDigest: singleOutputDigestHex(bobAbOutSats, bobOutSpk),
      sighashType: 131,
      l1MaturityHeight: maturityHeight,
      graceEndHeight: maturityHeight + graceBlocks,
      refundHeight: maturityHeight + refundDelayBlocks,
    },
    {
      channelId: 'BC',
      authorizationMode: 'mnr02-0x83-at-maturity',
      cetPackageDigest: bcDesc.routeLeafHashHex,
      refundPackageDigest: bcDesc.refundLeafHashHex,
      revocationPackageDigest: sha256Hex('BC L1 no-revocation'),
      routePolicyDigest: sha256Hex('BC policy'),
      activationHeight: 119,
      expiryHeight: 220,
      requiredWalletIds: ['Carol', 'Guard'],
      originationPreauthorizationDigest: sha256Hex('BC preauth'),
      bobPinnedOutputDigest: singleOutputDigestHex(bobBcOutSats, bobOutSpk),
      sighashType: 131,
      l1MaturityHeight: maturityHeight,
      graceEndHeight: maturityHeight + graceBlocks,
      refundHeight: maturityHeight + refundDelayBlocks,
    },
    {
      channelId: 'CA',
      authorizationMode: 'interactive-bilateral',
      cetPackageDigest: caDesc.cetLeafHashHex,
      refundPackageDigest: caDesc.refundLeafHashHex,
      revocationPackageDigest: caRevocationDigest,
      routePolicyDigest: sha256Hex('CA policy'),
      activationHeight: 119,
      expiryHeight: 200,
      requiredWalletIds: ['Alice', 'Carol'],
    },
  ];

  const epochPolicy = {
    bitcoinNetwork: 'bitcoin-testnet4',
    genesisHash: sha256Hex('testnet4 genesis'),
    previousLedgerRoot: sha256Hex('prior ledger'),
    nearChainId: 'near:testnet',
    nearContractId: 'shz-guard.testnet',
    eventId: 'SHZ/BTCUSD/TESTNET4/177',
    oracleEpoch: 177,
    currentHeight: 120,
    challengeEndHeight: 125,
    channels: channelPolicies,
  };

  const walletKeyIds = ['Alice', 'Carol', 'Guard'];
  const walletKeys = Object.fromEntries(
    walletKeyIds.map(id => [id, generateKeyPairSync('ec', {namedCurve: 'secp256k1'})]),
  );
  const walletPubkeys = Object.fromEntries(
    walletKeyIds.map(id => [id, walletKeys[id].publicKey.export({format: 'pem', type: 'spki'})]),
  );

  let state = openClearingEpoch({proposal, pythSignedUpdate, policy: epochPolicy});
  for (const c of state.channels) {
    for (const walletId of c.requiredWalletIds) {
      const m = {
        sessionHash: state.sessionHash,
        proposalHash: state.proposalHash,
        channelId: c.channelId,
        walletId,
        commitmentTxid: c.commitmentTxid,
        cetPackageDigest: c.cetPackageDigest,
        refundPackageDigest: c.refundPackageDigest,
        revocationPackageDigest: c.revocationPackageDigest,
        oracleReceiptHash: state.oracleReceiptHash,
        routePolicyDigest: c.routePolicyDigest,
        activationHeight: c.activationHeight,
        expiryHeight: c.expiryHeight,
        authorizationMode: c.authorizationMode,
      };
      m.signatureHex = sign('sha256', canonicalWalletApproval(m), walletKeys[walletId].privateKey).toString('hex');
      state = approveChannel(state, m, walletPubkeys);
    }
  }

  const obsKey = generateKeyPairSync('ed25519');
  const nearObservation = {
    observerId: 'IndependentNearNode',
    nearChainId: state.nearChainId,
    nearContractId: state.nearContractId,
    sessionHash: state.sessionHash,
    eventId: state.eventId,
    oracleEpoch: state.oracleEpoch,
    signedPayloadSha256: state.oraclePayloadSha256,
    stateRoot: sha256Hex('NEAR finalized state'),
    blockHash: sha256Hex('NEAR finalized block'),
    blockHeight: 1000050,
    challengeWindowClosed: true,
  };
  nearObservation.signatureHex = sign(null, canonicalNearObservation(nearObservation), obsKey.privateKey).toString('hex');

  const requestedState = requestChannelCloseout(state, {
    height: 180,
    externalCommitmentVerifierReady: true,
    nearObservation,
    observerKeys: {IndependentNearNode: obsKey.publicKey.export({format: 'pem', type: 'spki'})},
  });

  // Step t = 2 (Maturity, Bob 100% Offline!): Alice + Carol + Guard assemble and sign the
  // 3-input, 5-output multilateral clearing transaction using ONLY Bob's t=0 0x83 signatures!
  const clearingTx = {
    version: 2,
    locktime: maturityHeight,
    inputs: [
      {
        txid: txidAB,
        vout: 0,
        sequence: 0xfffffffe,
        prevoutValueSats: 2095,
        prevoutScriptPubKeyHex: abDesc.scriptPubKeyHex,
        witnessHex: [],
      },
      {
        txid: txidBC,
        vout: 1,
        sequence: 0xfffffffe,
        prevoutValueSats: 1595,
        prevoutScriptPubKeyHex: bcDesc.scriptPubKeyHex,
        witnessHex: [],
      },
      {
        txid: txidCA,
        vout: 2,
        sequence: 0xfffffffe,
        prevoutValueSats: 1270,
        prevoutScriptPubKeyHex: caDesc.scriptPubKeyHex,
        witnessHex: [],
      },
    ],
    outputs: [
      {valueSats: bobAbOutSats, scriptPubKeyHex: bobOutSpk},
      {valueSats: bobBcOutSats, scriptPubKeyHex: bobOutSpk},
      {valueSats: aliceWinnerSats, scriptPubKeyHex: aliceOutSpk},
      {valueSats: carolFreedSats, scriptPubKeyHex: carolOutSpk},
      {valueSats: anchorSats, scriptPubKeyHex: anchorOutSpk},
    ],
  };

  // Sign vin[0] (AB): Alice 0x01 + Guard 0x01 + Bob's origination 0x83 (no bobBtcSk!)
  const abSighash0x01 = computeBip341TapSighash(clearingTx, 0, SIGHASH_ALL, abDesc.routeLeafHashHex);
  clearingTx.inputs[0].witnessHex = [
    bobAbSig0x83Hex,
    encodeWitnessSigHex(bip340Sign(guardBtcSk, abSighash0x01), SIGHASH_ALL),
    encodeWitnessSigHex(bip340Sign(aliceBtcSk, abSighash0x01), SIGHASH_ALL),
    abDesc.routeCetScriptHex,
    abDesc.routeControlBlockHex,
  ];

  // Sign vin[1] (BC): Carol 0x01 + Guard 0x01 + Bob's origination 0x83 (no bobBtcSk!)
  const bcSighash0x01 = computeBip341TapSighash(clearingTx, 1, SIGHASH_ALL, bcDesc.routeLeafHashHex);
  clearingTx.inputs[1].witnessHex = [
    bobBcSig0x83Hex,
    encodeWitnessSigHex(bip340Sign(guardBtcSk, bcSighash0x01), SIGHASH_ALL),
    encodeWitnessSigHex(bip340Sign(carolBtcSk, bcSighash0x01), SIGHASH_ALL),
    bcDesc.routeCetScriptHex,
    bcDesc.routeControlBlockHex,
  ];

  // Sign vin[2] (CA): Interactive bilateral 0x00 sorted [pk0, pk1]
  const caSighash0x00 = computeBip341TapSighash(clearingTx, 2, SIGHASH_DEFAULT, caDesc.cetLeafHashHex);
  const sigAliceCA = encodeWitnessSigHex(bip340Sign(aliceBtcSk, caSighash0x00), SIGHASH_DEFAULT);
  const sigCarolCA = encodeWitnessSigHex(bip340Sign(carolBtcSk, caSighash0x00), SIGHASH_DEFAULT);
  const [sigPk0, sigPk1] =
    caDesc.sortedPubkeysHex[0] === alicePk ? [sigAliceCA, sigCarolCA] : [sigCarolCA, sigAliceCA];
  clearingTx.inputs[2].witnessHex = [
    sigPk1,
    sigPk0,
    caDesc.cetScriptHex,
    caDesc.cetControlBlockHex,
  ];

  const channelBindings = [
    {
      channelId: 'AB',
      inputIndex: 0,
      onlineCounterpartyPubkeyXHex: alicePk,
      offlineBobPubkeyXHex: bobPk,
      routerGuardPubkeyXHex: guardPk,
    },
    {
      channelId: 'BC',
      inputIndex: 1,
      onlineCounterpartyPubkeyXHex: carolPk,
      offlineBobPubkeyXHex: bobPk,
      routerGuardPubkeyXHex: guardPk,
    },
    {
      channelId: 'CA',
      inputIndex: 2,
      partyAPubkeyXHex: carolPk,
      partyBPubkeyXHex: alicePk,
      refundCsv,
    },
  ];

  const revocationReceipts = [
    {
      channelId: 'CA',
      priorCommitmentSecretHex: caPriorRevocationSecret.toString('hex'),
      revocationSequence: 10,
      preimageRevealSequence: 11,
      watchtowerBreachTxDigest: sha256Hex('CA watchtower justice tx'),
    },
  ];

  const htlcRouteSchedule = [
    {channelId: 'AB', cltvExpiryHeight: 240},
    {channelId: 'BC', cltvExpiryHeight: 220},
    {channelId: 'CA', cltvExpiryHeight: 200},
  ];

  return {
    requestedState,
    clearingTx,
    channelBindings,
    revocationReceipts,
    htlcRouteSchedule,
    broadcastHeight: 180,
    alicePk,
    bobPk,
    carolPk,
    guardPk,
    aliceBtcSk,
    carolBtcSk,
    guardBtcSk,
    abDesc,
    bcDesc,
  };
}

test('UTXORef cross-repo NUMS internal key and P2TR signing-target vector parity in JS', () => {
  // Exact vector from crates/shz-utxoref/src/lib.rs (`UTXO-Ref/native/dlc-signer/tests/signing_target_vectors.json`)
  const party0 = '6ff108799ba57ff60cd927b1d6cd110e938f8c2546aafa496019047f6bf37b28';
  const party1 = '94046d75efcf1173660ef37bd2036e29641c7717ee64f93dc513cd468c779734';
  assert.equal(
    deriveUtxoRefNumsInternalKeyHex(),
    'c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab',
  );
  const desc = buildInteractiveChannelDescriptor({
    partyAPubkeyXHex: party1,
    partyBPubkeyXHex: party0,
    refundCsv: 144,
  });
  assert.equal(desc.cetLeafHashHex, '96b07f4c218cfa9a56d2a6389137b7a0f1971361875f3d4256884c8994f55144');
  assert.equal(desc.refundLeafHashHex, 'e650bb5c5e8f81ddc841c64e2b868e15892f0d97d616a92cf14f208e6b254e26');
  assert.equal(desc.scriptPubKeyHex, '5120b9e8d1bb16d684e2d08709a501a31c4a88f8bba4f6ae3cf4d1d1c9e891cf164d');
});

test('Bob-offline 0x83 + interactive 3-channel settlement authorizes broadcast without Bob key, then confirms cleanly', () => {
  const f = buildFullSettlementFixture();
  const auth = authorizeBroadcastReadySettlement(f.requestedState, f);
  assert.equal(auth.phase, 'AUTHORIZED_FOR_BITCOIN_BROADCAST');
  assert.equal(auth.readyForBitcoinBroadcast, true);
  // Broadcast readiness is STILL not confirmed on-chain!
  assert.equal(auth.bitcoinSpendEnforced, false);
  assert.equal(auth.collateralReleased, false);
  assert.equal(auth.nearFinalityVerified, false);
  assert.equal(auth.minerFeeSats, '1080');

  // Unconfirmed / insufficient confirmations keep collateral locked
  const pending = confirmBitcoinSettlement(auth, {
    txid: auth.clearingTxid,
    blockHash: sha256Hex('block-181'),
    blockHeight: 181,
    confirmations: 2,
    minConfirmations: 6,
  });
  assert.equal(pending.phase, 'AWAITING_BITCOIN_CONFIRMATIONS');
  assert.equal(pending.collateralReleased, false);
  assert.equal(pending.bitcoinSpendEnforced, false);

  // Confirmed with >= 6 confirmations unlocks collateral enforcement
  const confirmed = confirmBitcoinSettlement(auth, {
    txid: auth.clearingTxid,
    blockHash: sha256Hex('block-181'),
    blockHeight: 181,
    confirmations: 6,
    minConfirmations: 6,
    expectedParentTipHash: sha256Hex('tip-180'),
    observedParentTipHash: sha256Hex('tip-180'),
  });
  assert.equal(confirmed.phase, 'BITCOIN_SETTLEMENT_CONFIRMED');
  assert.equal(confirmed.bitcoinSpendEnforced, true);
  assert.equal(confirmed.collateralReleased, true);
  assert.equal(confirmed.nearFinalityVerified, false);
  assert.equal(confirmed.verifiedChecks.length, 4);
});

test('1-sat shave or output swap on offline Bob output is rejected by pinned digest and 0x83 TapSighash', () => {
  const f = buildFullSettlementFixture();
  const shaved = structuredClone(f.clearingTx);
  shaved.outputs[0].valueSats -= 1;
  shaved.outputs[2].valueSats += 1;
  assert.throws(
    () => authorizeBroadcastReadySettlement(f.requestedState, {...f, clearingTx: shaved}),
    /Bob pinned output digest mismatch/,
  );

  // Even if someone tried to swap vout[0] and vout[1] (AB vs BC Bob outputs), both pinned digest & 0x83 fail
  const swapped = structuredClone(f.clearingTx);
  [swapped.outputs[0], swapped.outputs[1]] = [swapped.outputs[1], swapped.outputs[0]];
  assert.throws(
    () => authorizeBroadcastReadySettlement(f.requestedState, {...f, clearingTx: swapped}),
    /Bob pinned output digest mismatch/,
  );

  // Forged Bob 0x83 signature bytes with intact output value fails BIP-340 Schnorr verification
  const forgedSig = structuredClone(f.clearingTx);
  const origBobWitness = forgedSig.inputs[0].witnessHex[0];
  forgedSig.inputs[0].witnessHex[0] =
    (origBobWitness.startsWith('00') ? '11' : '00') + origBobWitness.slice(2);
  assert.throws(
    () => authorizeBroadcastReadySettlement(f.requestedState, {...f, clearingTx: forgedSig}),
    /invalid Bob 0x83 origination Schnorr signature/,
  );
});

test('revealing HTLC preimage before prior commitment revocation secret is rejected', () => {
  const f = buildFullSettlementFixture();
  const badOrder = [
    {
      ...f.revocationReceipts[0],
      revocationSequence: 12,
      preimageRevealSequence: 12,
    },
  ];
  assert.throws(
    () => authorizeBroadcastReadySettlement(f.requestedState, {...f, revocationReceipts: badOrder}),
    /preimage revealed before prior state revocation/,
  );

  const wrongSecret = [
    {
      ...f.revocationReceipts[0],
      priorCommitmentSecretHex: 'ab'.repeat(32),
    },
  ];
  assert.throws(
    () => authorizeBroadcastReadySettlement(f.requestedState, {...f, revocationReceipts: wrongSecret}),
    /prior commitment revocation secret mismatch/,
  );
});

test('unsafe staggered hop CLTV delta (< 6 blocks) or passing bobSecretKey is rejected', () => {
  const f = buildFullSettlementFixture();
  // Passing bobSecretKey anywhere in bundle is rejected
  assert.throws(
    () =>
      authorizeBroadcastReadySettlement(f.requestedState, {
        ...f,
        clearingTx: {...f.clearingTx, bobSecretKey: '22'.repeat(32)},
      }),
    /offline Bob secret key must never be supplied/,
  );

  // Enforce >= 6 block hop delta requirement
  assert.throws(
    () =>
      authorizeBroadcastReadySettlement(f.requestedState, {
        ...f,
        minCltvDeltaBlocks: 25, // AB(240) - BC(220) = 20 < 25!
      }),
    /unsafe staggered hop CLTV delta/,
  );
});

test('block reorganization halts settlement, freezes ledger, and revokes collateral release', () => {
  const f = buildFullSettlementFixture();
  const auth = authorizeBroadcastReadySettlement(f.requestedState, f);
  const confirmed = confirmBitcoinSettlement(auth, {
    txid: auth.clearingTxid,
    blockHash: sha256Hex('block-181'),
    blockHeight: 181,
    confirmations: 6,
  });
  assert.equal(confirmed.collateralReleased, true);

  // Watchtower detects a 6-block reorg invalidating block-181!
  const halted = confirmBitcoinSettlement(confirmed, {
    txid: auth.clearingTxid,
    blockHash: sha256Hex('block-181'),
    blockHeight: 181,
    confirmations: 0,
    reorgInvalidated: true,
  });
  assert.equal(halted.phase, 'HALTED_ON_REORG');
  assert.equal(halted.collateralReleased, false);
  assert.equal(halted.bitcoinSpendEnforced, false);
  assert.equal(halted.ledgerFrozen, true);

  // Anchor tip mismatch also halts
  const tipHalted = confirmBitcoinSettlement(auth, {
    txid: auth.clearingTxid,
    blockHash: sha256Hex('block-181-alt'),
    blockHeight: 181,
    confirmations: 6,
    expectedParentTipHash: sha256Hex('tip-180-expected'),
    observedParentTipHash: sha256Hex('tip-180-reorged'),
  });
  assert.equal(tipHalted.phase, 'HALTED_ON_REORG');
  assert.equal(tipHalted.reorgReason, 'anchor_tip_mismatch');
  assert.equal(tipHalted.ledgerFrozen, true);
});
