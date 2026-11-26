import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  verifyWithdrawalReceipt,
  verifyConversionQuote,
  signConversionQuote,
  computeWithdrawalId,
  computeReceiptDigest,
  canonicalJson,
  networkId,
} from './withdrawal-receipt.mjs';
import { createJournal, openJournal, createReserveAuthorizer, receiptMessage } from './journal.mjs';
import { createCoordinator, openCoordinator } from './checkpoint.mjs';
import { fundingMessage, verifyBtcFunding, verifyReceiptBackedBinding, reconciliationEvent } from './evidence.mjs';
import { observeReceiptBackedNativeRgb } from './native-peer.mjs';
import { inspectCandidate, verifyDurableWithdrawalReceipt } from './shz-candidate.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.join(here, 'withdrawal-vectors.json');
const h = c => c.repeat(64);

function loadVectors() {
  return JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
}

function buildBridgeFixture(t) {
  const vectors = loadVectors();
  const vec = vectors.vectors[0]; // regtest_p2tr_clearing_v3
  const receipt = structuredClone(vec.receipt);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shz-bridge-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const keys = {}, policy = {};
  for (const role of ['reserve', 'btc', 'rgb', 'conflict']) {
    keys[role] = generateKeyPairSync('ed25519');
    policy[role] = keys[role].publicKey.export({ type: 'spki', format: 'pem' });
  }
  const providerKey = generateKeyPairSync('ed25519');
  const providerId = 'utexo-regtest-lp-1';
  const assetId = 'rgb:fixture-usdt6';
  const assetPrecision = 6;
  const preimage = h('7');
  const paymentHash = createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex');
  const payee = '03' + h('8');
  const payer = '02' + h('9');
  const at = Number(BigInt(receipt.reserved_at_us) / 1000000n) + 1;
  const expiresAt = at + 300;
  // sats = 250000, quotedFeeSats = 1000 -> net = 249000 sats
  // btcUsdCents = 10000000 ($100,000.00), assetUsdCents = 100 ($1.00), decimals = 6
  // floor(249000 * 10000000 * 10^6 / (100000000 * 100)) = 249000000 (249.000000 units)
  const quote = {
    schema: 'SHZ/RGB/CONVERSION-QUOTE/V1',
    withdrawalId: receipt.withdrawal_id,
    receiptDigest: receipt.receipt_digest,
    network: 'regtest',
    sats: receipt.amount_sats,
    assetId,
    assetPrecision,
    assetUnits: '249000000',
    carrierMsat: '3000000',
    providerId,
    oracleSnapshot: {
      source: 'shz-frost-vwap-v1',
      sequence: 42,
      timestampUs: String(BigInt(at) * 1000000n - 5_000_000n),
      btcUsdCents: '10000000',
      assetUsdCents: '100',
      digest: h('a'),
    },
    feeCeilingSats: '2000',
    quotedFeeSats: '1000',
    destination: payee,
    btcScriptPubKey: receipt.destination_script,
    paymentHash,
    issuedAt: at - 1,
    expiresAt,
  };
  const providerSig = signConversionQuote(quote, providerKey.privateKey);
  const receiptPolicy = {
    network: 'regtest',
    routerConfig: vec.router_config,
    routerSigner: vec.router_signer,
    routerId: 1,
    providerKeys: { [providerId]: providerKey.publicKey.export({ type: 'spki', format: 'pem' }) },
    assetAllowlist: { [assetId]: { precision: assetPrecision } },
    maxFeeCeilingSats: '5000',
    maxOracleAgeUs: 30_000_000,
  };
  const journalId = h('b');
  return {
    root, vectors, vec, receipt, quote, providerSig, providerKey, receiptPolicy,
    keys, policy, journalId, at, expiresAt, preimage, paymentHash, payer, payee, assetId,
  };
}

test('cross-language golden vectors verify byte-for-byte against Rust BIP340 receipts', () => {
  const doc = loadVectors();
  assert.equal(doc.schema, 'SHZ/WITHDRAWAL-VECTORS/V1');
  assert.ok(doc.vectors.length >= 3);
  for (const v of doc.vectors) {
    assert.equal(canonicalJson(v.receipt), v.canonical_json);
    assert.equal(computeWithdrawalId(v.receipt), v.receipt.withdrawal_id);
    assert.equal(computeReceiptDigest(v.receipt), v.receipt.receipt_digest);
    assert.equal(networkId(v.network), v.receipt.network_id);
    if (v.network === 'regtest') {
      const ok = verifyWithdrawalReceipt(v.receipt, {
        network: 'regtest',
        routerConfig: v.router_config,
        routerSigner: v.router_signer,
        routerId: 1,
        requireState: 'reserved',
      });
      assert.equal(ok.withdrawalId, v.receipt.withdrawal_id);
      assert.equal(ok.receiptDigest, v.receipt.receipt_digest);
    } else {
      // Cross-network replay (testnet4 vector submitted to regtest policy) MUST fail closed.
      assert.throws(() => verifyWithdrawalReceipt(v.receipt, {
        network: 'regtest',
        routerConfig: v.router_config,
        routerSigner: v.router_signer,
      }), /cross-network/);
    }
  }
});

test('explorer candidates and simulated channel acks cannot authorize asset movement', async t => {
  const f = buildBridgeFixture(t);
  const owner = h('a'), channel = { txid: h('b'), vout: 0 }, other = { txid: h('c'), vout: 1 };
  const raw = o => ({ txid: [...Buffer.from(o.txid, 'hex')], vout: o.vout });
  const j = { journal: { config_hash: h('d'), tip: { records: 50, digest: h('e') }, next_resolution: 2 } };
  const b = {
    seq: 1, digest: h('f'), phase: 'committed', ledger_state: 'Committed', committed_us: 1000,
    accounts: [{ channel, owner, approved: true }, { channel: other, owner: h('9'), approved: true }],
    acks: [{ channel, owner_signed: true, evidence: h('8') }],
    settlements: [{ channel, owner, released_margin_sats: 500, payout_sats: 1500, realized_pnl_sats: 1000 }],
    clearing: { rows: [{ channel: raw(channel), paid: 1000, collected: 0, net: 1000 }, { channel: raw(other), paid: 0, collected: 1000, net: -1000 }], cash_before: 0, cash_after: 0 },
  };
  const accounts = [{ owner, outpoint: channel, kind: 'utxo', balance: { free: 800, realized_pnl: 900 } }];
  const candidate = await inspectCandidate({
    get: async p => structuredClone(p.endsWith('/journal') ? j : p.endsWith('/accounts') ? accounts : { batch: b }),
    sequence: 1, owner, channel,
  });
  assert.equal(candidate.receiptEligible, false);
  assert.throws(() => verifyDurableWithdrawalReceipt(candidate, f.receiptPolicy), /explorer observation or simulated channel ack/);
  const auth = createReserveAuthorizer({
    journalId: f.journalId,
    reservePrivateKey: f.keys.reserve.privateKey,
    receiptPolicy: f.receiptPolicy,
  });
  assert.throws(() => auth.authorize({ id: 'ob1', receipt: candidate, quote: f.quote, providerSig: f.providerSig, at: f.at }), /explorer observation or simulated channel ack/);
});

test('mismatched fields, stale auth, signature substitution, cross-network replay and duplicate receipt rejected', t => {
  const f = buildBridgeFixture(t);
  // 1. Mismatched quote fields
  const badQuoteCases = [
    { sats: '250001' },
    { withdrawalId: h('1') },
    { receiptDigest: h('1') },
    { network: 'testnet4' },
    { assetId: 'rgb:unlisted' },
    { assetPrecision: 8 },
    { assetUnits: '249000001' },
    { carrierMsat: '2999999' },
    { providerId: 'rogue-provider' },
    { quotedFeeSats: '2001' },
    { feeCeilingSats: '6000' },
    { btcScriptPubKey: '5120' + h('f') },
    { paymentHash: '0'.repeat(64) },
    { expiresAt: Number(BigInt(f.receipt.expires_us) / 1000000n) + 10 },
  ];
  for (const patch of badQuoteCases) {
    const q = { ...structuredClone(f.quote), ...patch };
    const sig = signConversionQuote(q, f.providerKey.privateKey);
    assert.throws(() => verifyConversionQuote(q, sig, f.receipt, { ...f.receiptPolicy, nowSec: f.at }), `expected reject for ${JSON.stringify(patch)}`);
  }

  // 2. Stale oracle snapshot & stale quote & expired receipt
  const staleOracle = structuredClone(f.quote);
  staleOracle.oracleSnapshot.timestampUs = String(BigInt(f.at) * 1000000n - 60_000_000n);
  assert.throws(() => verifyConversionQuote(staleOracle, signConversionQuote(staleOracle, f.providerKey.privateKey), f.receipt, { ...f.receiptPolicy, nowSec: f.at }), /stale oracle/);
  assert.throws(() => verifyConversionQuote(f.quote, f.providerSig, f.receipt, { ...f.receiptPolicy, nowSec: f.expiresAt }), /stale or not-yet-valid/);
  assert.throws(() => verifyWithdrawalReceipt(f.receipt, { ...f.receiptPolicy, nowUs: BigInt(f.receipt.expires_us) }), /stale\/expired/);

  // 3. Signature substitution (swap owner_sig and router_sig, tamper byte, wrong provider key)
  const swapped = { ...structuredClone(f.receipt), owner_sig: f.receipt.router_sig, router_sig: f.receipt.owner_sig };
  assert.throws(() => verifyWithdrawalReceipt(swapped, f.receiptPolicy), /signature rejected/);
  const otherProvider = generateKeyPairSync('ed25519');
  assert.throws(() => verifyConversionQuote(f.quote, signConversionQuote(f.quote, otherProvider.privateKey), f.receipt, { ...f.receiptPolicy, nowSec: f.at }), /provider quote signature rejected/);

  // 4. Cross-network replay (testnet4 vector)
  const tn4 = f.vectors.vectors.find(v => v.network === 'testnet4');
  assert.throws(() => verifyWithdrawalReceipt(tn4.receipt, { network: 'regtest', routerConfig: tn4.router_config, routerSigner: tn4.router_signer }), /cross-network/);

  // 5. Duplicate receipt consumption in both authorizer and durable journal + checkpoint CAS
  const auth = createReserveAuthorizer({
    journalId: f.journalId,
    reservePrivateKey: f.keys.reserve.privateKey,
    receiptPolicy: f.receiptPolicy,
  });
  const rec1 = auth.authorize({ id: 'ob-1', receipt: f.receipt, quote: f.quote, providerSig: f.providerSig, at: f.at });
  assert.throws(() => auth.authorize({ id: 'ob-2', receipt: f.receipt, quote: f.quote, providerSig: f.providerSig, at: f.at }), /duplicate withdrawal receipt/);

  const coord = createCoordinator(
    path.join(f.root, 'journal'),
    path.join(f.root, 'pins'),
    f.policy,
    f.journalId,
    { receiptPolicy: f.receiptPolicy }
  );
  const tip1 = coord.append(rec1);
  assert.equal(tip1.seq, 1);
  // Fresh authorizer trying to replay the same receipt into the durable journal under a new obligation ID MUST fail!
  const auth2 = createReserveAuthorizer({
    journalId: f.journalId,
    reservePrivateKey: f.keys.reserve.privateKey,
    receiptPolicy: f.receiptPolicy,
  });
  const recDup = auth2.authorize({ id: 'ob-dup', receipt: f.receipt, quote: f.quote, providerSig: f.providerSig, at: f.at });
  assert.throws(() => coord.append(recDup), /duplicate withdrawal receipt/);
  coord.close();

  // Reopen with exact receiptPolicy succeeds; reopening without receiptPolicy fails header check!
  assert.throws(() => openCoordinator(path.join(f.root, 'journal'), path.join(f.root, 'pins'), f.policy, f.journalId), /header\/policy mismatch/);
  const reopened = openCoordinator(
    path.join(f.root, 'journal'),
    path.join(f.root, 'pins'),
    f.policy,
    f.journalId,
    { receiptPolicy: f.receiptPolicy }
  );
  assert.equal(reopened.snapshot().length, 1);
  assert.equal(reopened.snapshot()[0].withdrawalId, f.receipt.withdrawal_id);
  reopened.close();
});

test('end-to-end receipt-backed funding binding, native peer observation, and signed reconciliation', async t => {
  const f = buildBridgeFixture(t);
  const auth = createReserveAuthorizer({
    journalId: f.journalId,
    reservePrivateKey: f.keys.reserve.privateKey,
    receiptPolicy: f.receiptPolicy,
  });
  const rec = auth.authorize({ id: 'ob-e2e', receipt: f.receipt, quote: f.quote, providerSig: f.providerSig, at: f.at });
  const reserve = rec.event;
  const binding = { payer: f.payer, scriptPubKey: f.receipt.destination_script };
  const bindSig = sign(null, fundingMessage(f.journalId, reserve, binding), f.keys.reserve.privateKey).toString('hex');

  const verifiedBind = verifyReceiptBackedBinding({
    journalId: f.journalId, reserve, binding, signature: bindSig,
    authorizer: f.policy.reserve, receipt: f.receipt, quote: f.quote,
    providerSig: f.providerSig, receiptPolicy: f.receiptPolicy,
  });
  assert.equal(verifiedBind.receiptDigest, f.receipt.receipt_digest);

  // Synthetic Core RPC for BTC funding leg matching receipt.amount_sats (250,000 sats = 0.0025 BTC)
  const txid = h('c'), blockHash = h('d'), tip = h('e');
  const rpcData = {
    getblockchaininfo: { chain: 'regtest', bestblockhash: tip, blocks: 120 },
    getblockheader: { hash: blockHash, height: 114 },
    getblockhash: blockHash,
    getblock: { hash: blockHash, tx: [txid] },
    getrawtransaction: { txid, blockhash: blockHash, in_active_chain: true, vout: [{ n: 0, value: 0.0025, scriptPubKey: { hex: binding.scriptPubKey } }] },
  };
  const btcObs = await verifyBtcFunding({
    rpc: async m => structuredClone(rpcData[m]),
    journalId: f.journalId, reserve, binding, signature: bindSig,
    authorizer: f.policy.reserve, txid, vout: 0, blockHash,
  });

  // Independent native peer observations bound to receipt + quote
  const d = {
    network: 'Regtest', payment_hash: f.paymentHash, payee_pubkey: f.payee,
    asset_id: f.assetId, asset_amount: Number(f.quote.assetUnits), amt_msat: '3000000',
    timestamp: f.at - 1, expiry_sec: f.expiresAt - (f.at - 1),
  };
  const p = { payment_hash: f.paymentHash, payment_type: 'Outbound', status: 'Succeeded', payee_pubkey: f.payee, asset_id: f.assetId, asset_amount: f.quote.assetUnits, amt_msat: 3000000, preimage: f.preimage };
  const q = { ...p, payment_type: 'InboundAutoClaim' };
  const mkCall = (pubkey, pay) => async method => ({
    getNetwork: 'regtest', getCapabilities: { lightning: true }, getAddressState: { status: 'ready' },
    getNetworkInfo: { network: 'Regtest' }, getNodeInfo: { pubkey }, decodeInvoice: d,
    getPayment: pay, getInvoiceStatus: { status: 'Succeeded' },
  }[method]);
  const rgbObs = await observeReceiptBackedNativeRgb({
    payerCall: mkCall(f.payer, p), receiverCall: mkCall(f.payee, q),
    invoice: 'lnbcrt_fixture', receipt: f.receipt, quote: f.quote,
    providerSig: f.providerSig, receiptPolicy: f.receiptPolicy,
    journalId: f.journalId, reserve, binding, signature: bindSig, authorizer: f.policy.reserve,
  });
  assert.equal(rgbObs.receiptDigest, f.receipt.receipt_digest);

  // Drive durable coordinator through reserve -> submit -> reconcile
  const coord = createCoordinator(
    path.join(f.root, 'e2e-journal'),
    path.join(f.root, 'e2e-pins'),
    f.policy,
    f.journalId,
    { receiptPolicy: f.receiptPolicy }
  );
  coord.append(rec);
  coord.append({ event: { type: 'submit', id: 'ob-e2e', at: f.at + 1 }, auth: {} });
  const reconEvent = reconciliationEvent(f.journalId, reserve, binding, btcObs, rgbObs, f.at + 2);
  const reconRec = {
    event: reconEvent,
    auth: {
      btc: sign(null, receiptMessage(f.journalId, 'btc', reserve, reconEvent), f.keys.btc.privateKey).toString('hex'),
      rgb: sign(null, receiptMessage(f.journalId, 'rgb', reserve, reconEvent), f.keys.rgb.privateKey).toString('hex'),
    },
  };
  const finalTip = coord.append(reconRec);
  assert.equal(finalTip.seq, 3);
  assert.equal(coord.snapshot()[0].state, 'reconciled');
  assert.equal(coord.snapshot()[0].credited, true);
  coord.close();
});
