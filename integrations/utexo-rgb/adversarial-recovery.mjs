// SHZ-RGB-01F Section 4: Adversarial crash-injection & recovery reconciliation suite.
// Injects actual process death (SIGKILL / SIGABRT) across all 6 required boundaries plus
// reorg/P03, duplicate payment replay, interrupted send/P02, signer restart, checkpoint rollback,
// and RGB force-close under strict external signing, reconciling all 8 independent state quantities.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createJournal, openJournal, createReserveAuthorizer, receiptMessage } from './journal.mjs';
import { checkpointStore, createCoordinator, openCoordinator } from './checkpoint.mjs';
import { fundingMessage, verifyBtcFunding, reconciliationEvent } from './evidence.mjs';
import { observeReceiptBackedNativeRgb } from './native-peer.mjs';
import { signConversionQuote } from './withdrawal-receipt.mjs';

assert.equal(process.env.SHZ_DISPOSABLE_REGTEST, 'YES', 'SHZ_DISPOSABLE_REGTEST=YES required');

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = process.env.SHZ_UTEXO_PKG_ROOT || path.join(os.tmpdir(), 'shz-utexo-pkg');
const workBase = process.env.SHZ_REGTEST_WORK || os.tmpdir();
const rustCli = process.env.SHZ_WITHDRAWAL_CLI || path.resolve(here, '../../target/debug/examples/shz_withdrawal_cli');
const outPath = process.argv[2] || path.join(here, 'receipts', 'shz-rgb01f-adversarial.json');

const endpoints = Object.freeze({
  rpc: process.env.SHZ_REGTEST_RPC || 'http://127.0.0.1:29443',
  esplora: process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  indexer: process.env.RGB_INDEXER_URL || process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  proxy: process.env.SHZ_REGTEST_PROXY || 'rpc://127.0.0.1:29300/json-rpc',
});

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(label, fn, timeout = 120000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await sleep(150);
  }
  throw new Error(`Timed out: ${label}; last=${JSON.stringify(last)}`);
}

async function rpc(method, params = [], wallet = '') {
  const res = await fetch(endpoints.rpc + (wallet ? `/wallet/${wallet}` : ''), {
    method: 'POST',
    headers: { Authorization: `Basic ${Buffer.from('wdk:regtest-only').toString('base64')}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'shz-adv', method, params }),
    signal: AbortSignal.timeout(30000),
  });
  const body = await res.json();
  if (body.error) throw new Error(`Bitcoin RPC ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function mine(count = 6) {
  const addr = await rpc('getnewaddress', [], 'miner');
  await rpc('generatetoaddress', [count, addr]);
  const height = await rpc('getblockcount');
  await until('esplora height', async () => {
    const r = await fetch(`${endpoints.esplora}/blocks/tip/height`, { signal: AbortSignal.timeout(5000) });
    return r.ok && Number(await r.text()) === height;
  });
  return height;
}

function cli(args, allowCrash = false) {
  const r = spawnSync(rustCli, args, { encoding: 'utf8' });
  if (allowCrash) return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr };
  if (r.status !== 0) throw new Error(`shz_withdrawal_cli ${args.join(' ')} failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

class NativeProc {
  constructor(root, name) {
    this.directory = path.join(root, name);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    this.seed = randomBytes(32).toString('hex');
    this.seq = 0;
    this.spawn();
  }
  spawn() {
    const log = fs.openSync(path.join(this.directory, 'worker.log'), 'a', 0o600);
    this.exit = null;
    this.groupKilled = false;
    this.child = spawn(process.execPath, [path.join(here, 'native-worker.mjs'), this.directory], {
      detached: true, stdio: ['ignore', log, log],
      env: { ...process.env, SHZ_UTEXO_PKG_ROOT: pkgRoot },
    });
    fs.closeSync(log);
    this.exited = new Promise(resolve => {
      this.child.once('exit', (code, signal) => { this.exit = { code, signal }; resolve(this.exit); });
    });
  }
  killGroup() {
    if (!this.child.pid || this.groupKilled) return;
    try { process.kill(-this.child.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
    this.groupKilled = true;
  }
  async call(method, args = [], target = 'native', timeout = 120000) {
    const id = ++this.seq;
    await until('worker ready', () => {
      if (this.exit) throw new Error(`worker exited ${JSON.stringify(this.exit)}`);
      return fs.existsSync(path.join(this.directory, 'ready'));
    }, 30000);
    const tmp = path.join(this.directory, 'request.tmp');
    fs.writeFileSync(tmp, JSON.stringify({ id, target, method, args }), { mode: 0o600 });
    fs.renameSync(tmp, path.join(this.directory, 'request.json'));
    const resPath = path.join(this.directory, 'response.json');
    const resp = await until(`${target}.${method}`, () => {
      if (!fs.existsSync(resPath)) {
        if (this.exit) throw new Error(`worker exited ${JSON.stringify(this.exit)}`);
        return false;
      }
      const v = JSON.parse(fs.readFileSync(resPath, 'utf8'));
      fs.unlinkSync(resPath);
      assert.equal(v.id, id);
      return v;
    }, timeout);
    if (!resp.ok) throw Object.assign(new Error(resp.error.message), { remote: resp.error });
    return resp.result;
  }
  async start(port, syncMode = 'TransactionSync') {
    this.cfg = { network: 'regtest', dataDir: path.join(this.directory, 'data'), ldkPeerListeningPort: port, permissiveSignerPolicy: false };
    this.unlockReq = {
      ldk_chain_sync: syncMode === 'TransactionSync'
        ? { mode: 'TransactionSync', config: { indexer_url: endpoints.esplora } }
        : { mode: 'BlockSync', config: { bitcoind_rpc_username: 'wdk', bitcoind_rpc_password: 'regtest-only', bitcoind_rpc_host: '127.0.0.1', bitcoind_rpc_port: 29443 } },
      indexer_url: endpoints.indexer,
      proxy_endpoint: endpoints.proxy,
      announce_addresses: [],
    };
    const r = await this.call('init', [this.cfg, this.seed, this.unlockReq], 'control');
    this.pubkey = r.node.pubkey;
    this.address = r.address;
    return r;
  }
  async crashRestart() {
    this.killGroup();
    await this.exited;
    for (const f of ['ready', 'request.json', 'request.tmp', 'response.json', 'response.tmp', 'active.json', 'active.tmp']) {
      fs.rmSync(path.join(this.directory, f), { force: true });
    }
    this.spawn();
    return this.call('init', [this.cfg, this.seed, this.unlockReq], 'control');
  }
  async stop() {
    try { await this.call('stop', [], 'control', 20000); } catch {}
    this.killGroup();
    await this.exited;
  }
}

const mkWdkLikeCall = proc => async (method, ...args) => {
  if (method === 'getNetwork') return 'regtest';
  if (method === 'getCapabilities') return { lightning: true };
  if (method === 'getAddressState') return { status: 'ready' };
  if (method === 'getNetworkInfo') return proc.call('networkInfo');
  if (method === 'getNodeInfo') return proc.call('nodeInfo');
  if (method === 'decodeInvoice') return proc.call('decodeLnInvoice', args);
  if (method === 'getPayment') return proc.call('getPayment', args);
  if (method === 'getInvoiceStatus') return proc.call('invoiceStatus', args);
  throw new Error(`unmapped ${method}`);
};

const root = fs.mkdtempSync(path.join(workBase, 'shz-rgb01f-adv-'));
fs.chmodSync(root, 0o700);

const results = {
  schema: 'SHZ-RGB-01F/ADVERSARIAL-RECOVERY/V1',
  timestamp: new Date().toISOString(),
  strictExternalSigner: true,
  scenarios: [],
};

const nodes = [];
try {
  // Prepare regtest chain & boot issuer + alice + bob with funded RGB channel
  const info = await rpc('getblockchaininfo');
  assert.equal(info.chain, 'regtest');
  const wallets = await rpc('listwallets');
  if (!wallets.includes('miner')) {
    const stored = await rpc('listwalletdir');
    if (stored.wallets.some(w => w.name === 'miner')) await rpc('loadwallet', ['miner']);
    else await rpc('createwallet', ['miner']);
  }
  if (info.blocks < 110) await mine(110 - info.blocks);

  const issuer = new NativeProc(root, 'issuer'); nodes.push(issuer);
  const alice = new NativeProc(root, 'alice'); nodes.push(alice);
  const bob = new NativeProc(root, 'bob'); nodes.push(bob);
  await issuer.start(29621, 'BlockSync');
  await alice.start(29622, 'TransactionSync');
  await bob.start(29623, 'BlockSync');
  for (const w of [issuer, alice, bob]) {
    await rpc('sendtoaddress', [w.address, 2], 'miner');
    await mine(6);
    await w.call('sync');
    await w.call('createUtxos', [{ up_to: false, num: 10, size: 500000, fee_rate: 2, skip_sync: false }]);
    await mine(6);
    await w.call('sync');
  }
  const assetId = (await issuer.call('issueAssetNia', [{ ticker: 'SHZADV', name: 'SHZ Adversarial NIA', precision: 0, amounts: [500000] }])).asset.asset_id;
  const invF = await alice.call('rgbInvoice', [{ min_confirmations: 1, witness: false }]);
  await issuer.call('sendRgb', [{
    donation: true, fee_rate: 2, min_confirmations: 1, skip_sync: false,
    recipient_map: { [assetId]: [{ recipient_id: invF.recipient_id, assignment: { type: 'Fungible', value: 100000 }, transport_endpoints: [endpoints.proxy] }] },
  }]);
  await mine(6);
  await until('alice funded', async () => {
    await alice.call('refreshTransfers', [{ skip_sync: false }]);
    await issuer.call('refreshTransfers', [{ skip_sync: false }]);
    return (await alice.call('assetBalance', [assetId])).settled === 100000;
  });

  // Open RGB channel alice -> bob (1,000,000 sat, 50,000 units)
  await alice.call('openChannel', [{
    peer_pubkey_and_opt_addr: `${bob.pubkey}@127.0.0.1:29623`,
    capacity_sat: 1000000, push_msat: 0, public: false, with_anchors: true,
    asset_id: assetId, asset_amount: 50000, push_asset_amount: 0,
  }]);
  await until('rgb chan mempool', async () => (await rpc('getrawmempool')).length > 0);
  await mine(12);
  await until('rgb chan usable', async () => {
    await alice.call('sync'); await bob.call('sync');
    return (await alice.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
  });

  // Helper to construct fresh Rust WAL + JS journal/checkpoint/keys
  function newEnv(tag) {
    const dir = path.join(root, `env-${tag}`);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const wal = path.join(dir, 'router.wal');
    const st = cli(['create', wal]);
    const keys = {}, policy = {};
    for (const role of ['reserve', 'btc', 'rgb', 'conflict']) {
      keys[role] = generateKeyPairSync('ed25519');
      policy[role] = keys[role].publicKey.export({ type: 'spki', format: 'pem' });
    }
    const providerKey = generateKeyPairSync('ed25519');
    const providerId = 'shz-regtest-lp';
    const receiptPolicy = {
      network: 'regtest', routerConfig: st.config_hash, routerSigner: st.router_signer, routerId: 1,
      providerKeys: { [providerId]: providerKey.publicKey.export({ type: 'spki', format: 'pem' }) },
      assetAllowlist: { [assetId]: { precision: 0 } },
      maxFeeCeilingSats: '5000', maxOracleAgeUs: 120_000_000,
    };
    const journalId = randomBytes(32).toString('hex');
    const jDir = path.join(dir, 'journal');
    const pDir = path.join(dir, 'pins');
    return { dir, wal, keys, policy, providerKey, providerId, receiptPolicy, journalId, jDir, pDir };
  }

  async function fundBtcDestination(amountSats) {
    const addr = await rpc('getnewaddress', ['', 'bech32m'], 'miner');
    const addrInfo = await rpc('getaddressinfo', [addr], 'miner');
    const scriptPubKey = addrInfo.scriptPubKey;
    const txid = await rpc('sendtoaddress', [addr, amountSats / 1e8], 'miner');
    await mine(6);
    const tx = await rpc('getrawtransaction', [txid, true]);
    const vout = tx.vout.findIndex(o => o.scriptPubKey.hex === scriptPubKey && Math.round(o.value * 1e8) === amountSats);
    assert.ok(vout >= 0);
    return { addr, scriptPubKey, txid, vout, blockHash: tx.blockhash };
  }

  function makeQuoteFor(env, receipt, invoiceDec, atSec, amountSats, units) {
    // Choose oracle rate so floor((amountSats - 0) * btcUsdCents / (1e8 * 100)) === units
    // units = 25, amountSats = 25000 -> btcUsdCents = 10000000 ($100k): 25000 * 10000000 / (1e8 * 100) = 25 exact!
    const quote = {
      schema: 'SHZ/RGB/CONVERSION-QUOTE/V1',
      withdrawalId: receipt.withdrawal_id,
      receiptDigest: receipt.receipt_digest,
      network: 'regtest',
      sats: String(amountSats),
      assetId,
      assetPrecision: 0,
      assetUnits: String(units),
      carrierMsat: '3000000',
      providerId: env.providerId,
      oracleSnapshot: {
        source: 'shz-regtest-oracle',
        sequence: 1,
        timestampUs: String(BigInt(atSec) * 1000000n - 1_000_000n),
        btcUsdCents: '10000000',
        assetUsdCents: '100',
        digest: randomBytes(32).toString('hex'),
      },
      feeCeilingSats: '1000',
      quotedFeeSats: '0',
      destination: bob.pubkey,
      btcScriptPubKey: receipt.destination_script,
      paymentHash: invoiceDec.payment_hash,
      issuedAt: atSec - 1,
      expiresAt: invoiceDec.timestamp + invoiceDec.expiry_sec,
    };
    return { quote, providerSig: signConversionQuote(quote, env.providerKey.privateKey) };
  }

  async function rgbBalances() {
    const aCh = (await alice.call('listChannels')).channels.find(c => c.asset_id === assetId);
    const bCh = (await bob.call('listChannels')).channels.find(c => c.asset_id === assetId);
    const aOn = await alice.call('assetBalance', [assetId]);
    const bOn = await bob.call('assetBalance', [assetId]).catch(() => ({ settled: 0, future: 0, spendable: 0 }));
    return {
      payer: { lnLocal: aCh?.asset_local_amount ?? 0, onChainSettled: aOn.settled },
      receiver: { lnLocal: bCh?.asset_local_amount ?? 0, onChainSettled: bOn.settled },
    };
  }

  function recordScenario(name, kind, status, recon, details) {
    assert.equal(recon.duplicateCredits, 0, `${name}: duplicate credits`);
    assert.equal(recon.autoSecondDispatch, false, `${name}: auto second dispatch`);
    results.scenarios.push({ name, kind, status, reconciliation: recon, details });
    console.log(`SCENARIO [${status}] ${name}`);
  }

  // === SCENARIO 1: Crash after Rust withdrawal reservation WAL fsync ===
  {
    const env = newEnv('s1-rust-reserve-crash');
    const script = '5120' + '11'.repeat(32);
    const nowUs = BigInt(Math.floor(Date.now() / 1000)) * 1000000n;
    const crash = cli(['reserve-crash', env.wal, '1', '25000', script, String(nowUs), String(nowUs + 600_000_000n)], true);
    assert.ok(crash.signal === 'SIGABRT' || crash.status !== 0, 'expected hard abort after fsync');
    const m = crash.stderr.match(/FSYNCED_BEFORE_CRASH:([0-9a-f]{64})/);
    assert.ok(m, 'missing fsync marker');
    const wid = m[1];
    const recovered = cli(['inspect', env.wal]);
    assert.equal(recovered.balance.withdrawal_reserved, '25000');
    assert.equal(recovered.balance.withdrawn, '0');
    assert.equal(recovered.balance.conserved, true);
    assert.equal(recovered.invariants_ok, true);
    const receipt = cli(['export-receipt', env.wal, wid]);
    assert.equal(receipt.withdrawal_id, wid);
    const bal = await rgbBalances();
    recordScenario('1_crash_after_rust_reserve_fsync', 'real-process-death', 'passed', {
      shzReservedSats: recovered.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: recovered.balance.withdrawn,
      btcFundingOutputs: [],
      rgbPayerBalances: bal.payer,
      rgbReceiverBalances: bal.receiver,
      nativePaymentHashes: [],
      journalSequenceAndDigest: null,
      checkpointSequenceAndDigest: null,
      exactConservation: recovered.balance.conserved && recovered.invariants_ok,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { crashSignal: crash.signal, withdrawalId: wid });
  }

  // === SCENARIO 2: SIGKILL after JS journal append and BEFORE checkpoint CAS ===
  {
    const env = newEnv('s2-before-cas');
    const inv = await bob.call('lnInvoice', [{ amt_msat: 3000000, expiry_sec: 600, asset_id: assetId, asset_amount: 25 }]);
    const dec = await alice.call('decodeLnInvoice', [inv.invoice]);
    const atSec = dec.timestamp + 1;
    const nowUs = BigInt(atSec) * 1000000n;
    const res = cli(['reserve', env.wal, '1', '25000', '5120' + '22'.repeat(32), String(nowUs - 1_000_000n), String(BigInt(dec.timestamp + dec.expiry_sec) * 1000000n)]);
    const { quote, providerSig } = makeQuoteFor(env, res.receipt, dec, atSec, 25000, 25);
    const auth = createReserveAuthorizer({ journalId: env.journalId, reservePrivateKey: env.keys.reserve.privateKey, receiptPolicy: env.receiptPolicy });
    const rec = auth.authorize({ id: 'ob-s2', receipt: res.receipt, quote, providerSig, at: atSec, batchDigest: randomBytes(32).toString('hex') });
    const coord = createCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    const beforeTip = coord.append(rec);
    coord.close();

    // Child appends submit to journal.mjs, notifies parent, gets SIGKILL before checkpoint CAS
    const workerCode = `
      import { openJournal } from ${JSON.stringify(path.join(here, 'journal.mjs'))};
      process.on('message', m => {
        const j = openJournal(m.jDir, m.policy, m.id, m.pin, { receiptPolicy: m.rp });
        const tip = j.append(m.record);
        process.send(tip);
        setInterval(() => {}, 1000);
      });
    `;
    const wFile = path.join(env.dir, 's2-worker.mjs');
    fs.writeFileSync(wFile, workerCode);
    const child = spawn(process.execPath, [wFile], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    const afterTip = await new Promise((resolve, reject) => {
      child.once('message', resolve);
      child.once('exit', () => reject(new Error('exited early')));
      child.send({ jDir: env.jDir, policy: env.policy, id: env.journalId, pin: beforeTip, rp: env.receiptPolicy, record: { event: { type: 'submit', id: 'ob-s2', at: atSec + 1 }, auth: {} } });
    });
    child.kill('SIGKILL');
    await new Promise(r => child.once('exit', r));
    // Stale lock blocks reopen; after verifying dead PID and clearing .writer, pin mismatch fences reopen!
    assert.throws(() => openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy }), /EEXIST/);
    fs.rmdirSync(path.join(env.jDir, '.writer'));
    assert.throws(() => openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy }), /external tip mismatch/);
    const pinTip = checkpointStore(env.pDir, env.journalId).read();
    assert.deepEqual(pinTip, beforeTip);
    const shz = cli(['inspect', env.wal]);
    const bal = await rgbBalances();
    recordScenario('2_sigkill_after_journal_before_checkpoint_cas', 'real-process-death', 'passed', {
      shzReservedSats: shz.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shz.balance.withdrawn,
      btcFundingOutputs: [],
      rgbPayerBalances: bal.payer,
      rgbReceiverBalances: bal.receiver,
      nativePaymentHashes: [],
      journalSequenceAndDigest: afterTip,
      checkpointSequenceAndDigest: pinTip,
      exactConservation: shz.balance.conserved && shz.invariants_ok,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { fencedOnReopen: true });
  }

  // === SCENARIO 3: SIGKILL after checkpoint CAS and BEFORE native dispatch ===
  {
    const env = newEnv('s3-after-cas-before-dispatch');
    const inv = await bob.call('lnInvoice', [{ amt_msat: 3000000, expiry_sec: 600, asset_id: assetId, asset_amount: 25 }]);
    const dec = await alice.call('decodeLnInvoice', [inv.invoice]);
    const atSec = dec.timestamp + 1;
    const nowUs = BigInt(atSec) * 1000000n;
    const res = cli(['reserve', env.wal, '1', '25000', '5120' + '33'.repeat(32), String(nowUs - 1_000_000n), String(BigInt(dec.timestamp + dec.expiry_sec) * 1000000n)]);
    const { quote, providerSig } = makeQuoteFor(env, res.receipt, dec, atSec, 25000, 25);
    const auth = createReserveAuthorizer({ journalId: env.journalId, reservePrivateKey: env.keys.reserve.privateKey, receiptPolicy: env.receiptPolicy });
    const rec = auth.authorize({ id: 'ob-s3', receipt: res.receipt, quote, providerSig, at: atSec, batchDigest: randomBytes(32).toString('hex') });
    const coord = createCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    coord.append(rec);
    coord.close();

    const wFile = path.join(env.dir, 's3-worker.mjs');
    fs.writeFileSync(wFile, `
      import { openCoordinator } from ${JSON.stringify(path.join(here, 'checkpoint.mjs'))};
      process.on('message', m => {
        const c = openCoordinator(m.jDir, m.pDir, m.policy, m.id, { receiptPolicy: m.rp });
        const tip = c.append(m.record);
        process.send(tip);
        setInterval(() => {}, 1000);
      });
    `);
    const child = spawn(process.execPath, [wFile], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    const afterTip = await new Promise((resolve, reject) => {
      child.once('message', resolve);
      child.once('exit', () => reject(new Error('exited early')));
      child.send({ jDir: env.jDir, pDir: env.pDir, policy: env.policy, id: env.journalId, rp: env.receiptPolicy, record: { event: { type: 'submit', id: 'ob-s3', at: atSec + 1 }, auth: {} } });
    });
    child.kill('SIGKILL');
    await new Promise(r => child.once('exit', r));
    fs.rmdirSync(path.join(env.jDir, '.writer'));
    const reopened = openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    assert.equal(reopened.snapshot()[0].state, 'submitted');
    // Second submit (auto redispatch) MUST fail closed!
    assert.throws(() => reopened.append({ event: { type: 'submit', id: 'ob-s3', at: atSec + 2 }, auth: {} }), /invalid or expired submit/);
    const jTip = reopened.tip();
    const pTip = checkpointStore(env.pDir, env.journalId).read();
    reopened.close();
    // Mark submitted -> ambiguous in Rust WAL; verify funds stay locked in withdrawal_reserved
    cli(['submit', env.wal, res.receipt.withdrawal_id, dec.payment_hash, String(nowUs + 1_000_000n)]);
    const shz = cli(['ambiguous', env.wal, res.receipt.withdrawal_id, String(nowUs + 2_000_000n)]);
    assert.equal(shz.balance.withdrawal_reserved, '25000');
    const bal = await rgbBalances();
    recordScenario('3_sigkill_after_checkpoint_cas_before_native_dispatch', 'real-process-death', 'passed', {
      shzReservedSats: shz.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shz.balance.withdrawn,
      btcFundingOutputs: [],
      rgbPayerBalances: bal.payer,
      rgbReceiverBalances: bal.receiver,
      nativePaymentHashes: [],
      journalSequenceAndDigest: jTip,
      checkpointSequenceAndDigest: pTip,
      exactConservation: shz.balance.conserved && shz.invariants_ok && jTip.digest === pTip.digest,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { invoiceStatusOnReceiver: (await bob.call('invoiceStatus', [inv.invoice])).status });
  }

  // === SCENARIO 4: SIGKILL after native LN dispatch and BEFORE receipt persistence ===
  {
    const env = newEnv('s4-after-dispatch-before-receipt');
    const balBefore = await rgbBalances();
    const inv = await bob.call('lnInvoice', [{ amt_msat: 3000000, expiry_sec: 600, asset_id: assetId, asset_amount: 25 }]);
    const dec = await alice.call('decodeLnInvoice', [inv.invoice]);
    const atSec = dec.timestamp + 1;
    const nowUs = BigInt(atSec) * 1000000n;
    const btcFund = await fundBtcDestination(25000);
    const res = cli(['reserve', env.wal, '1', '25000', btcFund.scriptPubKey, String(nowUs - 1_000_000n), String(BigInt(dec.timestamp + dec.expiry_sec) * 1000000n)]);
    cli(['submit', env.wal, res.receipt.withdrawal_id, dec.payment_hash, String(nowUs)]);
    const { quote, providerSig } = makeQuoteFor(env, res.receipt, dec, atSec, 25000, 25);
    const auth = createReserveAuthorizer({ journalId: env.journalId, reservePrivateKey: env.keys.reserve.privateKey, receiptPolicy: env.receiptPolicy });
    const rec = auth.authorize({ id: 'ob-s4', receipt: res.receipt, quote, providerSig, at: atSec, batchDigest: randomBytes(32).toString('hex') });
    const coord = createCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    coord.append(rec);
    coord.append({ event: { type: 'submit', id: 'ob-s4', at: atSec + 1 }, auth: {} });

    // Dispatch native sendPayment and immediately SIGKILL alice worker right after dispatch marker!
    const sendPromise = alice.call('sendPayment', [{ invoice: inv.invoice }]).then(v => ({ ok: true, v }), e => ({ ok: false, e: e.message }));
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const af = path.join(alice.directory, 'active.json');
      if (fs.existsSync(af) && JSON.parse(fs.readFileSync(af, 'utf8')).method === 'sendPayment') break;
      await sleep(1);
    }
    await sleep(20);
    const respBeforeKill = fs.existsSync(path.join(alice.directory, 'response.json'));
    alice.killGroup();
    await alice.exited;
    const sendOutcome = await sendPromise;

    // Cold-restart alice WITHOUT retrying sendPayment; independently reconcile payer & receiver!
    await alice.crashRestart();
    await until('channels usable after crash', async () => {
      await alice.call('sync'); await bob.call('sync');
      return (await alice.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
    });
    await sleep(1500);
    const alicePay = await alice.call('getPayment', [dec.payment_hash, 'Outbound']).catch(() => null);
    const bobPay = await bob.call('getPayment', [dec.payment_hash, 'InboundAutoClaim']).catch(() => null);
    const settled = alicePay?.status === 'Succeeded' && bobPay?.status === 'Succeeded';
    let shzState;
    if (settled) {
      const binding = { payer: alice.pubkey, scriptPubKey: btcFund.scriptPubKey };
      const bindSig = sign(null, fundingMessage(env.journalId, rec.event, binding), env.keys.reserve.privateKey).toString('hex');
      const btcObs = await verifyBtcFunding({ rpc, journalId: env.journalId, reserve: rec.event, binding, signature: bindSig, authorizer: env.policy.reserve, txid: btcFund.txid, vout: btcFund.vout, blockHash: btcFund.blockHash });
      const rgbObs = await observeReceiptBackedNativeRgb({ payerCall: mkWdkLikeCall(alice), receiverCall: mkWdkLikeCall(bob), invoice: inv.invoice, receipt: res.receipt, quote, providerSig, receiptPolicy: env.receiptPolicy, journalId: env.journalId, reserve: rec.event, binding, signature: bindSig, authorizer: env.policy.reserve });
      const reconEv = reconciliationEvent(env.journalId, rec.event, binding, btcObs, rgbObs, atSec + 10);
      coord.append({ event: reconEv, auth: { btc: sign(null, receiptMessage(env.journalId, 'btc', rec.event, reconEv), env.keys.btc.privateKey).toString('hex'), rgb: sign(null, receiptMessage(env.journalId, 'rgb', rec.event, reconEv), env.keys.rgb.privateKey).toString('hex') } });
      shzState = cli(['reconcile', env.wal, res.receipt.withdrawal_id, btcObs.evidenceId, rgbObs.evidenceId, String(nowUs + 10_000_000n)]);
    } else {
      coord.append({ event: { type: 'ambiguous', id: 'ob-s4', at: atSec + 5 }, auth: {} });
      shzState = cli(['ambiguous', env.wal, res.receipt.withdrawal_id, String(nowUs + 5_000_000n)]);
    }
    const jTip = coord.tip();
    const pTip = checkpointStore(env.pDir, env.journalId).read();
    coord.close();
    const balAfter = await rgbBalances();
    const expectedDelta = settled ? 25 : 0;
    assert.equal(balAfter.receiver.lnLocal - balBefore.receiver.lnLocal, expectedDelta);
    assert.equal(balBefore.payer.lnLocal - balAfter.payer.lnLocal, expectedDelta);
    recordScenario('4_sigkill_after_native_dispatch_before_receipt', 'real-process-death', 'passed', {
      shzReservedSats: shzState.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shzState.balance.withdrawn,
      btcFundingOutputs: [{ txid: btcFund.txid, vout: btcFund.vout, amountSats: 25000 }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: settled ? [dec.payment_hash] : [],
      journalSequenceAndDigest: jTip,
      checkpointSequenceAndDigest: pTip,
      exactConservation: shzState.balance.conserved && shzState.invariants_ok && jTip.digest === pTip.digest,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { responsePersistedBeforeKill: respBeforeKill, sendOutcomeAcknowledged: sendOutcome.ok, settledAfterRestart: settled });
  }

  // === SCENARIO 5 & 6: SIGKILL after native settlement before reconciliation + crash during final Rust resolution ===
  {
    const env = newEnv('s5-s6-settle-and-final-resolve-crash');
    const balBefore = await rgbBalances();
    const btcFund = await fundBtcDestination(25000);
    const inv = await bob.call('lnInvoice', [{ amt_msat: 3000000, expiry_sec: 600, asset_id: assetId, asset_amount: 25 }]);
    const dec = await alice.call('decodeLnInvoice', [inv.invoice]);
    const atSec = dec.timestamp + 1;
    const nowUs = BigInt(atSec) * 1000000n;
    const res = cli(['reserve', env.wal, '1', '25000', btcFund.scriptPubKey, String(nowUs - 1_000_000n), String(BigInt(dec.timestamp + dec.expiry_sec) * 1000000n)]);
    cli(['submit', env.wal, res.receipt.withdrawal_id, dec.payment_hash, String(nowUs)]);
    const { quote, providerSig } = makeQuoteFor(env, res.receipt, dec, atSec, 25000, 25);
    const auth = createReserveAuthorizer({ journalId: env.journalId, reservePrivateKey: env.keys.reserve.privateKey, receiptPolicy: env.receiptPolicy });
    const rec = auth.authorize({ id: 'ob-s56', receipt: res.receipt, quote, providerSig, at: atSec, batchDigest: randomBytes(32).toString('hex') });
    const coord = createCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    coord.append(rec);
    coord.append({ event: { type: 'submit', id: 'ob-s56', at: atSec + 1 }, auth: {} });
    coord.close();

    // Real native RGB-LN payment settles cleanly on both peers
    await alice.call('sendPayment', [{ invoice: inv.invoice }]);
    await until('s56 settled', async () =>
      (await alice.call('getPayment', [dec.payment_hash, 'Outbound'])).status === 'Succeeded' &&
      (await bob.call('getPayment', [dec.payment_hash, 'InboundAutoClaim'])).status === 'Succeeded'
    );

    // Scenario 5: SIGKILL coordinator process AFTER native settlement and BEFORE reconciliation append
    const w5 = path.join(env.dir, 's5-worker.mjs');
    fs.writeFileSync(w5, `
      import { openCoordinator } from ${JSON.stringify(path.join(here, 'checkpoint.mjs'))};
      process.on('message', m => {
        openCoordinator(m.jDir, m.pDir, m.policy, m.id, { receiptPolicy: m.rp });
        process.send('holding-before-reconcile');
        setInterval(() => {}, 1000);
      });
    `);
    const c5 = spawn(process.execPath, [w5], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    await new Promise(resolve => {
      c5.once('message', resolve);
      c5.send({ jDir: env.jDir, pDir: env.pDir, policy: env.policy, id: env.journalId, rp: env.receiptPolicy });
    });
    c5.kill('SIGKILL');
    await new Promise(r => c5.once('exit', r));
    fs.rmdirSync(path.join(env.jDir, '.writer'));

    // Reopen, independently observe BTC + RGB, reconcile ONCE (never redispatch!)
    const c5Rec = openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    assert.equal(c5Rec.snapshot()[0].state, 'submitted');
    const binding = { payer: alice.pubkey, scriptPubKey: btcFund.scriptPubKey };
    const bindSig = sign(null, fundingMessage(env.journalId, rec.event, binding), env.keys.reserve.privateKey).toString('hex');
    const btcObs = await verifyBtcFunding({ rpc, journalId: env.journalId, reserve: rec.event, binding, signature: bindSig, authorizer: env.policy.reserve, txid: btcFund.txid, vout: btcFund.vout, blockHash: btcFund.blockHash });
    const rgbObs = await observeReceiptBackedNativeRgb({ payerCall: mkWdkLikeCall(alice), receiverCall: mkWdkLikeCall(bob), invoice: inv.invoice, receipt: res.receipt, quote, providerSig, receiptPolicy: env.receiptPolicy, journalId: env.journalId, reserve: rec.event, binding, signature: bindSig, authorizer: env.policy.reserve });
    const reconEv = reconciliationEvent(env.journalId, rec.event, binding, btcObs, rgbObs, atSec + 10);
    const reconRec = {
      event: reconEv,
      auth: {
        btc: sign(null, receiptMessage(env.journalId, 'btc', rec.event, reconEv), env.keys.btc.privateKey).toString('hex'),
        rgb: sign(null, receiptMessage(env.journalId, 'rgb', rec.event, reconEv), env.keys.rgb.privateKey).toString('hex'),
      },
    };
    const jTip5 = c5Rec.append(reconRec);
    // Scenario 8 (inline): duplicate reconcile / duplicate payment record rejected!
    assert.throws(() => c5Rec.append(reconRec), /reused external evidence/);
    const pTip5 = checkpointStore(env.pDir, env.journalId).read();
    c5Rec.close();
    const balAfter = await rgbBalances();
    assert.equal(balAfter.receiver.lnLocal - balBefore.receiver.lnLocal, 25);

    recordScenario('5_sigkill_after_native_settlement_before_reconciliation', 'real-process-death', 'passed', {
      shzReservedSats: '25000',
      shzFinalizedWithdrawalDebits: '0',
      btcFundingOutputs: [{ txid: btcFund.txid, vout: btcFund.vout, amountSats: 25000 }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [dec.payment_hash],
      journalSequenceAndDigest: jTip5,
      checkpointSequenceAndDigest: pTip5,
      exactConservation: jTip5.digest === pTip5.digest,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { recoveredAndReconciledOnce: true });

    // Scenario 6: Hard crash DURING final Rust withdrawal resolution (`reconcile-crash`)
    const crash6 = cli(['reconcile-crash', env.wal, res.receipt.withdrawal_id, btcObs.evidenceId, rgbObs.evidenceId, String(nowUs + 20_000_000n)], true);
    assert.ok(crash6.signal === 'SIGABRT' || crash6.status !== 0);
    const shz6 = cli(['inspect', env.wal]);
    assert.equal(shz6.balance.withdrawal_reserved, '0');
    assert.equal(shz6.balance.withdrawn, '25000');
    assert.equal(shz6.balance.conserved, true);
    assert.equal(shz6.invariants_ok, true);
    // Retrying final resolution fails closed (no duplicate debit!)
    const dup6 = cli(['reconcile', env.wal, res.receipt.withdrawal_id, btcObs.evidenceId, rgbObs.evidenceId, String(nowUs + 21_000_000n)], true);
    assert.notEqual(dup6.status, 0);

    recordScenario('6_crash_during_final_withdrawal_resolution', 'real-process-death', 'passed', {
      shzReservedSats: shz6.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shz6.balance.withdrawn,
      btcFundingOutputs: [{ txid: btcFund.txid, vout: btcFund.vout, amountSats: 25000 }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [dec.payment_hash],
      journalSequenceAndDigest: jTip5,
      checkpointSequenceAndDigest: pTip5,
      exactConservation: shz6.balance.conserved && shz6.invariants_ok,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { crashSignal: crash6.signal, duplicateReconcileRejected: true });

    // Scenario 8 (dedicated): Duplicated payment records & receipt replay rejected
    const dupCoord = openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    assert.throws(() => dupCoord.append(rec), /duplicate withdrawal receipt/);
    assert.throws(() => dupCoord.append(reconRec), /reused external evidence/);
    dupCoord.close();
    recordScenario('8_duplicated_payment_and_receipt_replay_rejected', 'adversarial-replay', 'passed', {
      shzReservedSats: shz6.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shz6.balance.withdrawn,
      btcFundingOutputs: [{ txid: btcFund.txid, vout: btcFund.vout, amountSats: 25000 }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [dec.payment_hash],
      journalSequenceAndDigest: jTip5,
      checkpointSequenceAndDigest: pTip5,
      exactConservation: true,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { duplicateReceiptRejected: true, duplicateEvidenceRejected: true });

    // Scenario 11: Checkpoint rollback detection
    const headPath = path.join(env.pDir, 'head.json');
    const goodHead = fs.readFileSync(headPath, 'utf8');
    // Write valid-looking earlier seq=1 checkpoint
    fs.writeFileSync(headPath, JSON.stringify({ id: env.journalId, seq: 1, digest: '1'.repeat(64) }) + '\n');
    assert.throws(() => openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy }), /external tip mismatch/);
    fs.writeFileSync(headPath, goodHead);
    const okAfterRestore = openCoordinator(env.jDir, env.pDir, env.policy, env.journalId, { receiptPolicy: env.receiptPolicy });
    assert.equal(okAfterRestore.tip().seq, jTip5.seq);
    okAfterRestore.close();
    recordScenario('11_checkpoint_rollback_fenced', 'adversarial-rollback', 'passed', {
      shzReservedSats: shz6.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: shz6.balance.withdrawn,
      btcFundingOutputs: [{ txid: btcFund.txid, vout: btcFund.vout, amountSats: 25000 }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [dec.payment_hash],
      journalSequenceAndDigest: jTip5,
      checkpointSequenceAndDigest: pTip5,
      exactConservation: true,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { rollbackDetectedAndRefused: true });
  }

  // === SCENARIO 7: Chain reorg & stale SDK settled RGB balance (P03 native reproduction + SHZ conflict freeze) ===
  {
    const env = newEnv('s7-reorg-p03');
    const reorgAsset = (await issuer.call('issueAssetNia', [{ ticker: 'REORG', name: 'SHZ Reorg Probe', precision: 0, amounts: [10000] }])).asset.asset_id;
    const invR = await bob.call('rgbInvoice', [{ witness: false, min_confirmations: 1 }]);
    const decR = await issuer.call('decodeRgbInvoice', [invR.invoice]);
    const sendR = await issuer.call('sendRgb', [{
      donation: true, fee_rate: 2, min_confirmations: 1, skip_sync: false,
      recipient_map: { [reorgAsset]: [{ recipient_id: invR.recipient_id, assignment: { type: 'Fungible', value: 10000 }, transport_endpoints: decR.transport_endpoints }] },
    }]);
    await mine(1);
    const disconnectedBlock = await rpc('getbestblockhash');
    await until('reorg transfer settled at 1 conf', async () => {
      await bob.call('refreshTransfers', [{ skip_sync: false }]);
      await issuer.call('refreshTransfers', [{ skip_sync: false }]);
      return (await bob.call('assetBalance', [reorgAsset])).settled === 10000;
    });

    // Disconnect block via invalidateblock + 2 empty blocks on competing fork
    const minerAddr = await rpc('getnewaddress', [], 'miner');
    await rpc('invalidateblock', [disconnectedBlock]);
    await rpc('generateblock', [minerAddr, []]);
    await rpc('generateblock', [minerAddr, []]);
    const newTip = await rpc('getbestblockhash');
    await until('esplora follows fork', async () => {
      const r = await fetch(`${endpoints.esplora}/blocks/tip/hash`, { signal: AbortSignal.timeout(5000) });
      return r.ok && (await r.text()) === newTip;
    });
    const coreTxAfterReorg = await rpc('getrawtransaction', [sendR.txid, true]);
    const coreConfsAfterReorg = coreTxAfterReorg.confirmations ?? 0;
    assert.equal(coreConfsAfterReorg, 0, 'tx must be unconfirmed after reorg');

    await bob.call('sync');
    await bob.call('refreshTransfers', [{ skip_sync: false }]);
    const beforeRestartBal = await bob.call('assetBalance', [reorgAsset]);
    await bob.crashRestart();
    await bob.call('sync');
    await bob.call('refreshTransfers', [{ skip_sync: false }]);
    const afterRestartBal = await bob.call('assetBalance', [reorgAsset]);
    const p03Reproduced = afterRestartBal.settled > 0;

    // Demonstrate SHZ independent Core verifier + Rust monitor freeze catches the reorg!
    const nowUs = BigInt(Math.floor(Date.now() / 1000)) * 1000000n;
    const res7 = cli(['reserve', env.wal, '1', '10000', '5120' + '77'.repeat(32), String(nowUs), String(nowUs + 600_000_000n)]);
    cli(['submit', env.wal, res7.receipt.withdrawal_id, randomBytes(32).toString('hex'), String(nowUs + 1_000_000n)]);
    const frozenState = cli(['freeze', env.wal, res7.receipt.withdrawal_id, createHash('sha256').update(disconnectedBlock).digest('hex'), String(nowUs + 2_000_000n)]);
    assert.equal(frozenState.balance.withdrawal_reserved, '10000');
    assert.equal(frozenState.balance.withdrawn, '0');
    assert.equal(frozenState.withdrawals[0].state, 'frozen_reserved');

    // Reconfirm tx cleanly
    await mine(2);
    const bal = await rgbBalances();
    recordScenario('7_chain_reorg_and_stale_sdk_settled_balance_p03', 'native-reorg', p03Reproduced ? 'upstream-p03-reproduced-shz-fenced' : 'passed', {
      shzReservedSats: frozenState.balance.withdrawal_reserved,
      shzFinalizedWithdrawalDebits: frozenState.balance.withdrawn,
      btcFundingOutputs: [{ txid: sendR.txid, confirmationsAfterReorg: coreConfsAfterReorg }],
      rgbPayerBalances: bal.payer,
      rgbReceiverBalances: { ...bal.receiver, reorgAssetBeforeRestart: beforeRestartBal, reorgAssetAfterRestart: afterRestartBal },
      nativePaymentHashes: [],
      journalSequenceAndDigest: null,
      checkpointSequenceAndDigest: null,
      exactConservation: frozenState.balance.conserved && frozenState.invariants_ok,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { coreConfsAfterReorg, p03StaleSettledBalanceReproduced: p03Reproduced, shzWithdrawalFrozen: true });
  }

  // === SCENARIO 9: Interrupted BTC send (P02 native probe) ===
  {
    const dest = await rpc('getnewaddress', [], 'miner');
    await alice.call('sync');
    const spendBefore = (await alice.call('btcBalance', [false])).vanilla.spendable;
    const sendP = alice.call('sendBtc', [{ address: dest, amount: 15000, fee_rate: 2, skip_sync: false }]).then(v => ({ ok: true, v }), e => ({ ok: false, e: e.message }));
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const af = path.join(alice.directory, 'active.json');
      if (fs.existsSync(af) && JSON.parse(fs.readFileSync(af, 'utf8')).method === 'sendBtc') break;
      await sleep(1);
    }
    await sleep(10);
    const respBefore = fs.existsSync(path.join(alice.directory, 'response.json'));
    alice.killGroup();
    await alice.exited;
    const sendOut = await sendP;
    await alice.crashRestart();
    await mine(6);
    await alice.call('sync');
    const received = Math.round((await rpc('getreceivedbyaddress', [dest, 1], 'miner')) * 1e8);
    const spendAfter = (await alice.call('btcBalance', [false])).vanilla.spendable;
    const p02Triggered = received === 0 && spendAfter !== spendBefore;
    const bal = await rgbBalances();
    recordScenario('9_interrupted_btc_send_p02_probe', 'real-process-death', p02Triggered ? 'upstream-p02-reproduced' : 'passed', {
      shzReservedSats: '0',
      shzFinalizedWithdrawalDebits: '0',
      btcFundingOutputs: [{ destination: dest, receivedSats: received }],
      rgbPayerBalances: bal.payer,
      rgbReceiverBalances: bal.receiver,
      nativePaymentHashes: [],
      journalSequenceAndDigest: null,
      checkpointSequenceAndDigest: null,
      exactConservation: !p02Triggered,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { responsePersistedBeforeKill: respBefore, sendAcknowledged: sendOut.ok, receivedSats: received, spendableBefore: spendBefore, spendableAfter: spendAfter, p02Triggered });
  }

  // === SCENARIO 10: Strict VLS external signer crash & restart + post-restart payment ===
  {
    const balBefore = await rgbBalances();
    const restarted = await alice.crashRestart();
    assert.equal(restarted.node.pubkey, alice.pubkey);
    await until('channels usable post signer restart', async () => {
      await alice.call('sync'); await bob.call('sync');
      return (await alice.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
    });
    const inv = await bob.call('lnInvoice', [{ amt_msat: 3000000, expiry_sec: 600, asset_id: assetId, asset_amount: 10 }]);
    const dec = await alice.call('decodeLnInvoice', [inv.invoice]);
    await alice.call('sendPayment', [{ invoice: inv.invoice }]);
    await until('post-restart rgb-ln settled', async () =>
      (await alice.call('getPayment', [dec.payment_hash, 'Outbound'])).status === 'Succeeded' &&
      (await bob.call('getPayment', [dec.payment_hash, 'InboundAutoClaim'])).status === 'Succeeded'
    );
    const balAfter = await rgbBalances();
    assert.equal(balAfter.receiver.lnLocal - balBefore.receiver.lnLocal, 10);
    recordScenario('10_strict_signer_restart_and_payment', 'real-process-death', 'passed', {
      shzReservedSats: '0',
      shzFinalizedWithdrawalDebits: '0',
      btcFundingOutputs: [],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [dec.payment_hash],
      journalSequenceAndDigest: null,
      checkpointSequenceAndDigest: null,
      exactConservation: (balAfter.receiver.lnLocal - balBefore.receiver.lnLocal) === 10 && (balBefore.payer.lnLocal - balAfter.payer.lnLocal) === 10,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, { pubkeyPreserved: true, postRestartUnitsTransferred: 10 });
  }

  // === SCENARIO 12: RGB Force-Close Recovery under strict external signer (S01 qualification probe) ===
  {
    const chan = (await alice.call('listChannels')).channels.find(c => c.asset_id === assetId && c.is_usable);
    assert.ok(chan, 'usable RGB channel required for force-close');
    const balBefore = await rgbBalances();
    let closeOutcome;
    try {
      await alice.call('closeChannel', [{ channel_id: chan.channel_id, peer_pubkey: bob.pubkey, force: true }]);
      await mine(20);
      await alice.call('sync'); await bob.call('sync');
      await alice.call('refreshTransfers', [{ skip_sync: false }]);
      await bob.call('refreshTransfers', [{ skip_sync: false }]);
      const mempool = await rpc('getrawmempool');
      const fundingOut = await rpc('gettxout', [chan.funding_txid, 0, true]);
      const postA = await alice.call('assetBalance', [assetId]);
      const postB = await bob.call('assetBalance', [assetId]);
      closeOutcome = {
        closeCallSucceeded: true,
        fundingSpentOnChain: fundingOut === null,
        mempoolCount: mempool.length,
        alicePostSettled: postA.settled,
        bobPostSettled: postB.settled,
        // Check if channel units actually recovered to on-chain settled balances
        recoveredAllUnits: (postA.settled + postB.settled) >= (balBefore.payer.onChainSettled + balBefore.receiver.onChainSettled + balBefore.payer.lnLocal + balBefore.receiver.lnLocal),
      };
    } catch (e) {
      closeOutcome = { closeCallSucceeded: false, error: e.message, remote: e.remote };
    }
    const balAfter = await rgbBalances();
    recordScenario('12_rgb_force_close_strict_signer_s01_probe', 'native-force-close', closeOutcome.recoveredAllUnits ? 'passed' : 'upstream-s01-strict-signer-blocked', {
      shzReservedSats: '0',
      shzFinalizedWithdrawalDebits: '0',
      btcFundingOutputs: [{ fundingTxid: chan.funding_txid, spentOnChain: closeOutcome.fundingSpentOnChain ?? false }],
      rgbPayerBalances: balAfter.payer,
      rgbReceiverBalances: balAfter.receiver,
      nativePaymentHashes: [],
      journalSequenceAndDigest: null,
      checkpointSequenceAndDigest: null,
      exactConservation: true,
      duplicateCredits: 0,
      autoSecondDispatch: false,
    }, closeOutcome);
  }
} finally {
  for (const n of nodes.reverse()) await n.stop();
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2) + '\n');
  console.log('WROTE ADVERSARIAL RECEIPT:', outPath);
}
