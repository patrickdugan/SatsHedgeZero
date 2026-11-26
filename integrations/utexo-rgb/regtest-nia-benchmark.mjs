// SHZ-RGB-01F: Reproducible native UTEXO regtest benchmark (NIA/IFA fixture, strict external signer).
// Starts with 1 smoke payment per rail before scaling to target attempts (default 100 per rail).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { checkDecoded } from './adapter.mjs';
import { qualifyNativePair } from './native-peer.mjs';

assert.equal(process.env.SHZ_DISPOSABLE_REGTEST, 'YES', 'SHZ_DISPOSABLE_REGTEST=YES required');

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = process.env.SHZ_UTEXO_PKG_ROOT || path.join(os.tmpdir(), 'shz-utexo-pkg');
const workBase = process.env.SHZ_REGTEST_WORK || os.tmpdir();
const require = createRequire(import.meta.url);
const native = require(path.join(pkgRoot, 'node_modules/@utexo/rgb-lightning-node-nodejs'));
const wdk = await import(path.join(pkgRoot, 'node_modules/@utexo/wdk-rgb-lightning/index-node.js'));

const endpoints = Object.freeze({
  rpc: process.env.SHZ_REGTEST_RPC || 'http://127.0.0.1:29443',
  esplora: process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  indexer: process.env.RGB_INDEXER_URL || process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  proxy: process.env.SHZ_REGTEST_PROXY || 'rpc://127.0.0.1:29300/json-rpc',
});

const targetAttempts = Number(process.argv[2] ?? 100);
const chainAttempts = Number(process.argv[3] ?? targetAttempts);
const outPath = process.argv[4] || path.join(here, 'receipts', 'shz-rgb01f-benchmarks.json');
assert.ok(Number.isSafeInteger(targetAttempts) && targetAttempts >= 1 && targetAttempts <= 100);
assert.ok(Number.isSafeInteger(chainAttempts) && chainAttempts >= 1 && chainAttempts <= 100);

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
    body: JSON.stringify({ jsonrpc: '2.0', id: 'shz-rgb01f', method, params }),
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
  await until('esplora tip', async () => {
    const r = await fetch(`${endpoints.esplora}/blocks/tip/height`, { signal: AbortSignal.timeout(5000) });
    return r.ok && Number(await r.text()) === height;
  });
  return height;
}

async function txFeeSats(txid) {
  const tx = await rpc('getrawtransaction', [txid, true]);
  if (typeof tx.fee === 'number') return Math.round(tx.fee * 1e8);
  let inSats = 0;
  for (const vin of tx.vin) {
    const prev = await rpc('getrawtransaction', [vin.txid, true]);
    inSats += Math.round(prev.vout[vin.vout].value * 1e8);
  }
  const outSats = tx.vout.reduce((s, o) => s + Math.round(o.value * 1e8), 0);
  return inSats - outSats;
}

async function prepareChain() {
  const info = await rpc('getblockchaininfo');
  assert.equal(info.chain, 'regtest');
  const wallets = await rpc('listwallets');
  if (!wallets.includes('miner')) {
    const stored = await rpc('listwalletdir');
    if (stored.wallets.some(w => w.name === 'miner')) await rpc('loadwallet', ['miner']);
    else await rpc('createwallet', ['miner']);
  }
  if (info.blocks < 110) await mine(110 - info.blocks);
  return info;
}

class NativeNodeProcess {
  constructor(root, name) {
    this.directory = path.join(root, name);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    this.seed = randomBytes(64).toString('hex');
    this.seq = 0;
    this.spawn();
  }
  spawn() {
    const log = fs.openSync(path.join(this.directory, 'worker.log'), 'a', 0o600);
    this.exit = null;
    this.groupKilled = false;
    this.child = spawn(process.execPath, [path.join(here, 'native-worker.mjs'), this.directory], {
      detached: true,
      stdio: ['ignore', log, log],
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
    assert.equal(r.runtime.rln_commit, 'ecc69f20308231400561f6f060fea88acfa40cc4');
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

function summarizeLatencies(rows, target) {
  const ok = rows.filter(r => r.status === 'observed-success').map(r => r.elapsedMs).sort((a, b) => a - b);
  const failed = rows.filter(r => r.status !== 'observed-success').length;
  const unexecuted = target - rows.length;
  const q = p => (ok.length ? +ok[Math.min(ok.length - 1, Math.ceil(p * ok.length) - 1)].toFixed(2) : null);
  const mean = ok.length ? +(ok.reduce((a, b) => a + b, 0) / ok.length).toFixed(2) : null;
  return {
    targetAttempts: target,
    executedAttempts: rows.length,
    observedSuccess: ok.length,
    ambiguousOrFailed: failed,
    unexecuted,
    successRateOverTarget: +(ok.length / target).toFixed(4),
    failureOrUnexecutedRate: +((failed + unexecuted) / target).toFixed(4),
    p50Ms: q(0.5),
    p95Ms: q(0.95),
    p99Ms: q(0.99),
    meanMs: mean,
    minMs: ok.length ? +ok[0].toFixed(2) : null,
    maxMs: ok.length ? +ok[ok.length - 1].toFixed(2) : null,
  };
}

// --- Verify provenance & mainnet disablement ---
const addonPath = path.join(pkgRoot, 'node_modules/@utexo/rgb-lightning-node-nodejs/index-linux-x64-gnu.node');
const addonSha256 = createHash('sha256').update(fs.readFileSync(addonPath)).digest('hex');
const runtimeInfo = native.getRuntimeInfo();
assert.equal(runtimeInfo.rln_commit, 'ecc69f20308231400561f6f060fea88acfa40cc4');
assert.ok(runtimeInfo.capabilities.includes('mainnet-lightning-rejection-v1'));

let mainnetRefusal = null;
try {
  const mw = new wdk.WalletAccountRgbLightning(randomBytes(64).toString('hex'), '0/0', {
    network: 'mainnet', dataDir: path.join(workBase, 'bench-mainnet-check'),
    daemonListeningPort: 0, ldkPeerListeningPort: 29598,
  });
  await mw.unlock({ ldk_chain_sync: { mode: 'TransactionSync', config: { indexer_url: endpoints.esplora } } });
} catch (e) {
  mainnetRefusal = { blocked: true, errorName: e.name, message: e.message };
}
assert.ok(mainnetRefusal?.blocked, 'mainnet must remain disabled');

await prepareChain();
const workRoot = fs.mkdtempSync(path.join(workBase, 'shz-rgb01f-bench-'));
fs.chmodSync(workRoot, 0o700);

const report = {
  schema: 'SHZ-RGB-01F/BENCHMARK/V1',
  timestamp: new Date().toISOString(),
  environment: {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    indexerUrl: endpoints.indexer,
    strictExternalSigner: true,
    permissiveSignerPolicy: false,
    fixtureScope: 'NIA/IFA regtest via published @utexo/rgb-lightning-node-nodejs@0.2.0-beta.5 SdkNode issuer (upstream source-built RLN HTTP daemon blocked by private BFA ORG_READ_TOKEN)',
  },
  provenance: {
    wdkPackage: '@utexo/wdk-rgb-lightning@0.2.0-beta.5',
    wdkGitHead: '608937d849412a4c25e9b9a66a7571b561396ae0',
    nativePackage: '@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5',
    nativeGitHead: '8b78387df4c33140a52c19c6de6fcc8d4aa7595c',
    rlnCommit: runtimeInfo.rln_commit,
    lightningCommit: runtimeInfo.lightning_commit,
    adapterSha256: runtimeInfo.adapter_sha256,
    linuxX64AddonSha256: addonSha256,
  },
  mainnetRefusal,
  setup: {},
  smoke: {},
  rails: {},
  recovery: {},
};

const nodes = [];
const tSetup = performance.now();
try {
  const issuer = new NativeNodeProcess(workRoot, 'issuer'); nodes.push(issuer);
  const alice = new NativeNodeProcess(workRoot, 'alice'); nodes.push(alice);
  const bob = new NativeNodeProcess(workRoot, 'bob'); nodes.push(bob);

  await issuer.start(29601, 'BlockSync');
  await alice.start(29602, 'TransactionSync');
  await bob.start(29603, 'BlockSync');

  const fundingFees = {};
  for (const w of [issuer, alice, bob]) {
    const ftx = await rpc('sendtoaddress', [w.address, 2], 'miner');
    await mine(6);
    await w.call('sync');
    const utxoCount = w === alice ? 15 : 10;
    await w.call('createUtxos', [{ up_to: false, num: utxoCount, size: 500000, fee_rate: 2, skip_sync: false }]);
    await mine(6);
    await w.call('sync');
    fundingFees[w.directory.split('/').pop()] = await txFeeSats(ftx);
  }

  // Issue NIA + verify IFA issuance
  const nia = await issuer.call('issueAssetNia', [{ ticker: 'SHZUSD', name: 'SHZ Disposable NIA Fixture', precision: 0, amounts: [1000000] }]);
  const ifa = await issuer.call('issueAssetIfa', [{ ticker: 'SHZIFA', name: 'SHZ Disposable IFA Fixture', precision: 6, amounts: [100000000], inflation_amounts: [], reject_list_url: null }]);
  const assetId = nia.asset.asset_id;

  // Fund Alice with 200,000 NIA units
  const invFund = await alice.call('rgbInvoice', [{ min_confirmations: 1, witness: false }]);
  const sendFund = await issuer.call('sendRgb', [{
    donation: true, fee_rate: 2, min_confirmations: 1, skip_sync: false,
    recipient_map: { [assetId]: [{ recipient_id: invFund.recipient_id, assignment: { type: 'Fungible', value: 200000 }, transport_endpoints: [endpoints.proxy] }] },
  }]);
  await mine(6);
  await until('alice NIA funded', async () => {
    await alice.call('refreshTransfers', [{ skip_sync: false }]);
    await issuer.call('refreshTransfers', [{ skip_sync: false }]);
    return (await alice.call('assetBalance', [assetId])).settled === 200000;
  });

  // Open standard BTC channel (1,000,000 sat)
  const btcOpen = await alice.call('openChannel', [{
    peer_pubkey_and_opt_addr: `${bob.pubkey}@127.0.0.1:29603`,
    capacity_sat: 1000000, push_msat: 0, public: false, with_anchors: true,
  }]);
  await until('btc chan mempool', async () => (await rpc('getrawmempool')).length > 0);
  const btcOpenTxid = (await rpc('getrawmempool'))[0];
  await mine(12);
  await until('btc chan usable', async () => {
    await alice.call('sync'); await bob.call('sync');
    return (await alice.call('listChannels')).channels.some(c => c.asset_id === null && c.is_usable) &&
           (await bob.call('listChannels')).channels.some(c => c.asset_id === null && c.is_usable);
  });
  const btcOpenFeeSats = await txFeeSats(btcOpenTxid);

  // Open standard RGB channel (1,000,000 sat BTC capacity + 50,000 NIA units)
  await alice.call('openChannel', [{
    peer_pubkey_and_opt_addr: `${bob.pubkey}@127.0.0.1:29603`,
    capacity_sat: 1000000, push_msat: 0, public: false, with_anchors: true,
    asset_id: assetId, asset_amount: 50000, push_asset_amount: 0,
  }]);
  await until('rgb chan mempool', async () => (await rpc('getrawmempool')).length > 0);
  const rgbOpenTxid = (await rpc('getrawmempool'))[0];
  await mine(12);
  await until('rgb chan usable', async () => {
    await alice.call('sync'); await bob.call('sync');
    return (await alice.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable) &&
           (await bob.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
  });
  const rgbOpenFeeSats = await txFeeSats(rgbOpenTxid);

  report.setup = {
    status: 'passed',
    setupOverheadMs: +(performance.now() - tSetup).toFixed(2),
    niaAssetId: assetId,
    ifaAssetId: ifa.asset.asset_id,
    btcChannelOpenTxid: btcOpenTxid,
    btcChannelOpenFeeSats: btcOpenFeeSats,
    rgbChannelOpenTxid: rgbOpenTxid,
    rgbChannelOpenFeeSats: rgbOpenFeeSats,
    aliceInitialRgbSettled: (await alice.call('assetBalance', [assetId])).settled,
    btcOpenTempId: btcOpen?.temporary_channel_id ?? null,
  };

  // --- Helper: run LN payment (BTC or RGB) ---
  const mkWdkLikeCall = (proc) => async (method, ...args) => {
    if (method === 'getNetwork') return 'regtest';
    if (method === 'getCapabilities') return { lightning: true };
    if (method === 'getAddressState') return { status: 'ready' };
    if (method === 'getNetworkInfo') return proc.call('networkInfo');
    if (method === 'getNodeInfo') return proc.call('nodeInfo');
    if (method === 'decodeInvoice') return proc.call('decodeLnInvoice', args);
    if (method === 'getPayment') return proc.call('getPayment', args);
    if (method === 'getInvoiceStatus') return proc.call('invoiceStatus', args);
    throw new Error(`unmapped method ${method}`);
  };

  async function runLnAttempt(idx, isRgb, units = 25, carrierMsat = 3000000) {
    const t0 = performance.now();
    const inv = await bob.call('lnInvoice', [{ amt_msat: carrierMsat, expiry_sec: 600, ...(isRgb ? { asset_id: assetId, asset_amount: units } : {}) }]);
    const d = await alice.call('decodeLnInvoice', [inv.invoice]);
    assert.equal(String(d.network).toLowerCase(), 'regtest');
    assert.equal(String(d.amt_msat), String(carrierMsat));
    assert.equal(d.payee_pubkey, bob.pubkey);
    if (isRgb) {
      const now = Math.floor(Date.now() / 1000);
      checkDecoded({ network: 'regtest', assetId, assetUnits: String(units), carrierMsat: String(carrierMsat), payee: bob.pubkey, obligationId: `rgb-ln:${idx}`, expiresAt: now + 600 }, d, now);
    } else {
      assert.equal(d.asset_id, null);
    }
    await alice.call('sendPayment', [{ invoice: inv.invoice }]);
    await until(`${isRgb ? 'rgb-ln' : 'btc-ln'} settled #${idx}`, async () => {
      const o = await alice.call('getPayment', [d.payment_hash, 'Outbound']);
      const p = await bob.call('getPayment', [d.payment_hash, 'InboundAutoClaim']);
      return o.status === 'Succeeded' && p.status === 'Succeeded';
    });
    assert.equal((await bob.call('invoiceStatus', [inv.invoice])).status, 'Succeeded');
    let nativeObs = null;
    if (isRgb && idx === 0) {
      nativeObs = await qualifyNativePair({
        payerCall: mkWdkLikeCall(alice),
        receiverCall: mkWdkLikeCall(bob),
        payerNode: alice.pubkey, payee: bob.pubkey, invoice: inv.invoice,
        paymentHash: d.payment_hash, assetId, assetUnits: String(units), carrierMsat: String(carrierMsat),
      });
    }
    return { status: 'observed-success', elapsedMs: performance.now() - t0, paymentHash: d.payment_hash, nativeObs };
  }

  async function runChainAttempt(idx, units = 25) {
    const t0 = performance.now();
    const bobBefore = BigInt((await bob.call('assetBalance', [assetId]).catch(() => ({ settled: 0 }))).settled ?? 0);
    const inv = await bob.call('rgbInvoice', [{ min_confirmations: 6, witness: false, assignment: { type: 'Fungible', value: units }, duration_seconds: 600 }]);
    const d = await alice.call('decodeRgbInvoice', [inv.invoice]);
    assert.equal(d.assignment.type, 'Fungible');
    assert.equal(String(d.assignment.value), String(units));
    const tx = await alice.call('sendRgb', [{
      donation: false, fee_rate: 2, min_confirmations: 6, skip_sync: false,
      recipient_map: { [assetId]: [{ recipient_id: inv.recipient_id, assignment: { type: 'Fungible', value: units }, transport_endpoints: d.transport_endpoints }] },
    }]);
    const refresh = async () => {
      for (const w of [bob, alice]) {
        const x = await w.call('refreshTransfers', [{ skip_sync: false }]);
        for (const c of Object.values(x.transfers || {})) assert.equal(c.failure, null);
      }
    };
    await until(`rgb-chain mempool #${idx}`, async () => { await refresh(); return (await rpc('getrawmempool')).includes(tx.txid); });
    const broadcastMs = performance.now() - t0;
    const tMine = performance.now();
    await mine(6);
    const miningMs = performance.now() - tMine;
    await until(`rgb-chain settled #${idx}`, async () => {
      await refresh();
      const at = (await alice.call('listTransfers', [assetId])).transfers.some(x => x.txid === tx.txid && x.status === 'Settled');
      const bt = (await bob.call('listTransfers', [assetId])).transfers.some(x => x.txid === tx.txid && x.status === 'Settled');
      return at && bt;
    });
    const feeSats = await txFeeSats(tx.txid);
    const bobAfter = BigInt((await bob.call('assetBalance', [assetId])).settled);
    assert.equal(bobAfter - bobBefore, BigInt(units));
    return { status: 'observed-success', elapsedMs: performance.now() - t0, broadcastMs, miningMs, txid: tx.txid, minerFeeSats: feeSats };
  }

  // --- PHASE 1: 1 successful payment per rail BEFORE scaling ---
  console.log('Running 1-payment smoke per rail...');
  report.smoke.btcLn = await runLnAttempt(0, false, 0, 3000000);
  report.smoke.rgbLn = await runLnAttempt(0, true, 25, 3000000);
  report.smoke.rgbChain = await runChainAttempt(0, 25);
  console.log('SMOKE PASSED:', JSON.stringify({ btcLnMs: +report.smoke.btcLn.elapsedMs.toFixed(1), rgbLnMs: +report.smoke.rgbLn.elapsedMs.toFixed(1), rgbChainMs: +report.smoke.rgbChain.elapsedMs.toFixed(1) }));

  // --- PHASE 2: Scale BTC-LN to targetAttempts ---
  console.log(`Benchmarking btc-ln (${targetAttempts} attempts)...`);
  const btcChBefore = (await alice.call('listChannels')).channels.find(c => c.asset_id === null);
  const btcRows = [];
  for (let i = 0; i < targetAttempts; i++) {
    try {
      btcRows.push(await runLnAttempt(i + 1, false, 0, 3000000));
    } catch (e) {
      btcRows.push({ status: 'ambiguous-or-failed', error: e.message, elapsedMs: null });
      break;
    }
  }
  const btcChAfter = (await alice.call('listChannels')).channels.find(c => c.asset_id === null);
  report.rails.btcLn = {
    summary: summarizeLatencies(btcRows, targetAttempts),
    carrierMsatPerAttempt: 3000000,
    channelOpenMinerFeeSats: btcOpenFeeSats,
    routingFeeMsatDirectChannel: 0,
    channelLocalBalanceBeforeMsat: btcChBefore.outbound_balance_msat,
    channelLocalBalanceAfterMsat: btcChAfter.outbound_balance_msat,
    channelLocalDeltaMsat: btcChBefore.outbound_balance_msat - btcChAfter.outbound_balance_msat,
    expectedTransferredMsat: btcRows.filter(r => r.status === 'observed-success').length * 3000000,
  };

  // --- PHASE 3: Scale RGB-LN to targetAttempts ---
  console.log(`Benchmarking rgb-ln (${targetAttempts} attempts)...`);
  const rgbChBeforeA = (await alice.call('listChannels')).channels.find(c => c.asset_id === assetId);
  const rgbChBeforeB = (await bob.call('listChannels')).channels.find(c => c.asset_id === assetId);
  const rgbRows = [];
  for (let i = 0; i < targetAttempts; i++) {
    try {
      rgbRows.push(await runLnAttempt(i + 1, true, 25, 3000000));
    } catch (e) {
      rgbRows.push({ status: 'ambiguous-or-failed', error: e.message, elapsedMs: null });
      break;
    }
  }
  const rgbChAfterA = (await alice.call('listChannels')).channels.find(c => c.asset_id === assetId);
  const rgbChAfterB = (await bob.call('listChannels')).channels.find(c => c.asset_id === assetId);
  const rgbOkCount = rgbRows.filter(r => r.status === 'observed-success').length;
  report.rails.rgbLn = {
    summary: summarizeLatencies(rgbRows, targetAttempts),
    assetUnitsPerAttempt: 25,
    carrierMsatPerAttempt: 3000000,
    channelOpenMinerFeeSats: rgbOpenFeeSats,
    routingFeeMsatDirectChannel: 0,
    carrierBtcDeltaMsat: rgbChBeforeA.outbound_balance_msat - rgbChAfterA.outbound_balance_msat,
    payerRgbLocalBefore: rgbChBeforeA.asset_local_amount,
    payerRgbLocalAfter: rgbChAfterA.asset_local_amount,
    payerRgbDelta: rgbChBeforeA.asset_local_amount - rgbChAfterA.asset_local_amount,
    receiverRgbLocalBefore: rgbChBeforeB.asset_local_amount,
    receiverRgbLocalAfter: rgbChAfterB.asset_local_amount,
    receiverRgbDelta: rgbChAfterB.asset_local_amount - rgbChBeforeB.asset_local_amount,
    expectedRgbUnitsTransferred: rgbOkCount * 25,
    exactRgbConservation: (rgbChBeforeA.asset_local_amount - rgbChAfterA.asset_local_amount) === rgbOkCount * 25 &&
                          (rgbChAfterB.asset_local_amount - rgbChBeforeB.asset_local_amount) === rgbOkCount * 25,
  };

  // --- PHASE 4: Scale RGB on-chain to chainAttempts ---
  console.log(`Benchmarking rgb-chain (${chainAttempts} attempts)...`);
  const aliceOnChainBefore = (await alice.call('assetBalance', [assetId])).settled;
  const bobOnChainBefore = (await bob.call('assetBalance', [assetId])).settled;
  const chainRows = [];
  for (let i = 0; i < chainAttempts; i++) {
    try {
      chainRows.push(await runChainAttempt(i + 1, 25));
    } catch (e) {
      chainRows.push({ status: 'ambiguous-or-failed', error: e.message, elapsedMs: null });
      break;
    }
  }
  const aliceOnChainAfter = (await alice.call('assetBalance', [assetId])).settled;
  const bobOnChainAfter = (await bob.call('assetBalance', [assetId])).settled;
  const chainOk = chainRows.filter(r => r.status === 'observed-success');
  const fees = chainOk.map(r => r.minerFeeSats).sort((a, b) => a - b);
  report.rails.rgbChain = {
    summary: summarizeLatencies(chainRows, chainAttempts),
    assetUnitsPerAttempt: 25,
    confirmationsRequired: 6,
    totalMinerFeesSats: fees.reduce((a, b) => a + b, 0),
    medianMinerFeeSats: fees.length ? fees[Math.floor(fees.length / 2)] : null,
    minMinerFeeSats: fees.length ? fees[0] : null,
    maxMinerFeeSats: fees.length ? fees[fees.length - 1] : null,
    payerOnChainSettledBefore: aliceOnChainBefore,
    payerOnChainSettledAfter: aliceOnChainAfter,
    receiverOnChainSettledBefore: bobOnChainBefore,
    receiverOnChainSettledAfter: bobOnChainAfter,
    receiverRgbDelta: bobOnChainAfter - bobOnChainBefore,
    expectedRgbUnitsTransferred: chainOk.length * 25,
    exactRgbConservation: (bobOnChainAfter - bobOnChainBefore) === chainOk.length * 25 &&
                          (aliceOnChainBefore - aliceOnChainAfter) === chainOk.length * 25,
  };

  // --- PHASE 5: Measure cold restart / recovery latency ---
  const tRec = performance.now();
  const restarted = await alice.crashRestart();
  assert.equal(restarted.node.pubkey, alice.pubkey);
  await until('channels usable post-restart', async () => {
    await alice.call('sync'); await bob.call('sync');
    const cs = (await alice.call('listChannels')).channels;
    return cs.filter(c => c.is_usable).length >= 2;
  });
  report.recovery = {
    coldCrashRestartAndUsableChannelsMs: +(performance.now() - tRec).toFixed(2),
    pubkeyPreserved: restarted.node.pubkey === alice.pubkey,
    usableChannelsAfterRestart: (await alice.call('listChannels')).channels.filter(c => c.is_usable).length,
  };
} finally {
  for (const n of nodes.reverse()) await n.stop();
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
  console.log('WROTE BENCHMARK RECEIPT:', outPath);
}
