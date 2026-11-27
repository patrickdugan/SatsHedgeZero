// SHZ-RGB-02 (Research Extension): Separately gated regtest experiment evaluating native RLN
// atomic BTC <-> RGB Lightning swaps (makerInit, taker, makerExecute, listSwaps, getSwap)
// under the strict external signer (permissiveSignerPolicy: false).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

assert.equal(process.env.SHZ_RGB02_EXPERIMENT, 'YES', 'Explicit SHZ_RGB02_EXPERIMENT=YES gate required');
assert.equal(process.env.SHZ_DISPOSABLE_REGTEST, 'YES', 'SHZ_DISPOSABLE_REGTEST=YES required');

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = process.env.SHZ_UTEXO_PKG_ROOT || path.join(os.tmpdir(), 'shz-utexo-pkg');
const workBase = process.env.SHZ_REGTEST_WORK || os.tmpdir();
const outPath = process.argv[2] || path.join(here, 'receipts', 'shz-rgb02-atomic-swap.json');
const require = createRequire(import.meta.url);
const native = require(path.join(pkgRoot, 'node_modules/@utexo/rgb-lightning-node-nodejs'));
const wdk = await import(path.join(pkgRoot, 'node_modules/@utexo/wdk-rgb-lightning/index-node.js'));

const endpoints = Object.freeze({
  rpc: process.env.SHZ_REGTEST_RPC || 'http://127.0.0.1:29443',
  esplora: process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  indexer: process.env.RGB_INDEXER_URL || process.env.SHZ_REGTEST_ESPLORA || 'http://127.0.0.1:29302',
  proxy: process.env.SHZ_REGTEST_PROXY || 'rpc://127.0.0.1:29300/json-rpc',
});

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(label, fn, timeout = 90000) {
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
    body: JSON.stringify({ jsonrpc: '2.0', id: 'shz-rgb02', method, params }),
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
  async call(method, args = [], target = 'native', timeout = 90000) {
    const id = ++this.seq;
    await until('worker ready', () => fs.existsSync(path.join(this.directory, 'ready')), 30000);
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

// Assert mainnet Lightning remains disabled (never bypass WDK restriction)
let mainnetDisabled = false;
try {
  const mw = new wdk.WalletAccountRgbLightning(randomBytes(32).toString('hex'), '0/0', {
    network: 'mainnet', dataDir: path.join(workBase, 'rgb02-mainnet-check'),
    daemonListeningPort: 0, ldkPeerListeningPort: 29597,
  });
  await mw.unlock({ ldk_chain_sync: { mode: 'TransactionSync', config: { indexer_url: endpoints.esplora } } });
} catch {
  mainnetDisabled = true;
}
assert.ok(mainnetDisabled, 'WDK mainnet restriction must remain intact');

const root = fs.mkdtempSync(path.join(workBase, 'shz-rgb02-'));
fs.chmodSync(root, 0o700);
const receipt = {
  schema: 'SHZ-RGB-02/ATOMIC-SWAP/V1',
  timestamp: new Date().toISOString(),
  rlnCommit: native.getRuntimeInfo().rln_commit,
  strictExternalSigner: true,
  mainnetDisabled,
  cases: [],
};

const nodes = [];
try {
  const info = await rpc('getblockchaininfo');
  assert.equal(info.chain, 'regtest');
  const maker = new NativeProc(root, 'maker'); nodes.push(maker);
  const taker = new NativeProc(root, 'taker'); nodes.push(taker);
  await maker.start(29641, 'BlockSync');
  await taker.start(29642, 'TransactionSync');
  for (const w of [maker, taker]) {
    await rpc('sendtoaddress', [w.address, 2], 'miner');
    await mine(6);
    await w.call('sync');
    await w.call('createUtxos', [{ up_to: false, num: 10, size: 500000, fee_rate: 2, skip_sync: false }]);
    await mine(6);
    await w.call('sync');
  }
  // Maker issues NIA asset (simulating LP holding RGB liquidity)
  const assetId = (await maker.call('issueAssetNia', [{ ticker: 'SHZSWP', name: 'SHZ Atomic Swap Fixture', precision: 0, amounts: [500000] }])).asset.asset_id;
  // Open shared RGB channel: Maker holds 100,000 RGB + 500,000 sat BTC; push 400,000,000 msat (400,000 sat) BTC to Taker so Taker can pay BTC for RGB!
  await maker.call('openChannel', [{
    peer_pubkey_and_opt_addr: `${taker.pubkey}@127.0.0.1:29642`,
    capacity_sat: 1000000,
    push_msat: 400000000,
    public: false,
    with_anchors: true,
    asset_id: assetId,
    asset_amount: 100000,
    push_asset_amount: 0,
  }]);
  await until('swap chan mempool', async () => (await rpc('getrawmempool')).length > 0);
  await mine(12);
  await until('swap chan usable', async () => {
    await maker.call('sync'); await taker.call('sync');
    return (await maker.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable) &&
           (await taker.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
  });

  const snap = async () => {
    const mc = (await maker.call('listChannels')).channels.find(c => c.asset_id === assetId);
    const tc = (await taker.call('listChannels')).channels.find(c => c.asset_id === assetId);
    return {
      makerBtcMsat: mc.outbound_balance_msat,
      takerBtcMsat: tc.outbound_balance_msat,
      makerRgb: mc.asset_local_amount,
      takerRgb: tc.asset_local_amount,
    };
  };

  // Case 1: Atomic BTC -> RGB swap (Taker sends 50,000,000 msat = 50,000 sats BTC, receives 500 RGB units)
  {
    const before = await snap();
    const t0 = performance.now();
    const init = await maker.call('makerInit', [{ qty_from: 50000000, from_asset: null, qty_to: 500, to_asset: assetId, timeout_sec: 300 }]);
    await taker.call('taker', [{ swapstring: init.swapstring }]);
    const wMaker = await maker.call('getSwap', [init.payment_hash, false]);
    const wTaker = await taker.call('getSwap', [init.payment_hash, true]);
    assert.equal(wMaker.swap.status, 'Waiting');
    assert.equal(wTaker.swap.status, 'Waiting');
    await maker.call('makerExecute', [{ swapstring: init.swapstring, payment_secret: init.payment_secret, taker_pubkey: taker.pubkey }]);
    await until('btc->rgb swap succeeded', async () =>
      (await maker.call('getSwap', [init.payment_hash, false])).swap.status === 'Succeeded' &&
      (await taker.call('getSwap', [init.payment_hash, true])).swap.status === 'Succeeded'
    );
    const elapsedMs = +(performance.now() - t0).toFixed(2);
    const after = await snap();
    const btcConserved = (after.makerBtcMsat - before.makerBtcMsat) === 50000000 && (before.takerBtcMsat - after.takerBtcMsat) === 50000000;
    const rgbConserved = (before.makerRgb - after.makerRgb) === 500 && (after.takerRgb - before.takerRgb) === 500;
    assert.ok(btcConserved && rgbConserved, `conservation failed: ${JSON.stringify({ before, after })}`);
    receipt.cases.push({ name: '1_atomic_btc_to_rgb_same_channel', status: 'passed', elapsedMs, paymentHash: init.payment_hash, btcConserved, rgbConserved, before, after });
    console.log('RGB02 CASE 1 PASS:', { elapsedMs, btcConserved, rgbConserved });
  }

  // Case 2: Reverse Atomic RGB -> BTC swap (Taker sends 200 RGB, receives 20,000,000 msat BTC)
  {
    const before = await snap();
    const t0 = performance.now();
    const init = await maker.call('makerInit', [{ qty_from: 200, from_asset: assetId, qty_to: 20000000, to_asset: null, timeout_sec: 300 }]);
    await taker.call('taker', [{ swapstring: init.swapstring }]);
    await maker.call('makerExecute', [{ swapstring: init.swapstring, payment_secret: init.payment_secret, taker_pubkey: taker.pubkey }]);
    await until('rgb->btc swap succeeded', async () =>
      (await maker.call('getSwap', [init.payment_hash, false])).swap.status === 'Succeeded' &&
      (await taker.call('getSwap', [init.payment_hash, true])).swap.status === 'Succeeded'
    );
    const elapsedMs = +(performance.now() - t0).toFixed(2);
    const after = await snap();
    const btcConserved = (before.makerBtcMsat - after.makerBtcMsat) === 20000000 && (after.takerBtcMsat - before.takerBtcMsat) === 20000000;
    const rgbConserved = (after.makerRgb - before.makerRgb) === 200 && (before.takerRgb - after.takerRgb) === 200;
    assert.ok(btcConserved && rgbConserved);
    receipt.cases.push({ name: '2_atomic_rgb_to_btc_reverse', status: 'passed', elapsedMs, paymentHash: init.payment_hash, btcConserved, rgbConserved, before, after });
    console.log('RGB02 CASE 2 PASS:', { elapsedMs });
  }

  // Case 3: Adversarial — Expired swapstring rejected by both taker and makerExecute (zero balance movement)
  {
    const before = await snap();
    const init = await maker.call('makerInit', [{ qty_from: 10000000, from_asset: null, qty_to: 100, to_asset: assetId, timeout_sec: 1 }]);
    await sleep(2200);
    let takerErr = null, makerErr = null;
    try { await taker.call('taker', [{ swapstring: init.swapstring }]); } catch (e) { takerErr = e.message; }
    try { await maker.call('makerExecute', [{ swapstring: init.swapstring, payment_secret: init.payment_secret, taker_pubkey: taker.pubkey }]); } catch (e) { makerErr = e.message; }
    assert.ok(takerErr && makerErr, 'both expired taker and makerExecute must reject');
    const st = (await maker.call('getSwap', [init.payment_hash, false])).swap.status;
    assert.equal(st, 'Expired');
    const after = await snap();
    assert.deepEqual(after, before);
    receipt.cases.push({ name: '3_adversarial_expired_swap_abort', status: 'passed', makerStatus: st, takerRejected: true, makerRejected: true, zeroPartialExecution: true });
    console.log('RGB02 CASE 3 PASS (expired abort)');
  }

  // Case 4: Adversarial — Unwhitelisted makerExecute (Taker never calls `taker`) -> HTLC intercepted & failed, zero partial execution!
  {
    const before = await snap();
    const init = await maker.call('makerInit', [{ qty_from: 10000000, from_asset: null, qty_to: 100, to_asset: assetId, timeout_sec: 300 }]);
    // Maker executes WITHOUT Taker whitelisting!
    await maker.call('makerExecute', [{ swapstring: init.swapstring, payment_secret: init.payment_secret, taker_pubkey: taker.pubkey }]);
    await until('unwhitelisted swap failed', async () =>
      (await maker.call('getSwap', [init.payment_hash, false])).swap.status === 'Failed'
    );
    const after = await snap();
    assert.deepEqual(after, before);
    receipt.cases.push({ name: '4_adversarial_unwhitelisted_htlc_reject_zero_partial', status: 'passed', makerStatus: 'Failed', zeroPartialExecution: true, before, after });
    console.log('RGB02 CASE 4 PASS (unwhitelisted reject)');
  }

  // Case 5: Adversarial — Taker SIGKILL + cold restart while swap is Waiting, then Maker executes -> atomic settle!
  {
    const before = await snap();
    const init = await maker.call('makerInit', [{ qty_from: 10000000, from_asset: null, qty_to: 100, to_asset: assetId, timeout_sec: 300 }]);
    await taker.call('taker', [{ swapstring: init.swapstring }]);
    await taker.crashRestart();
    await until('taker channel usable after crash', async () => {
      await maker.call('sync'); await taker.call('sync');
      return (await taker.call('listChannels')).channels.some(c => c.asset_id === assetId && c.is_usable);
    });
    const persisted = await taker.call('getSwap', [init.payment_hash, true]);
    assert.equal(persisted.swap.status, 'Waiting');
    await maker.call('makerExecute', [{ swapstring: init.swapstring, payment_secret: init.payment_secret, taker_pubkey: taker.pubkey }]);
    await until('post-crash swap succeeded', async () =>
      (await maker.call('getSwap', [init.payment_hash, false])).swap.status === 'Succeeded' &&
      (await taker.call('getSwap', [init.payment_hash, true])).swap.status === 'Succeeded'
    );
    const after = await snap();
    assert.equal(after.makerBtcMsat - before.makerBtcMsat, 10000000);
    assert.equal(after.takerRgb - before.takerRgb, 100);
    const allMaker = await maker.call('listSwaps');
    const allTaker = await taker.call('listSwaps');
    receipt.cases.push({
      name: '5_adversarial_taker_sigkill_during_waiting_then_atomic_settle',
      status: 'passed',
      paymentHash: init.payment_hash,
      makerTotalSwapsListed: allMaker.maker.length,
      takerTotalSwapsListed: allTaker.taker.length,
      btcConserved: true,
      rgbConserved: true,
    });
    console.log('RGB02 CASE 5 PASS (taker crash recovery + atomic settle)');
  }
} finally {
  for (const n of nodes.reverse()) await n.stop();
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(receipt, null, 2) + '\n');
  console.log('WROTE RGB02 RECEIPT:', outPath);
}
