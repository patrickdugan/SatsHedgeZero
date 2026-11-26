import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hex, unhex, pubkey, bip340Sign, bip340Verify } from '../crypto.js';
import { linkHash, linkEventTemplate, nostrEventId, connectNostr, lnurlStart, lnurlFinish, weblnInfo, nostrAvailable, NOSTR_KIND } from '../wallet.js';
import { qrMatrix, encodeData, interleave, rsRemainder, alignPositions, formatBits, maskFns, rawModules, dataCodewords } from '../qr.js';

const VECTOR = fileURLToPath(new URL('./nostr_vector.json', import.meta.url));
const NETWORK = '07'.repeat(32);
const WALLET_SK = unhex('00'.repeat(31) + '03'); // BIP340 vector key, pubkey f9308a01...
const TRADE_SK = unhex('00'.repeat(31) + '05');
const CHALLENGE = '0c'.repeat(32);
const EXPIRES = 1_900_086_400_000_000;
const CREATED = 1_900_000_000;

// A NIP-07 stub: signs with a known key like an extension would (BIP340 over the NIP-01 event id).
function stubNostr(sk) {
  const pk = hex(pubkey(sk));
  return {
    async getPublicKey() { return pk; },
    async signEvent(t) {
      const ev = { ...t, pubkey: pk };
      ev.id = await nostrEventId(ev);
      ev.sig = hex(await bip340Sign(unhex(ev.id, 32), sk));
      return ev;
    },
  };
}

test('shared vector with the Rust verifier (crates/shz-venue/src/wallet.rs)', async () => {
  const nostr = stubNostr(WALLET_SK), pk = await nostr.getPublicKey();
  const trade = hex(pubkey(TRADE_SK));
  const hash = hex(await linkHash(NETWORK, 'nostr', unhex(pk, 32), unhex(trade, 32), unhex(CHALLENGE, 32), EXPIRES));
  const ev = await nostr.signEvent(linkEventTemplate({ venue: NETWORK, hash, challenge: CHALLENGE }, trade, CREATED));
  const vec = { venue: NETWORK, req: 'wallet-link', pubkey: pk, hash, link: { network: NETWORK, trade_key: trade, challenge: CHALLENGE, expires_us: EXPIRES }, event: ev };
  if (process.env.UPDATE_VECTORS) writeFileSync(VECTOR, JSON.stringify(vec, null, 2) + '\n');
  assert.deepEqual(JSON.parse(readFileSync(VECTOR, 'utf8')), vec);
  assert.equal(ev.kind, NOSTR_KIND);
  assert.ok(await bip340Verify(unhex(ev.id, 32), unhex(pk, 32), unhex(ev.sig, 64)));
});

test('connectNostr runs challenge, signEvent, link against a venue mock', async () => {
  const nostr = stubNostr(WALLET_SK), trade = hex(pubkey(TRADE_SK));
  const calls = [];
  const api = async (path, body) => {
    calls.push(path);
    if (path.endsWith('/challenge')) {
      assert.equal(body.wallet, hex(pubkey(WALLET_SK))); assert.equal(body.trade_key, trade);
      const hash = hex(await linkHash(NETWORK, 'nostr', unhex(body.wallet, 32), unhex(trade, 32), unhex(CHALLENGE, 32), EXPIRES));
      return { challenge: CHALLENGE, hash, venue: NETWORK, req: 'wallet-link', link_expires_us: EXPIRES };
    }
    // venue side: the event commits to the hash and the trading key signed the same hash
    const tag = (n) => body.event.tags.find((t) => t[0] === n)[1];
    assert.equal(tag('shz-req'), 'wallet-link'); assert.equal(tag('shz-venue'), NETWORK);
    assert.ok(await bip340Verify(unhex(tag('shz-hash'), 32), pubkey(TRADE_SK), unhex(body.session_signature, 64)));
    assert.equal(body.event.id, await nostrEventId(body.event));
    return { trade_key: trade, link: { kind: 'nostr', wallet: body.event.pubkey, expires_us: EXPIRES } };
  };
  const r = await connectNostr({ api, nostr, tradeSecret: TRADE_SK, nowS: () => CREATED });
  assert.deepEqual(calls, ['/api/wallet/nostr/challenge', '/api/wallet/nostr/link']);
  assert.equal(r.wallet, hex(pubkey(WALLET_SK))); assert.equal(r.expires_us, EXPIRES);
});

test('connectNostr rejects a wallet that signs with another key or a wrong id', async () => {
  const api = async () => ({ challenge: CHALLENGE, hash: '11'.repeat(32), venue: NETWORK });
  const liar = { ...stubNostr(WALLET_SK), async signEvent(t) { return stubNostr(TRADE_SK).signEvent(t); } };
  await assert.rejects(connectNostr({ api, nostr: liar, tradeSecret: TRADE_SK }), /different key/);
  const bad = { ...stubNostr(WALLET_SK), async signEvent(t) { const e = await stubNostr(WALLET_SK).signEvent(t); e.content += 'x'; return e; } };
  await assert.rejects(connectNostr({ api, nostr: bad, tradeSecret: TRADE_SK }), /wrong id/);
});

test('LNURL flow: start, poll pending then authed, trading key signs the link hash', async () => {
  const trade = hex(pubkey(TRADE_SK)), k1 = 'ab'.repeat(32);
  const wallet33 = '02' + '11'.repeat(32);
  const hash = hex(await linkHash(NETWORK, 'lnurl', unhex(wallet33, 33), unhex(trade, 32), unhex(k1, 32), EXPIRES));
  let polls = 0, confirmed = null;
  const api = async (path, body) => {
    if (path === '/api/wallet/lnurl/start') { assert.equal(body.trade_key, trade); return { k1, lnurl: 'LNURL1X', callback: 'https://v/x', expires_us: 1 }; }
    if (path.startsWith('/api/wallet/lnurl/status')) return ++polls < 3 ? { status: 'pending' } : { status: 'authed', wallet: wallet33, hash, link_expires_us: EXPIRES };
    confirmed = body; return { trade_key: trade, link: { kind: 'lnurl', wallet: wallet33, expires_us: EXPIRES } };
  };
  const s = await lnurlStart({ api, tradeSecret: TRADE_SK, origin: 'https://v' });
  const states = [];
  const r = await lnurlFinish({ api, tradeSecret: TRADE_SK, k1: s.k1, onState: (x) => states.push(x), sleep: async () => {} });
  assert.deepEqual(states, ['pending', 'pending', 'authed']);
  assert.ok(await bip340Verify(unhex(hash, 32), pubkey(TRADE_SK), unhex(confirmed.session_signature, 64)));
  assert.equal(r.wallet, wallet33); assert.equal(confirmed.k1, k1);
});

test('LNURL expiry surfaces as an error', async () => {
  const api = async () => ({ status: 'expired' });
  await assert.rejects(lnurlFinish({ api, tradeSecret: TRADE_SK, k1: 'ab'.repeat(32), sleep: async () => {} }), /expired/);
});

test('LNURL: an unsigned k1 stays pending on the venue, so the browser stops at its own expiry', async () => {
  let t = 1_000, polls = 0;
  const api = async () => { polls++; return { status: 'pending' }; };
  await assert.rejects(lnurlFinish({ api, tradeSecret: TRADE_SK, k1: 'ab'.repeat(32), expiresUs: 5_000, nowUs: () => t, sleep: async () => { t += 1_500; } }), /expired/);
  assert.equal(polls, 3);
});

test('WebLN: identity only, never pays', async () => {
  assert.equal(await weblnInfo({}), null);
  const calls = [];
  const webln = { enable: async () => calls.push('enable'), getInfo: async () => ({ node: { alias: 'test-node', pubkey: '02' + 'ab'.repeat(32) }, methods: ['getInfo', 'sendPayment'] }),
    sendPayment: async () => calls.push('sendPayment'), makeInvoice: async () => calls.push('makeInvoice') };
  const i = await weblnInfo({ webln });
  assert.equal(i.alias, 'test-node'); assert.deepEqual(calls, ['enable']);
  assert.equal((await weblnInfo({ webln: { enable: async () => { throw new Error('denied'); } } })).error, 'denied');
  assert.equal(nostrAvailable({ nostr: stubNostr(WALLET_SK) }), true);
  assert.equal(nostrAvailable({}), false);
});

// ---------------------------------------------------------------- QR ----
test('QR: ISO 18004 worked example HELLO WORLD, version 1-M codewords', () => {
  const data = encodeData('HELLO WORLD', 1, 'M');
  assert.deepEqual(data, [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]);
  assert.deepEqual(rsRemainder(data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
});

test('QR: alignment positions, format bits and capacities match the standard', () => {
  assert.deepEqual(alignPositions(2), [6, 18]);
  assert.deepEqual(alignPositions(7), [6, 22, 38]);
  assert.deepEqual(alignPositions(14), [6, 26, 46, 66]);
  assert.deepEqual(alignPositions(32), [6, 34, 60, 86, 112, 138]);
  assert.equal(formatBits('M', 5), 0b100000011001110);
  assert.equal(formatBits('L', 4), 0b110011000101111);
  assert.equal(Math.floor(rawModules(1) / 8), 26); assert.equal(rawModules(40), 29648);
  assert.equal(dataCodewords(1, 'M'), 16); assert.equal(dataCodewords(1, 'L'), 19); assert.equal(dataCodewords(40, 'L'), 2956);
});

// Independent read-back: check both format-info copies, undo the mask, walk the zigzag and return the codewords.
function readBack(q) {
  const { size, modules: m, version: ver, ecc } = q;
  const fmt = formatBits(ecc, q.mask);
  const bitAt = (x, y) => (m[y][x] ? 1 : 0);
  let f1 = 0; for (let i = 0; i <= 5; i++) f1 |= bitAt(8, i) << i; f1 |= bitAt(8, 7) << 6; f1 |= bitAt(8, 8) << 7; f1 |= bitAt(7, 8) << 8; for (let i = 9; i < 15; i++) f1 |= bitAt(14 - i, 8) << i;
  assert.equal(f1, fmt, 'format info copy 1');
  let f2 = 0; for (let i = 0; i < 8; i++) f2 |= bitAt(size - 1 - i, 8) << i; for (let i = 8; i < 15; i++) f2 |= bitAt(8, size - 15 + i) << i;
  assert.equal(f2, fmt, 'format info copy 2');
  const al = alignPositions(ver);
  const isFn = (x, y) => {
    if ((x < 9 && y < 9) || (x >= size - 8 && y < 9) || (x < 9 && y >= size - 8) || x === 6 || y === 6) return true;
    if (ver >= 7 && ((x >= size - 11 && x < size - 8 && y < 6) || (y >= size - 11 && y < size - 8 && x < 6))) return true;
    for (let i = 0; i < al.length; i++) for (let j = 0; j < al.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === al.length - 1) || (i === al.length - 1 && j === 0)) continue;
      if (Math.abs(x - al[i]) <= 2 && Math.abs(y - al[j]) <= 2) return true;
    }
    return false;
  };
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let v = 0; v < size; v++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - v : v;
      if (isFn(x, y)) continue;
      bits.push(bitAt(x, y) ^ (maskFns[q.mask](x, y) ? 1 : 0));
    }
  }
  const raw = Math.floor(rawModules(ver) / 8);
  const cw = []; for (let i = 0; i < raw; i++) { let b = 0; for (let k = 0; k < 8; k++) b = (b << 1) | bits[i * 8 + k]; cw.push(b); }
  return cw;
}

test('QR: matrices read back to the expected codewords (alphanumeric, byte, multi-block, v7+, any mask)', () => {
  const texts = ['HELLO WORLD', 'LNURL1' + 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'.repeat(7), 'https://example.com/a?b=c&d=é', 'X'.repeat(300), 'abc'.repeat(120)];
  for (const text of texts) for (const ecc of ['L', 'M']) {
    const q = qrMatrix(text, ecc);
    const expect = interleave(encodeData(text, q.version, ecc), q.version, ecc);
    assert.deepEqual(readBack(q), expect, `codewords ${text.slice(0, 12)} v${q.version}${ecc}`);
    assert.equal(q.size, q.version * 4 + 17);
    assert.deepEqual(readBack(qrMatrix(text, ecc, (q.mask + 3) % 8)), expect);
  }
  assert.throws(() => qrMatrix('x'.repeat(3000), 'M'), /too long/);
});
