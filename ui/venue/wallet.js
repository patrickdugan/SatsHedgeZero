// Wallet connect for the SHZ venue page: Nostr (NIP-07), LNURL-auth (LUD-04), WebLN identity.
// Wallets never sign venue approvals directly (the router needs raw BIP340 signatures over
// venue-chosen 32-byte messages, which NIP-07 and LNURL-auth cannot produce). A wallet
// authorizes a browser trading key once, with an expiry; the trading key keeps signing.
// Everything is injected (api, nostr, clock) so it runs under node with a stub wallet.
import { hex, unhex, concat, sha256, taggedHash, bip340Sign, pubkey } from './crypto.js';

export const NOSTR_KIND = 27810;
const utf8 = (s) => new TextEncoder().encode(s);
const le64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };

/** Same preimage as `link_hash` in crates/shz-venue/src/wallet.rs. */
export async function linkHash(network, kind, wallet, tradeKey, nonce, expiresUs) {
  const k = utf8(kind);
  return taggedHash('SHZ/VENUE/WALLET-LINK/V1', concat(unhex(network, 32), Uint8Array.of(k.length), k, Uint8Array.of(wallet.length), wallet, tradeKey, nonce, le64(expiresUs)));
}

/** NIP-01 event id for an unsigned event. */
export async function nostrEventId(ev) {
  return hex(await sha256(utf8(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
}

/** The unsigned event a wallet is asked to sign for a wallet-link challenge. */
export function linkEventTemplate(c, tradeKeyHex, nowS) {
  return {
    kind: NOSTR_KIND, created_at: nowS,
    tags: [['shz-venue', c.venue], ['shz-req', 'wallet-link'], ['shz-hash', c.hash], ['shz-challenge', c.challenge]],
    content: `SatsHedgeZero venue (testnet): authorize trading key ${tradeKeyHex}`,
  };
}

export const nostrAvailable = (win = globalThis) => !!(win && win.nostr && typeof win.nostr.signEvent === 'function' && typeof win.nostr.getPublicKey === 'function');

/**
 * Connect through a NIP-07 signer. `tradeSecret` is the browser trading key (Uint8Array).
 * Resolves `{kind:'nostr', wallet, expires_us, trade_key}`.
 */
export async function connectNostr({ api, nostr, tradeSecret, nowS = () => Math.floor(Date.now() / 1000) }) {
  const wallet = String(await nostr.getPublicKey()).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(wallet)) throw new Error('wallet returned an unusable public key');
  const tradeKey = hex(pubkey(tradeSecret));
  const c = await api('/api/wallet/nostr/challenge', { wallet, trade_key: tradeKey });
  const ev = await nostr.signEvent(linkEventTemplate(c, tradeKey, nowS()));
  if (ev.pubkey !== wallet) throw new Error('wallet signed with a different key than it reported');
  if (ev.id !== (await nostrEventId(ev))) throw new Error('wallet returned an event with a wrong id');
  const session_signature = hex(await bip340Sign(unhex(c.hash, 32), tradeSecret));
  const r = await api('/api/wallet/nostr/link', { event: ev, session_signature });
  return { kind: 'nostr', wallet, trade_key: tradeKey, expires_us: r.link.expires_us };
}

/** Ask the venue for a k1 bound to the trading key; show `lnurl` as a QR code. */
export function lnurlStart({ api, tradeSecret, origin }) {
  return api('/api/wallet/lnurl/start', { trade_key: hex(pubkey(tradeSecret)), origin });
}

/**
 * Poll until the wallet has authenticated k1, then sign the link hash with the trading key.
 * `onState` receives 'pending' | 'authed'. Rejects when the k1 expires or `signal` aborts.
 */
export async function lnurlFinish({ api, tradeSecret, k1, expiresUs, nowUs = () => Date.now() * 1000, onState = () => {}, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), signal, intervalMs = 1500 }) {
  for (;;) {
    if (signal && signal.aborted) throw new Error('cancelled');
    // The venue keeps no state for an unsigned k1, so it cannot report its expiry: track it here.
    if (expiresUs !== undefined && nowUs() >= expiresUs) throw new Error('QR code expired; try again');
    const s = await api('/api/wallet/lnurl/status?k1=' + k1);
    if (s.status === 'expired') throw new Error('QR code expired; try again');
    onState(s.status);
    if (s.status === 'authed') {
      const session_signature = hex(await bip340Sign(unhex(s.hash, 32), tradeSecret));
      const r = await api('/api/wallet/lnurl/confirm', { k1, session_signature });
      return { kind: 'lnurl', wallet: s.wallet, trade_key: r.trade_key, expires_us: r.link.expires_us };
    }
    if (s.status === 'linked') throw new Error('this QR code was already used');
    await sleep(intervalMs);
  }
}

/**
 * WebLN is identity display only. The venue has no Lightning backend (the channel adapter is
 * simulated), so sendPayment and makeInvoice are never called.
 */
export async function weblnInfo(win = globalThis) {
  const w = win && win.webln;
  if (!w) return null;
  try {
    if (typeof w.enable === 'function') await w.enable();
    const info = typeof w.getInfo === 'function' ? await w.getInfo() : null;
    const node = info && info.node ? info.node : {};
    return { available: true, alias: node.alias || null, pubkey: node.pubkey || null, methods: info && info.methods ? info.methods : [] };
  } catch (e) {
    return { available: true, alias: null, pubkey: null, error: String(e && e.message ? e.message : e) };
  }
}
