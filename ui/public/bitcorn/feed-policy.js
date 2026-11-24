// Vendored & adapted from patrickdugan/BitcornWisdom (MIT License, Copyright (c) 2026 Patrick Dugan).
// Feed eligibility policy. Instrument identity is a deliberate allowlist:
// a BTC/USD spot print must never silently turn into BTC/USDT or a perpetual.
import { KRAKEN_INTERVALS } from './kraken.js';
import { COINBASE_INTERVALS } from './coinbase.js';

export const INSTRUMENTS = Object.freeze({
  'BTC-USD-SPOT': Object.freeze({
    label: 'BTC / USD', base: 'BTC', quote: 'USD', product: 'spot',
    intervals: ['1m', '5m', '15m', '1h', '4h', '1d'],
    venues: [
      { market: 'kraken', symbol: 'BTCUSD' },
      { market: 'coinbase', symbol: 'BTCUSD' }
    ]
  }),
  'ETH-USD-SPOT': Object.freeze({
    label: 'ETH / USD', base: 'ETH', quote: 'USD', product: 'spot',
    intervals: ['1m', '5m', '15m', '1h', '4h', '1d'],
    venues: [
      { market: 'kraken', symbol: 'ETHUSD' },
      { market: 'coinbase', symbol: 'ETHUSD' }
    ]
  }),
  'BTC-USDT-SPOT': Object.freeze({
    label: 'BTC / USDT', base: 'BTC', quote: 'USDT', product: 'spot',
    intervals: ['1m', '3m', '5m', '15m', '30m', '1h', '4h', '1d'],
    venues: [{ market: 'spot', symbol: 'BTCUSDT' }]
  }),
  'ETH-USDT-SPOT': Object.freeze({
    label: 'ETH / USDT', base: 'ETH', quote: 'USDT', product: 'spot',
    intervals: ['1m', '3m', '5m', '15m', '30m', '1h', '4h', '1d'],
    venues: [{ market: 'spot', symbol: 'ETHUSDT' }]
  }),
  'BTC-USDT-PERP': Object.freeze({
    label: 'BTC / USDT · perpetual', base: 'BTC', quote: 'USDT', product: 'perpetual',
    intervals: ['1m', '3m', '5m', '15m', '30m', '1h', '4h', '1d'],
    venues: [{ market: 'futures', symbol: 'BTCUSDT' }]
  })
});

export const MAX_RELAYS = 2;
export const EMBED_THEMES = Object.freeze(['shz', 'darkDesk', 'noir', 'synth', 'verdigris']);

function venueSupportsInterval(market, interval) {
  if (market === 'kraken') return Object.hasOwn(KRAKEN_INTERVALS, interval);
  if (market === 'coinbase') return Object.hasOwn(COINBASE_INTERVALS, interval);
  return true;
}

export function resolveInstrument(value = 'BTC-USD-SPOT') {
  if (typeof value !== 'string' || !Object.hasOwn(INSTRUMENTS, value))
    throw new RangeError('Unknown instrument; use an explicit venue-compatible instrument ID');
  return INSTRUMENTS[value];
}

export function safeRelayBase(value, { allowLocal = false } = {}) {
  if (typeof value !== 'string' || value.length > 256) throw new TypeError('Invalid relay URL');
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError('Invalid relay URL'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (!(url.protocol === 'https:' || (allowLocal && local && url.protocol === 'http:')))
    throw new RangeError('Relay requires HTTPS (or same-machine HTTP development)');
  if (url.username || url.password || url.search || url.hash || url.pathname.includes('..'))
    throw new RangeError('Relay URL must be a clean base path without credentials or query');
  return url.href.replace(/\/$/, '');
}

export function feedPlan({ instrument = 'BTC-USD-SPOT', interval = '1m',
  preferred = null, relays = [], allowLocal = false } = {}) {
  const definition = resolveInstrument(instrument);
  if (!definition.intervals.includes(interval)) throw new RangeError('Interval unsupported by the chosen instrument');
  if (!Array.isArray(relays) || relays.length > MAX_RELAYS)
    throw new RangeError('Up to two opt-in relays are supported');
  const venues = definition.venues
    .filter(({ market }) => venueSupportsInterval(market, interval))
    .map(({ market, symbol }) => ({
      id: market + ':' + symbol,
      kind: 'exchange', market, symbol, instrument, interval,
      label: market === 'spot' ? 'BINANCE SPOT' : market === 'futures' ?
        'BINANCE PERPETUAL' : market.toUpperCase()
    }));
  const seen = new Set();
  const normalizedRelays = relays.map((value, index) => {
    const baseUrl = safeRelayBase(value, { allowLocal });
    if (seen.has(baseUrl)) throw new RangeError('Duplicate relay URL');
    seen.add(baseUrl);
    return {
      id: 'relay:' + (index + 1), kind: 'relay', baseUrl,
      market: 'relay', symbol: instrument, instrument, interval, label: 'RELAY ' + (index + 1)
    };
  });
  const sources = [...venues, ...normalizedRelays];
  if (preferred !== null && preferred !== undefined && preferred !== '') {
    const priority = sources.findIndex(source =>
      source.market === preferred || source.id === preferred);
    if (priority === -1)
      throw new RangeError('Preferred venue or relay is incompatible with the instrument');
    sources.unshift(...sources.splice(priority, 1));
  }
  return sources;
}

export function normalizeCandle(row) {
  if (!row || typeof row !== 'object' || !Number.isSafeInteger(row.time) || row.time < 0)
    throw new TypeError('Invalid feed candle timestamp');
  const { open, high, low, close, volume } = row;
  if (![open, high, low, close, volume].every(Number.isFinite) ||
      low <= 0 || low > high || open < low || open > high ||
      close < low || close > high || volume < 0)
    throw new TypeError('Invalid feed candle OHLCV');
  return { time: row.time, open, high, low, close, volume };
}

export function normalizeHistory(rows, maxRows = 1200) {
  if (!Array.isArray(rows) || rows.length > maxRows || rows.length === 0)
    throw new TypeError('Feed history must contain a bounded nonempty candle array');
  const byTime = new Map();
  for (const row of rows) {
    const candle = normalizeCandle(row);
    byTime.set(candle.time, candle);
  }
  return [...byTime.values()].sort((a, b) => a.time - b.time);
}

export function normalizeEmbedConfig(input) {
  const query = input instanceof URLSearchParams ? input : new URLSearchParams(input || '');
  const instrument = query.get('instrument') || 'BTC-USD-SPOT';
  const interval = query.get('interval') || '15m';
  const preferred = query.get('preferred') || null;
  const theme = query.get('theme') || 'shz';
  if (!EMBED_THEMES.includes(theme)) throw new RangeError('Unsupported embed theme');
  const demo = query.get('demo') === '1';
  const relays = query.getAll('relay');
  const parentOrigin = query.get('parentOrigin');
  if (parentOrigin) {
    let origin;
    try { origin = new URL(parentOrigin); }
    catch { throw new TypeError('Invalid parent origin'); }
    if (!['http:', 'https:'].includes(origin.protocol) ||
        origin.origin !== parentOrigin || origin.username || origin.password)
      throw new TypeError('parentOrigin must be an exact HTTP(S) origin');
  }
  return {
    instrument, interval, preferred, relays, theme, demo,
    parentOrigin: parentOrigin || null
  };
}

export function feedProvenance(source, { state = 'connecting', reason = 'initial',
  receivedAt = null } = {}) {
  return {
    sourceId: source.id, instrument: source.instrument,
    venue: source.market, symbol: source.symbol, kind: source.kind,
    state, reason, receivedAt
  };
}
