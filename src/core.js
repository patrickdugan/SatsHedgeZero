'use strict';

const { createHash } = require('node:crypto');
const MAX_INTEGER = (1n << 64n) - 1n;
const MAX_PRICE_USD = 1_000_000_000_000n;
const SATS_PER_BTC = 100_000_000n;
const MAX_SATS = 21_000_000n * SATS_PER_BTC;

function integer(value, name, { zero = true, max = MAX_INTEGER } = {}) {
  let n;
  if (typeof value === 'bigint') n = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) n = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) n = BigInt(value);
  else throw new TypeError(`${name} must be a canonical nonnegative integer`);
  if (n < 0n || (!zero && n === 0n) || n > max) {
    throw new RangeError(`${name} is outside its permitted range`);
  }
  return n;
}

function identifier(value, name) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new TypeError(`${name} must be a 1–128 character ASCII identifier`);
  }
  return value;
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  throw new TypeError('commitment data must be plain JSON with safe integer numbers');
}

function commitment(domain, value) {
  identifier(domain, 'hash domain');
  return createHash('sha256').update(domain + '\0' + canonical(value), 'utf8').digest('hex');
}

function compareIds(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

function signedString(value) {
  return value.toString();
}

module.exports = { integer, identifier, canonical, commitment, signedString, MAX_INTEGER, MAX_PRICE_USD, MAX_SATS, SATS_PER_BTC, compareIds };
