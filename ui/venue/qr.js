// Minimal QR Code encoder (ISO/IEC 18004): byte and alphanumeric modes, versions 1-40,
// error correction L and M, automatic mask choice. Zero dependencies; ES module.
// Written for this repo (no third-party code). Exports pure helpers so tests can check
// codewords against the ISO worked example.

const ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const ECC_PER_BLOCK = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
};
const NUM_BLOCKS = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
};
const FORMAT_BITS = { L: 1, M: 0 };

export function rawModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const a = Math.floor(ver / 7) + 2;
    r -= (25 * a - 10) * a - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}
export const dataCodewords = (ver, ecc) => Math.floor(rawModules(ver) / 8) - ECC_PER_BLOCK[ecc][ver] * NUM_BLOCKS[ecc][ver];

export function alignPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2, size = ver * 4 + 17;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
  const out = [6];
  for (let p = size - 7; out.length < n; p -= step) out.splice(1, 0, p);
  return out;
}

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
{ let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; } for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]; }
const gmul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
export function rsGenerator(deg) {
  let g = [1];
  for (let i = 0; i < deg; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) { next[j] ^= g[j]; next[j + 1] ^= gmul(g[j], EXP[i]); }
    g = next;
  }
  return g; // highest degree first, monic
}
export function rsRemainder(data, deg) {
  const g = rsGenerator(deg), rem = new Array(deg).fill(0);
  for (const b of data) {
    const f = b ^ rem.shift(); rem.push(0);
    if (f) for (let i = 0; i < deg; i++) rem[i] ^= gmul(g[i + 1], f);
  }
  return rem;
}

// ---- data encoding ----
function bitsOf(text) {
  const bytes = new TextEncoder().encode(text);
  const alnum = [...text].every((c) => ALNUM.includes(c));
  return { bytes, alnum, count: alnum ? text.length : bytes.length };
}
export function encodeData(text, ver, ecc) {
  const { bytes, alnum, count } = bitsOf(text);
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  put(alnum ? 2 : 4, 4);
  put(count, alnum ? (ver < 10 ? 9 : ver < 27 ? 11 : 13) : (ver < 10 ? 8 : 16));
  if (alnum) {
    for (let i = 0; i < text.length; i += 2) {
      if (i + 1 < text.length) put(ALNUM.indexOf(text[i]) * 45 + ALNUM.indexOf(text[i + 1]), 11);
      else put(ALNUM.indexOf(text[i]), 6);
    }
  } else for (const b of bytes) put(b, 8);
  const cap = dataCodewords(ver, ecc) * 8;
  if (bits.length > cap) return null;
  put(0, Math.min(4, cap - bits.length));
  while (bits.length % 8) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let pad = 0xec; out.length < cap / 8; pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}
export function interleave(data, ver, ecc) {
  const nb = NUM_BLOCKS[ecc][ver], deg = ECC_PER_BLOCK[ecc][ver], raw = Math.floor(rawModules(ver) / 8);
  const shortBlocks = nb - (raw % nb), shortLen = Math.floor(raw / nb);
  const blocks = []; let k = 0;
  for (let i = 0; i < nb; i++) {
    const len = shortLen - deg + (i < shortBlocks ? 0 : 1);
    const d = data.slice(k, k + len); k += len;
    blocks.push({ d, e: rsRemainder(d, deg) });
  }
  const out = [];
  for (let i = 0; i < shortLen - deg + 1; i++) for (let j = 0; j < nb; j++) if (i < blocks[j].d.length) out.push(blocks[j].d[i]);
  for (let i = 0; i < deg; i++) for (let j = 0; j < nb; j++) out.push(blocks[j].e[i]);
  return out;
}

// ---- matrix ----
const MASKS = [
  (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x, y) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];
export const maskFns = MASKS;

export function formatBits(ecc, mask) {
  const data = (FORMAT_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}
function versionBits(ver) {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

function build(ver, ecc, codewords, mask) {
  const size = ver * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, v) => { m[y][x] = v; fn[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy; if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy)); set(x, y, d !== 2 && d !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const al = alignPositions(ver);
  for (let i = 0; i < al.length; i++) for (let j = 0; j < al.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === al.length - 1) || (i === al.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  const drawFormat = (mk) => {
    const bits = formatBits(ecc, mk), b = (i) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, b(i));
    set(8, 7, b(6)); set(8, 8, b(7)); set(7, 8, b(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, b(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, b(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, b(i));
    set(8, size - 8, true);
  };
  drawFormat(0);
  if (ver >= 7) {
    const bits = versionBits(ver);
    for (let i = 0; i < 18; i++) { const c = ((bits >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3); set(a, b, c); set(b, a, c); }
  }
  // codewords, zigzag
  let bit = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let v = 0; v < size; v++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - v : v;
      if (!fn[y][x] && bit < codewords.length * 8) { m[y][x] = ((codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1) === 1; bit++; }
    }
  }
  const apply = (mk) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[mk](x, y)) m[y][x] = !m[y][x]; };
  let best = -1, bestPen = Infinity;
  if (mask === undefined) {
    for (let mk = 0; mk < 8; mk++) { apply(mk); drawFormat(mk); const p = penalty(m); if (p < bestPen) { bestPen = p; best = mk; } apply(mk); }
    mask = best;
  }
  apply(mask); drawFormat(mask);
  return { size, modules: m, mask, version: ver, ecc };
}

function penalty(m) {
  const n = m.length; let pen = 0;
  const runs = (get) => {
    for (let a = 0; a < n; a++) {
      let run = 1; const hist = [];
      for (let b = 1; b <= n; b++) {
        if (b < n && get(a, b) === get(a, b - 1)) run++;
        else { if (run >= 5) pen += 3 + run - 5; hist.push(run); run = 1; }
      }
      // finder-like 1:1:3:1:1 with 4 light on a side
      const s = []; for (let b = 0; b < n; b++) s.push(get(a, b) ? 1 : 0);
      const str = s.join('');
      for (const pat of ['00001011101', '10111010000']) { let i = -1; while ((i = str.indexOf(pat, i + 1)) >= 0) pen += 40; }
    }
  };
  runs((a, b) => m[a][b]); runs((a, b) => m[b][a]);
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) { const c = m[y][x]; if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) pen += 3; }
  let dark = 0; for (const r of m) for (const c of r) if (c) dark++;
  pen += Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
  return pen;
}

/** Encode `text` (uppercase alphanumeric text uses the denser mode). Returns {size, modules, version, mask, ecc}. */
export function qrMatrix(text, ecc = 'L', mask) {
  for (let ver = 1; ver <= 40; ver++) {
    const data = encodeData(text, ver, ecc);
    if (data) return build(ver, ecc, interleave(data, ver, ecc), mask);
  }
  throw new Error('text too long for a QR code');
}

/** SVG string with a 4-module quiet zone; colours inherit so it works in light and dark themes. */
export function qrSvg(text, { ecc = 'L', fg = '#000', bg = '#fff', px = 4 } = {}) {
  const { size, modules } = qrMatrix(text, ecc), q = 4, dim = size + q * 2;
  let d = '';
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (modules[y][x]) d += `M${x + q} ${y + q}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim * px}" height="${dim * px}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${dim}" height="${dim}" fill="${bg}"/><path d="${d}" fill="${fg}"/></svg>`;
}
