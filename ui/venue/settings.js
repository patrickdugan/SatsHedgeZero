// Interface style setting: 'modern' (Lightninger) or 'classic' (BitcoinWisdom Classic). Stored per browser.
const KEY = 'lightninger.ui';
export const UI_MODES = [
  ['modern', 'Lightninger', 'Black and gold chrome with the BitcornWisdom red and green'],
  ['classic', 'BitcoinWisdom Classic', 'Flat black, monospace, hollow green and solid red candles, L2 depth rail'],
];
export function getUiMode() { try { return localStorage.getItem(KEY) === 'classic' ? 'classic' : 'modern'; } catch { return 'modern'; } }
export function applyUiMode(mode = getUiMode()) {
  if (mode === 'classic') document.documentElement.dataset.ui = 'classic'; else delete document.documentElement.dataset.ui;
}
export function setUiMode(mode) { try { localStorage.setItem(KEY, mode); } catch { /* storage blocked */ } applyUiMode(mode); }
export const chartTheme = () => (getUiMode() === 'classic' ? 'classic' : 'og-wisdom');
export function chartSrc(market, origin) {
  return `vendor/bitcornwisdom/embed.html?instrument=${market}&theme=${chartTheme()}&interval=1m&preferred=relay:1&relay=${encodeURIComponent(origin)}`;
}
export function renderSettings(el, onChange) {
  const cur = getUiMode();
  el.innerHTML = `<div class="mnote">Interface style</div>` + UI_MODES.map(([id, name, note]) =>
    `<button type="button" class="wopt" data-mode="${id}" aria-pressed="${id === cur}"><b>${id === cur ? '&#10003; ' : ''}${name}</b><span>${note}</span></button>`).join('');
  for (const b of el.querySelectorAll('[data-mode]')) b.onclick = () => { setUiMode(b.dataset.mode); renderSettings(el, onChange); onChange(b.dataset.mode); };
}
