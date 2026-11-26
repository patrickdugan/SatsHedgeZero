// Client-side partial liquidation. The venue never signs for an account: below maintenance it
// only accepts orders that reduce the position, and publishes a plan (`position.risk.liquidation`)
// from shz_margin's Dutch auction: the tranche to close and the worst acceptable price, which
// moves away from the mark as the breach lasts. This module turns that plan and the current book
// into reduce-only fill-or-kill takes for the account's own key to sign.

/** Book levels are `[price_usd, qty_usd, orders]`; a take fills against one resting quote, so
 *  size each take to the average quote at that level. */
export function planTakes(risk, book, maxTakes = 8) {
  const plan = risk && risk.reduce_only && risk.liquidation;
  if (!plan || !book) return [];
  const sell = plan.reduce_side === 'short';
  const levels = (sell ? book.bids : book.asks) || [];
  const ok = (p) => (sell ? p >= plan.limit_usd : p <= plan.limit_usd);
  let left = Math.min(plan.tranche_usd, risk.notional_usd || plan.tranche_usd);
  const takes = [];
  for (const [price, qty, n] of levels) {
    if (left <= 0 || takes.length >= maxTakes || !ok(price)) break;
    const quote = Math.floor(qty / Math.max(1, n || 1));
    let room = Math.min(qty, Math.max(quote, 1) * Math.max(1, n || 1));
    while (left > 0 && room > 0 && takes.length < maxTakes) {
      const q = Math.min(left, Math.max(quote, 1), room);
      takes.push({ side: plan.reduce_side, quantity: q, limit_usd: price });
      left -= q; room -= q;
    }
  }
  return takes;
}

/** Human summary for the banner. */
export function describe(risk) {
  if (!risk || !risk.state) return null;
  const pct = (bps) => (bps == null ? '?' : (bps / 100).toFixed(2) + '%');
  const p = risk.params || {};
  switch (risk.state) {
    case 'warning': return { level: 'warn', text: `Margin ${pct(risk.margin_bps)} is close to maintenance ${pct(p.maintenance_bps)}. Liquidation price ${risk.liquidation_price_usd ?? '-'} USD.` };
    case 'maintenance': return { level: 'danger', text: `Below maintenance (${pct(risk.margin_bps)} < ${pct(p.maintenance_bps)}). The venue accepts only position-reducing orders. Partial liquidation: close ${risk.liquidation?.tranche_usd ?? '?'} USD at ${risk.liquidation?.limit_usd ?? '?'} or better (auction discount ${risk.liquidation?.auction_discount_bps ?? 0} bps).` };
    case 'bankrupt': return { level: 'danger', text: `A lot is past its bankruptcy price: it pays this account nothing (the DLC caps the loss at its margin). Only position-reducing orders are accepted.` };
    default: return null;
  }
}
