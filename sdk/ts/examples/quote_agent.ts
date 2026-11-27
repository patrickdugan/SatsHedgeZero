// Minimal agent strategy: one small spot bid and ask around the mark (or the perpetual with
// --perp), re-quoted when the mark moves, inside the grant's collar and per-order notional;
// the agent's own batch acknowledgements are auto-signed. Stops on revocation or expiry.
//
//   node examples/quote_agent.ts --venue http://127.0.0.1:8095 --agent-key agent.key --grant <id> [--seconds 60] [--perp]
//
// Testnet only (USDT is a labelled demo asset). Reads only the agent key.
import { readFileSync } from 'node:fs';
import { Agent, Client, LightningerError, Stream, unhex } from '../src/index.ts';

const arg = (k: string, d?: string) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const venue = arg('venue', 'http://127.0.0.1:8095')!;
const agent = await Agent.open(new Client(venue), unhex(readFileSync(arg('agent-key')!, 'utf8').trim(), 32), arg('grant')!);
const perp = process.argv.includes('--perp') || !agent.template.spot_pair;
const log = (o: object) => console.log(JSON.stringify({ t: Date.now() / 1000, ...o }));
const stopAcks = agent.startAutosigner();
const stream = await Stream.open(venue);
let marks = 0;
await stream.subscribe(['mark'], (_c, kind) => { if (kind === 'event') marks++; });

function plan(mark: number) {
  const half = Math.min(20, Math.floor(agent.limits.collar_bps / 2)) / 10_000;
  const usd = Math.max(1, Math.min(Math.floor(agent.limits.max_order_notional_usd / 4), 25));
  return { bid: Math.round(mark * (1 - half)), ask: Math.round(mark * (1 + half)), usd };
}
let quotes: string[] = [], quotedAt = 0;
const end = Date.now() + Number(arg('seconds', '60')) * 1000;
try {
  while (Date.now() < end) {
    const m: number | null = (await agent.c.mark()).mark_usd;
    if (m && (!quotedAt || Math.abs(m - quotedAt) / quotedAt * 10_000 >= 10)) {
      for (const q of quotes) await (perp ? agent.perpCancel(q) : agent.spotCancel(q)).catch((e) => log({ ev: 'cancel_refused', code: e.code }));
      const { bid, ask, usd } = plan(m);
      if (perp) {
        quotes = [(await agent.perpPost('long', usd, bid)).id, (await agent.perpPost('short', usd, ask)).id];
      } else {
        // 1,000-sat lots; price in demo-USDT base units (6 decimals) on the 0.1 tick.
        const sats = Math.max(1_000, Math.floor((usd / m) * 1e8 / 1_000) * 1_000);
        const px = (p: number) => Math.round(p * 10) * 100_000;
        quotes = [(await agent.spotPost(true, sats, px(bid))).id, (await agent.spotPost(false, sats, px(ask))).id];
      }
      quotedAt = m;
      log({ ev: 'quoted', instrument: perp ? 'perp' : 'spot', mark: m, bid, ask });
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
} catch (e) {
  if (!(e instanceof LightningerError) || !['grant.revoked', 'grant.expired', 'grant.unknown'].includes(e.code)) throw e;
  log({ ev: 'stopped', reason: e.code });
} finally {
  for (const q of quotes) await (perp ? agent.perpCancel(q) : agent.spotCancel(q)).catch(() => {}); // leave nothing resting
  await new Promise((r) => setTimeout(r, 500));
  stopAcks();
  stream.close();
}
log({ ev: 'done', marks, usage: (await agent.status()).usage });
