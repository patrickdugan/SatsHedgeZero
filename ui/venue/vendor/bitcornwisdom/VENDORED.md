# Vendored BitcornWisdom embed

Source: https://github.com/patrickdugan/BitcornWisdom, commit ce978fa (`Add relay-only instruments and SHZ-BTCUSD-INV`) on main, rebased onto b93bc8a.
Copied unmodified: `embed.html`, `embed.css`, `favicon.svg`, `LICENSE`, and the `src/` modules the embed imports transitively (embed, chart, core, indicators, workspace, market-motion, orderbook, drawings, demo, feed-policy, feed-router, feed-adapters, binance, realtime, kraken, coinbase).
Update by re-copying those files from a newer BitcornWisdom commit and editing the commit above.

Local additions (not in upstream): a `classic` embed theme (flat black, hollow green and solid red candles and volume) in `src/workspace.js`, `src/feed-policy.js` and `embed.css`; a hollow-volume branch in `src/chart.js`; and, for that theme only, a poll of the relay's `/api/book` that feeds the chart's L2 depth rail (`syncDepth` in `src/embed.js`); the relay-only `SHZ-BTCUSDT-SPOT` instrument in `src/feed-policy.js`, whose classic depth rail polls `/api/spot/book` instead. Re-apply these after re-copying from upstream.
