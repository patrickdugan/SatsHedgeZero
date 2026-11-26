# SHZ-RGB-01 | UTEXO settlement SDK evaluation

2026-11-26. Development only. This isolated package is an integration spike, not a wallet or a production adapter. Existing Rust workspace, DLC transactions, fee policy and UI are unchanged.

## Recommendation

Use the WDK RGB Lightning account as a separately operated Node sidecar for optional conversion and payout of already-realized BTC proceeds. Native USD/RGB collateral requires a separate protocol version and cryptographic design. Current beta.5 explicitly disables mainnet Lightning, so only disposable development networks are supported here.

- `@utexo/wdk-rgb-lightning@0.2.0-beta.5` and `@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5`: candidate pins from upstream README and npm version listing. External signer, LDK, rgb-lib and persistent node state. These are opt-in research dependencies; no install scripts run by the mock tests.
- `@utexo/rgb-sdk`: original Node repository archived July 28, 2026. Avoid for a new LN integration. `@utexo/wdk-wallet-rgb` remains a separate on-chain RGB path, with independent wallet identity/state.
- `@utexo/rgb-sdk-web`: browser RLN WASM beta, useful for user-operated wallet UI; not an HFT commitment monitor. React Native package is a separate mobile runtime.
- Xverse Sats Connect is a wallet-consent SDK; documented Spark, BTC and other asset APIs do not demonstrate RGB-USDT support. Xverse support (September 29, 2026) says USDT is unsupported. The April blog's conflation of RGB with Taproot Assets is inaccurate: they are distinct protocols.
- WDK's older public reference describes beta.15; use beta.5 source declarations for the prototype. Community-maintained module, independent of Tether's endorsement.

## Run

    node integrations/utexo-rgb/mock.test.mjs

Node 22+ recommended. No dependencies, secrets, sockets, chain access or payments are needed. The test function was executed in a JS isolate during review (31 passing assertions); Node CLI/native dependencies have not been run here. Run it with Node and record the output before expanding the spike.

Opt-in live research installation from this subfolder, after verifying npm tarball integrity/provenance and reviewing native installation scripts:

    npm install --save-exact @utexo/wdk-rgb-lightning@0.2.0-beta.5 @utexo/rgb-lightning-node-nodejs@0.2.0-beta.5

The manifest records the pins separately; installation is deliberately not required. Use a disposable Linux/regtest environment. Do not reuse SHZ custody, customer or production seed material. Instantiate WalletManagerRgbLightning with network=regtest, dedicated dataDir, strict signer policy and virtual channels disabled, unlock through the documented native request and obtain account 0. Pass this account to createDevelopmentAdapter(account, 'regtest'). The adapter checks the SDK's configured network and Lightning capability; the caller must independently verify the actual chain. Example API:

    const adapter = await createDevelopmentAdapter(account, 'regtest')
    const raw = await adapter.createReceiveInvoice(quote, nowSeconds)
    // Capture beta.5 response shape locally; extract the invoice via reviewed mapping.
    const candidate = await adapter.inspectInvoice(quote, invoice, nowSeconds)
    const observed = await adapter.observe(candidate, invoice)

The create result and observation are opaque; do not log secrets or raw responses. Invoice candidates bind contract ID, network, base units, carrier msat, recipient node key, payment hash, expiry and SHZ obligation ID. Unknown types, wrong amounts, expired quotes, unsafe JS integers and mainnet fail closed. The observer is deliberately incapable of authorizing credit or sending money; status is not durable commitment evidence.

## Sources (checked 2026-11-26)

- [Xverse article](https://www.xverse.app/blog/usdt-on-bitcoin-stablecoins-lightning)
- [Xverse support](https://support.xverse.app/hc/en-us/articles/48960869004045-What-s-the-difference-between-USDT-and-USDC-in-Xverse) and [Sats Connect](https://docs.xverse.app/sats-connect)
- [Archived Node SDK](https://github.com/UTEXO-Protocol/rgb-sdk)
- [WDK RGB Lightning](https://github.com/UTEXO-Protocol/wdk-rgb-lightning), [declarations](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/main/index.d.ts), [qualification register](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/main/PRODUCTION-GATES.md), [npm](https://www.npmjs.com/package/@utexo/wdk-rgb-lightning?activeTab=versions)
- [WDK beta.15 API reference](https://docs.wdk.tether.io/sdk/community-modules/wdk-rgb-lightning/api-reference/)
- [Web SDK](https://github.com/UTEXO-Protocol/rgb-sdk-web), [RN SDK](https://github.com/UTEXO-Protocol/rgb-sdk-rn)
- [UTEXO Mint](https://www.utexo.com/mint), [RGB ecosystem](https://rgb.info/build/developer-tools/)

See DESIGN.md for accounting and qualification gates.

Follow-up: [SHZ-RGB-01A benchmark and recovery](BENCHMARK.md).

Follow-up: [SHZ-RGB-01B signed settlement journal](JOURNAL.md).

Follow-up: [SHZ-RGB-01C evidence and checkpoint coordination](OBSERVERS.md).
