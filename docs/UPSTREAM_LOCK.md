# Upstream research snapshot for SHZ-MNR-01

Pinned on 2026-11-23. These branches contain unmerged research. Their existence is not a claim that SatsHedgeZero executes their contract or proof paths.

| Track | Pull request | Pinned commit | Needed integration |
| --- | --- | --- | --- |
| Exact-amount max-flow, reserve checks and V2 funded batch guard | [UTXORef #13](https://github.com/patrickdugan/UTXO-Ref/pull/13) | [`82105e2`](https://github.com/patrickdugan/UTXO-Ref/commit/82105e25208903167aac3ffaaaedb9d28a8b06de) | Differential-test solver and feed independently authenticated signed ledger and guarded spend bytes |
| Two-party Taproot inverse-DLC CET/refund and watchtower | [UTXORef #14](https://github.com/patrickdugan/UTXO-Ref/pull/14) | [`f3ed53f`](https://github.com/patrickdugan/UTXO-Ref/commit/f3ed53ffe233af2de5376a482f12a84cdc95fa2e) | Fund independent wallet contracts and retain every unilateral exit before multi-party clearing |
| Native DLC authorization and Nova transcript proof | [zk-rusto-no-bitcoino #28](https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/28) | [`f6a8d12`](https://github.com/patrickdugan/zk-rusto-no-bitcoino/commit/f6a8d129285869f339c86f1e2e7f1124bc09c37a) | Compose accepted-book membership, BIP340 signer authorization, selected CET table and exact settlement bytes |

Prior UTXORef #13 Core regtest funding used one test wallet controlling both inputs; it did not establish a multi-party production custody path. UTXORef #14's funded rehearsal exercised distinct local key processes under one operator, with production signer and independent recovery still pending. Nova #28 currently has separate arithmetic and signature circuits; it does not verify their combined DLC statement.

The initial SHZ source is an independent pure JavaScript reference for *synthetic* position-offset and netting tests. After the two upstream projects settle their schemas, add version-pinned adapters and compare their native accounting/transaction results against our local witnesses on fixed adversarial fixtures.
