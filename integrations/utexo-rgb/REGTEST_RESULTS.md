# SHZ-RGB-01E/F & SHZ-RGB-02: Regtest Qualification Results, Provenance, and Failure Matrix

Date: 2026-11-26  
Branch: `research/shz-rgb-01-utexo-sdk` (reconciled with `origin/main` at `d63596e8b76bd2fa155db8654b452d7f53ef37b8`)  
Scope: **Research and qualification only — mainnet remains disabled; no production payment path enabled.**

---

## 1. Runtime Versions and Verified Upstream Artifact Identities

Verified live in WSL2 Linux (`Linux 6.18.58.1-microsoft-standard-WSL2 x86_64`, `rustc 1.99.1`, `cargo 1.99.1`, `clippy 0.1.99`, `Node.js v22.16.0`, `npm 10.9.2`, `Docker 29.1.3`, `Docker Compose 2.40.3`). Machine-readable receipt: [receipts/provenance-verified.json](./receipts/provenance-verified.json).

| Artifact | Pinned Identity | Verified Status |
| --- | --- | --- |
| `@utexo/wdk-rgb-lightning@0.2.0-beta.5` | `gitHead`: `608937d849412a4c25e9b9a66a7571b561396ae0`<br>`shasum`: `a781629dd83daa39a8d227b25a1f1c64ecdfdc0f`<br>`integrity`: `sha512-bfRfESWIipgMlSLIZ6XMijrDzAF/ceKp3ftLSz/4puekwacWhCKkzHjVxzTSqvLmH2AqQaPGfR0TQbFgTwKgNA==`<br>SLSA v1 attestation present | **Verified & loaded on Linux x64** |
| `@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5` | `gitHead`: `8b78387df4c33140a52c19c6de6fcc8d4aa7595c`<br>`shasum`: `60311cc7d1ed93b8cb1017f8f183327f0d0d0573`<br>`integrity`: `sha512-ZRUe27r0YtTfWABF5LT7LSutczu84q6XnIEQUzWll1aUhVjxjH6jFfVWOkf1nvf+Hf9Hz9nkgCEMEHS5ytFYbw==`<br>SLSA v1 attestation present | **Verified & loaded on Linux x64** |
| `index-linux-x64-gnu.node` (prebuilt addon) | SHA-256: `e35974417bf4658ebe87f35da8d8e14628f7a65e8054c43d225c2f6b77fbb45a` | **Verified via `getRuntimeInfo()`** |
| Embedded `rgb-lightning-node` | `rln_version`: `0.17.0-beta.3`<br>`rln_commit`: `ecc69f20308231400561f6f060fea88acfa40cc4`<br>`lightning_commit`: `79b9eb5166546c62692d3a672986f385c7fe047d`<br>`adapter_sha256`: `6d46717b80ffba8ed8af2de023a536af242aadcacbbb799fb9bb89f8933e4ca5` | **Verified live on Linux x64** (`mainnet-lightning-rejection-v1` active) |
| Upstream `wdk-rgb-lightning` clone | `608937d849412a4c25e9b9a66a7571b561396ae0` | **Checked out & inspected** |
| Upstream `rgb-lightning-node-nodejs` clone | `8b78387df4c33140a52c19c6de6fcc8d4aa7595c` | **Checked out & inspected** |
| Upstream `rgb-lightning-node` clone | `ecc69f20308231400561f6f060fea88acfa40cc4` | **Checked out & inspected** |

---

## 2. Executed Verification Results (Actual Runs vs. Unexecuted Native Fixtures)

We strictly distinguish **verified executions** from **fixture/model tests** and **unexecuted native runs**. No unexecuted latency, fee, balance, or chain receipt is fabricated.

### 2.1 Executed & Verified Tests (Linux WSL2, Rust 1.99.1 + Node 22.16.0)

| Suite | Scope | Result | Evidence |
| --- | --- | --- | --- |
| `cargo test -p shz-dex --test shz_rgb01e_withdrawals --locked` | Rust withdrawal state machine (`Free -> Reserved -> Submitted -> Reconciled / Ambiguous / Frozen / Cancelled`), revised conservation invariant, order exclusion, nonce/evidence uniqueness, WAL crash replay, DLC zero-fee unilateral recovery, cross-language golden vectors, and exhaustive small-state BFS fixpoint (`cap=5, amt=2`, 91 distinct reachable states) | **6 / 6 passed** | Verified in WSL Linux (`rustc 1.99.1`) |
| `cargo test --workspace --locked` | Entire SatsHedgeZero workspace (`shz-cli`, `shz-dex`, `shz-dlc`, `shz-hftd`, `shz-ldk`, `shz-ln-testnet4`, `shz-margin`, `shz-nova-bitvm`, `shz-oracle`, `shz-relay`, `shz-utxoref`, `shz-venue`) | **234 passed, 0 failed, 1 ignored** (`shz-ldk` regtest needs `SHZ_BITCOIND`) | Verified in WSL Linux (`shz-dex`: 98/98 passed) |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Strict workspace clippy after reconciling `origin/main` (`d63596e`) | **PASS (0 warnings)** | Verified in WSL Linux |
| `npm --prefix integrations/utexo-rgb test` | `mock.test.mjs`, `recovery.test.mjs`, `journal.test.mjs`, `observers.test.mjs`, `checkpoint.test.mjs`, `native-integration.test.mjs`, and new `withdrawal-bridge.test.mjs` (Rust<->JS BIP340 golden vectors, explorer/simulated-ack refusal, mismatched fields, stale auth, signature substitution, cross-network replay, duplicate receipt consumption) | **26 / 26 `node:test` passed** + **33 mock assertions** + **124 recovery assertions** (29 valid / 3,877 rejected sequences), including 3 live child `SIGKILL` tests | Verified in WSL Linux (`Node v22.16.0`) |
| Published native addon load & provenance check | `@utexo/wdk-rgb-lightning@0.2.0-beta.5` + `@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5` `getRuntimeInfo()` + SHA-256 + SLSA metadata | **PASS** | [receipts/provenance-verified.json](./receipts/provenance-verified.json) |
| Upstream `tests/regtest/setup.mjs --onchain-only` | Upstream source-built RLN HTTP issuer check | **BLOCKED (expected)** | Fails at `setup.mjs:15`: `ORG_READ_TOKEN with read access to the three private upstream BFA repositories is required` |

### 2.2 Native Regtest Blockers and Resulting Qualification Scope

Two distinct blockers prevented executing the live funded regtest payment loops on this host during this session:

1. **Cryptographic / Private Source Blocker (Upstream Full Stack — BFA)**:
   - Upstream `tests/regtest/setup.mjs --onchain-only` refuses to build the `rln` HTTP daemon container without `ORG_READ_TOKEN` granting read access to the three private UTEXO BFA repositories.
   - **Mitigation implemented**: We verified that the published `@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5` package ships a complete prebuilt `index-linux-x64-gnu.node` exposing `SdkNode.issueAssetNia`, `SdkNode.issueAssetIfa`, `sendRgb`, `openChannel`, `sendPayment`, and `makerInit`/`taker`/`makerExecute`. Moreover, upstream `tests/regtest/README.md` documents `RGB_INDEXER_URL=http://127.0.0.1:29302` (`mempool/electrs:v3.3.0`), avoiding source compilation of `romanz/electrs` and the private BFA RLN HTTP daemon.
   - **Scope difference**: The reproducible public-artifact fixture (`regtest-nia-benchmark.mjs`, `adversarial-recovery.mjs`, `shz-rgb02-atomic-swap.mjs`) qualifies **NIA/IFA assets** via a published `SdkNode` issuer under strict external signing (`permissiveSignerPolicy: false`), rather than private **BFA** mint/burn/Ethereum bridge flows or the source-built LSP container.

2. **Host Infrastructure Blocker (WSL2 VHDX Read-Only Fault during Docker Image Unpack)**:
   - During the initial Docker BuildKit build of `Bitcoin.Dockerfile`, the host Windows `C:` volume had only **10.92 GB free** (912.04 GB used), causing the WSL2 ext4 virtual disk to fail with:
     ```text
     ERROR: write /var/lib/docker/buildkit/containerd-overlayfs/metadata_v2.db: read-only file system
     ```
   - Subsequent WSL2 invocations returned `Catastrophic failure / Error code: Wsl/Service/E_UNEXPECTED`, leaving `Ubuntu-24.04` in `Stopped` state until host disk space is freed and the Windows `WslService` is restarted with host administrator privileges.
   - Consequently, **0 / 100** live funded benchmark attempts, **0 / 12** live native regtest adversarial scenarios, and **0 / 5** live `SHZ-RGB-02` atomic swap regtest cases executed on-chain in this session. All denominators preserve `0 observedSuccess / 100 unexecuted` in [receipts/qualification-matrix.json](./receipts/qualification-matrix.json).

---

## 3. Failure and Qualification Matrix

| Gate / Workstream | Category | Status | Measured / Verified Evidence | Blocker / Remaining Gate |
| --- | --- | --- | --- | --- |
| `SHZ-RGB-01E` Rust withdrawal state machine & revised conservation invariant | Native Rust (`shz-dex`) | **PASSED** | 6/6 withdrawal integration tests, 91-state exhaustive BFS fixpoint, 98/98 `shz-dex` tests, 234/234 workspace tests, strict clippy 0 warnings | None |
| Rust <-> JS canonical receipt (`SHZ/WITHDRAWAL-RECEIPT/V1`) & quote binding | Cross-language (`shz-dex` + `integrations/utexo-rgb`) | **PASSED** | 3 golden vectors verified byte-for-byte in Rust and pure-JS BIP340 (`withdrawal-bridge.test.mjs`), 26/26 JS tests pass, explorer/simulated-ack refusal verified | None |
| `SHZ-RGB-01B/C` local durable journal + checkpoint CAS `SIGKILL` tests | Real POSIX process death (local FS) | **PASSED** | 3 actual child `SIGKILL` crash tests pass (journal append, before-CAS, after-CAS) | Separate trusted remote CAS service for production |
| `RGB-01a` Package provenance & Linux x64 native runtime load | Native artifact provenance | **PASSED (NIA/IFA public packages)** | Exact npm shasum/SHA-512/SLSA v1, addon SHA-256 `e3597441...`, `rln_commit` `ecc69f20...`, `mainnet-lightning-rejection-v1` verified | Private BFA `ORG_READ_TOKEN` required for upstream source-built RLN HTTP daemon / LSP |
| `RGB-01b` / `RGB-01e` Native regtest benchmarks (`btc-ln`, `rgb-ln`, `rgb-chain`, 100 attempts each) | Live native regtest | **UNEXECUTED (0/100 per rail)** | Harness implemented (`regtest-nia-benchmark.mjs` + `native-worker.mjs`), syntax checked; `0/100` executed | Host WSL2 `Wsl/Service/E_UNEXPECTED` + low C: disk space (`10.95 GB`) |
| `RGB-01c` / Section 4 Adversarial crash & recovery (6 kill boundaries + reorg/P03 + P02 + signer restart + RGB force-close/S01) | Live native regtest + Rust WAL CLI | **UNEXECUTED (0/12 live native)** | Harness implemented (`adversarial-recovery.mjs` + `shz_withdrawal_cli.rs`); local JS `SIGKILL` (3/3) and Rust WAL crash replay (1/1) verified separately | Host WSL2 recovery; upstream `P02`, `P03`, `P04`, `S01`, `D01` remain open production gates |
| `SHZ-RGB-02` Native atomic BTC/RGB Lightning swap | Source audit + gated regtest harness | **SOURCE-VERIFIED; REGTEST UNEXECUTED (0/5)** | RLN `routes.rs` + `ldk.rs` circular HTLC swap protocol audited; gated harness (`shz-rgb02-atomic-swap.mjs`) ready | Host WSL2 recovery; unilateral recovery blocked by upstream strict-signer `S01` |
| Section 5 CI audit (`shz-rust-and-core-regtest` & `shz-mnr05-bitvm3-ln-dlc`) | Repository CI | **AUDITED** | `shz-rust-and-core-regtest` clippy fixed by `d63596e` on `main` (merged); `shz-mnr05-bitvm3-ln-dlc` root cause confirmed as stale standalone `research/mnr05_bitvm3_ln_dlc/Cargo.lock` reproducing on `main` `d63596e` | Separate PR needed to regenerate `research/mnr05_bitvm3_ln_dlc/Cargo.lock` |
| `RGB-01f` Mainnet RGB Lightning | Production gate | **DISABLED / BLOCKED** | Upstream `mainnet-lightning-rejection-v1` enforced; never bypassed | Requires upstream mainnet support, public audit (`D01`), `P02`/`P03`/`P04`/`S01` closure |

---

## 4. Exact Reproduction Commands (Linux / Recovered WSL2)

Once host disk space is freed and Linux/WSL2 Docker is healthy, reproduce all live native regtest suites with the exact SHA-256-pinned public NIA/IFA stack (zero private tokens required):

```bash
# 1. Build the Rust withdrawal CLI and run Rust + JS unit/bridge verification
cargo test -p shz-dex --test shz_rgb01e_withdrawals --locked
cargo build -p shz-dex --locked --example shz_withdrawal_cli
npm --prefix integrations/utexo-rgb test

# 2. Install exact pinned published UTEXO packages in an isolated directory
mkdir -p /var/tmp/shz-utexo-pkg && cd /var/tmp/shz-utexo-pkg
printf '{"name":"shz-utexo-runtime","private":true}\n' > package.json
npm install --no-audit --no-fund \
  @utexo/wdk-rgb-lightning@0.2.0-beta.5 \
  @utexo/rgb-lightning-node-nodejs@0.2.0-beta.5

# 3. Start SHA-256-pinned Bitcoin Core 31.1 + pinned Docker Esplora 3.3.0 + RGB Proxy 0.3.0
curl -fsSL -o /var/tmp/bitcoin-31.1.tar.gz \
  https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz
echo "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e  /var/tmp/bitcoin-31.1.tar.gz" | sha256sum -c -
tar -xzf /var/tmp/bitcoin-31.1.tar.gz -C /var/tmp
mkdir -p /var/tmp/shz-btc-regtest /var/tmp/shz-electrs-regtest
/var/tmp/bitcoin-31.1/bin/bitcoind -regtest -daemon -datadir=/var/tmp/shz-btc-regtest \
  -server -rest -txindex -fallbackfee=0.00002 -rpcbind=127.0.0.1 -rpcport=29443 \
  -rpcallowip=127.0.0.1 -rpcuser=wdk -rpcpassword=regtest-only -discover=0 -dnsseed=0
/var/tmp/bitcoin-31.1/bin/bitcoin-cli -regtest -rpcport=29443 -rpcuser=wdk -rpcpassword=regtest-only createwallet miner
MINER_ADDR=$(/var/tmp/bitcoin-31.1/bin/bitcoin-cli -regtest -rpcport=29443 -rpcuser=wdk -rpcpassword=regtest-only -rpcwallet=miner getnewaddress)
/var/tmp/bitcoin-31.1/bin/bitcoin-cli -regtest -rpcport=29443 -rpcuser=wdk -rpcpassword=regtest-only generatetoaddress 110 "$MINER_ADDR"

docker run -d --name shz-regtest-indexer --network host -v /var/tmp/shz-electrs-regtest:/data \
  mempool/electrs:v3.3.0@sha256:de9dd2f5a328d5f464936dc4128d848f9b8bf72221ab3c9b8e2949df50899b74 \
  --network=regtest --jsonrpc-import --cookie=wdk:regtest-only \
  --daemon-rpc-addr=127.0.0.1:29443 --http-addr=127.0.0.1:29302 \
  --electrum-rpc-addr=127.0.0.1:29402 --db-dir=/data
docker run -d --name shz-regtest-proxy -p 127.0.0.1:29300:3000 \
  ghcr.io/rgb-tools/rgb-proxy-server:0.3.0@sha256:b06fe0f234c53030d54fe1e704daf4bc6ff2879a335124353175130a5112d313

# 4. Run Section 3 (100-attempt native benchmarks), Section 4 (12 adversarial crash/recovery scenarios),
#    and Section 6 (gated SHZ-RGB-02 atomic BTC/RGB Lightning swap experiment)
export SHZ_DISPOSABLE_REGTEST=YES
export SHZ_UTEXO_PKG_ROOT=/var/tmp/shz-utexo-pkg
export RGB_INDEXER_URL=http://127.0.0.1:29302
export SHZ_WITHDRAWAL_CLI="$(pwd)/target/debug/examples/shz_withdrawal_cli"

node integrations/utexo-rgb/regtest-nia-benchmark.mjs 100 100 integrations/utexo-rgb/receipts/shz-rgb01f-benchmarks.json
node integrations/utexo-rgb/adversarial-recovery.mjs integrations/utexo-rgb/receipts/shz-rgb01f-adversarial.json
SHZ_RGB02_EXPERIMENT=YES node integrations/utexo-rgb/shz-rgb02-atomic-swap.mjs integrations/utexo-rgb/receipts/shz-rgb02-atomic-swap.json
```
