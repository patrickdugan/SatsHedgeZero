# SHZ-RGB-01B: signed settlement journal

Research-only Linux local-filesystem sidecar. No SDK calls, signing secrets, SHZ ledger mutation or real asset movement. The original pure transition model remains the state machine; this wrapper checks signature policy, exact input schema, cross-role evidence uniqueness and persistent replay.

## Threat model and boundary

An independently provisioned journal ID and four distinct Ed25519 public keys (SPKI PEM) establish a policy. Distinct keys are necessary but do not establish organizational independence; arrange that separately. Pin the policy and journal ID outside the journal. Trusted SHZ withdrawal authorizer signs the reservation (batch digest, withdrawal ID, payment hash, asset contract ID, units, sats, carrier msat, recipient, network, times). Independent BTC and RGB observers sign the same reconciliation event plus the full reservation, in different signer domains. A chain observer signs conflict notices. Canonical signed bytes are UTF-8 JSON of a sorted-key structure prefixed by SHZ/RGB/JOURNAL/ATTEST/V1. The role and journal ID prevent cross-role/cross-journal signature reuse. Payment and withdrawal identities are unique within this journal. External proof identifiers are unique across both settlement roles. Observer software must choose stable, canonical, independently verified evidence IDs (e.g., chain/network + txid/outpoint + proof semantics; LN hash + verified claim), rather than arbitrary digests of different representations. Cross-journal/global uniqueness and proof-ID derivation need their own enforcement.

A valid signature establishes that the configured key attested to a statement. It does not independently prove chain inclusion, RGB consignment validity, Lightning preimage, received balance, BTC exchange execution, valid SHZ authorization or atomicity. This module does not implement the signer services. The record currently binds the core amount and identity fields; quote fee cap, provider identity, exact oracle snapshot, full signed SHZ reserve entitlement, and asset allowlist remain integration gates. Local submission timestamps assume a trusted clock and caller; no automatic payment dispatch exists.

## Persistence

New journal directory must be private and nonexistent. A writer obtains an exclusive .writer directory lock. Header pins role key fingerprints and journal ID; JSONL frames carry sequence, previous hash and SHA-256 digest over the canonical record. Append validates and replays before writing, fsyncs before returning the new tip, poisons the in-memory writer on failed write or fsync. Reopen checks every frame, all attestations and the exact externally supplied tip. A valid but older prefix, unacknowledged newer tail, malformed data or partial frame refuses reopening. The prototype refuses automatic truncation and stale-lock takeover. A SIGKILL leaves the lock; an operator must prove the prior process is dead before removing it, preserve original bytes and independently reconcile the correct tip. No lock deletion or pin correction is automated. Store pins in a separate trusted durable service, not alongside the journal. Persist the new tip externally before permitting any side effect; a crash between journal fsync and external pin advancement requires independent review. No dispatch can be retried from submitted/ambiguous/observed states. Reconciled obligations can freeze while retaining the historic credited marker, not silently reverse a real transfer.

Local trusted directory/host, single writer, local Linux fs semantics. No network FS, malicious host, privileged file mutation while open, power-loss durability, true ENOSPC recovery, multi-host coordination, pin store or log rotation has been qualified. This reference has a 4 MiB journal limit and 16 KiB frame limit and fully replays/verifies the history per append (quadratic total work); keep off the matching hot path. It contains no payment or credit side effects; credited is a model flag only.

## Verification

Run from this subfolder:

    npm test
    node --test journal.test.mjs

Local Node v22.16.0 on Linux: six tests passed (actual Node crypto/fsync/process kill). The test initially exposed an incorrect expected error reason for an out-of-order retry; updated the test to retry at a monotone timestamp and reran. Covered wrong role/domain, tampering, missing signatures, duplicate identity and cross-role proof reuse, key policy, exclusive writer, immutable snapshot, exact external pin, corrupt/torn tail, actual child SIGKILL after fsynced submit and no retry after restart. The local recovery-model copy retained the upstream transition logic; CI must run the exact checked-in tree. Torn frame was injected after clean close, not an instrumented partial-write crash or power-loss test. Test evidence uses synthetic proof identifiers and generated signing keys, never real wallets. No native RGB payments executed.

Previous sidecar Node CI at 6acab6270a2e50b9a0babf1bf926f4d5b692a896 passed ([run 45852021037](https://github.com/patrickdugan/SatsHedgeZero/actions/runs/45852021037)); two BitVM3 workflow runs at that SHA failed. No claim that all repository CI is green.

## Next acceptance

Build separate BTC and RGB evidence observers on the pinned disposable regtest fixture, authenticate an actual SHZ committed withdrawal, derive canonical proof IDs and verify receipt contents before signing. Add a trusted external compare-and-swap tip store, instrument real native dispatch and kill points between reservation, dispatch, native receipt, journal fsync and external pin publication. Demonstrate independently reconciled BTC/RGB balances after each crash/reorg, with zero duplicate credits; keep the live Rust settlement boundary unchanged until those gates pass.
