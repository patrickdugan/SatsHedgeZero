# Rust FROST member (`shz-frost-member`)

`crates/shz-frost-member` builds `shz-frost-member`, a drop-in replacement for
`ops/public-relay/frost_signer.py`, one member of the live 3-of-5 FROST price relay and DLC
oracle. The reason for the port: the Python member does secret-share, nonce and DLC
nonce-share arithmetic in Python big ints, which are not constant-time. The Rust member keeps
every secret in a k256 `Scalar` (constant-time scalar and field arithmetic) and computes ECDH
pads, partial signatures and BIP340 decision-lock signatures with it.

## What is the same

- Command line: `--share --state --listen --max-deviation-bps --view-refresh-s
  --view-max-age-s --no-price-check --coord-auth-key --no-coord-auth`, the "exactly one of
  `--coord-auth-key` or `--no-coord-auth`" rule (exit 2), `keygen --t --n --out`, and the
  startup line `frost member N group=... listen=... price_check=on coord_auth=on`.
- Endpoints and JSON: `/healthz`, `/commit`, `/sign`, `/dlc/deal`, `/dlc/receive`,
  `/dlc/sign-announcement`, `/dlc/lock-outcome`, `/dlc/lock-unattestable`, `/dlc/sign-outcome`,
  `/dlc/sign-unattestable`; status codes 200/401/404/409; response bodies byte-identical to
  `json.dumps`, including the `"{ExceptionType}: {message}"` refusal texts.
- Coordinator authentication (`coord_auth.py`): `X-SHZ-Auth` HMAC over path, timestamp, nonce
  and body hash, 30 s window, replay cache, 401 on failure.
- Safety rules: F-01 decision-lock quorum and the canonical announcement core, F-03 own price
  reading (the four fast sources over HTTPS every 15 s, staggered by index; VALID medians more
  than 50 bps off are refused), F-05 sequence and slot bounds and at most 64 stored nonces,
  F-14 setup abandonment (a member that completed `receive` refuses to deal again).
- State files: `share.json`, `nonces.json`, `dlc.json` and `coord_auth.key` are read and written
  in the Python member's format. JSON follows Python's `json` module exactly (key order,
  `1` vs `1.0`, `ensure_ascii`, `repr(float)`), so packet hashes over coordinator-supplied bodies
  and the rewritten state files are the same bytes. A member switches implementation in
  either direction without re-keying and without touching its state.

## Evidence

| Check | Command | Result |
|---|---|---|
| Byte vectors | `cargo test -p shz-frost-member` (replays `tests/vectors.json` from `tests/gen_vectors.py`) | 74 requests through the Python handler and the Rust member: same status, same response bytes; all five members' final `nonces.json` and `dlc.json` identical; Rust restarts on Python-written state |
| Python suites on Rust members | `SHZ_RUST_MEMBER=... python -m unittest -v test_rust_member` in `ops/public-relay` | test_frost, test_dlc, test_review_hft06 (all review repros) with every member a Rust process: 45 tests OK |
| Mixed confederation | `test_rust_member.MixedConfederation` | Python coordinator, Python members 1-2, Rust members 3-5 with auth key files: VALID packets signed by {1,2,3} and {2,3,4}, DLC event set up and attested with mixed signers, a body 100 bps off refused |
| Live price reading | default build, `--view-refresh-s 5`, `/healthz` | Windows build (schannel): four fresh sources, `VALID`, median within cents of the exchanges. The Linux build (OpenSSL) was not run |

The harness needs a binary built with `--features test-hooks` (adds `/test/*` routes and
harness callbacks for the internals the tests call directly). Never deploy that build.

## Differences from the Python member

- F-11 limits like `public_relay.LimitedHTTPServer`: 256 connections, 32 per address (503 beyond),
  10 s per socket read or write. The Python member has no limits; an idle local connection there
  holds a thread forever.
- Requests the Python member would parse and the Rust member refuses with 409: JSON in
  UTF-16/32, lone surrogate escapes (`"\ud800"`), integers beyond 2^127, `int()` of non-ASCII
  digits. The coordinator sends none of these; each is a refusal, never a different signature.
- The price fetch does not follow HTTP redirects (urllib does); a redirecting source counts as down.
- Hex decoding of `share.json` and `nonces.json` strings branches on the characters; the
  arithmetic after decoding is in k256.

## Build

On the box (x86_64 Linux): `pkg-config` and `libssl-dev` (the price fetch uses native-tls,
which links the system OpenSSL and its CA store), then

    cargo build --release -p shz-frost-member
    install -o root -g root -m 0755 target/release/shz-frost-member /opt/shz-frost-member/shz-frost-member

`--no-default-features` drops the price fetch; such a member refuses every VALID body.

## Deploy: one member at a time

Maturities are every 15 minutes (:00, :15, :30, :45), four are kept announced, attestation
starts at maturity + 5 s, and the unattestable path can run until maturity + 90 s plus the
coordinator's retries. Decision locks need 4 of 5 members, so a restart during an attestation
leaves exactly the quorum: switch members only inside the DLC-safe window, **maturity + 5 min to
maturity + 12 min** (for example :05 to :12), and never two at once.

Order: member 5, 4, 3, 2, 1 (the coordinator takes the first three members that answer, so 5 and 4
sign packets least often).

For member `N`:

1. Pre-checks. All five `curl -s 127.0.0.1:910M/healthz` answer with `coord_auth: true` and the
   same `group_pubkey`; the relay is publishing VALID packets; `GET /v1/dlc/events` on the relay
   shows the latest matured event `attested` (or `unattestable`) and the next four `announced`.
   Note member N's `last_seq` from `/healthz`.
2. Forensic copy, never to be restored: `cp -a /var/lib/shz-frost-signer-N /root/frost-signer-N-$(date +%F)`.
3. Inside the safe window, install the drop-in
   `/etc/systemd/system/shz-frost-signer@N.service.d/rust.conf` (applies to instance N only):

       [Service]
       ExecStart=
       ExecStart=/opt/shz-frost-member/shz-frost-member --share /var/lib/shz-frost-signer-%i/share.json --state /var/lib/shz-frost-signer-%i --listen 127.0.0.1:910%i --coord-auth-key /var/lib/shz-frost-signer-%i/coord_auth.key

   then `systemctl daemon-reload && systemctl restart shz-frost-signer@N`. User, state directory,
   `MemoryMax`, sandboxing and the address families stay as in `shz-frost-signer@.service`.
4. Check. `journalctl -u shz-frost-signer@N -n 3` shows
   `frost member N group=<group key> listen=127.0.0.1:910N price_check=on coord_auth=on`.
   `/healthz` shows the noted `last_seq` (or higher), `coord_auth: true`, `auth_refused` 0, and
   within 30 s `price_view.status` `VALID`. Packets keep flowing, and the relay's `/healthz`
   (`stats.frost.cheaters`, `stats.frost.refusals`) gains no entry for `N`.
5. Soak through the next maturity: the attestation's `decision_locks` include `N` and the
   member's `refused` counter did not move. Wait one hour more before the next member.

## Rollback

Remove the drop-in and restart:

    rm /etc/systemd/system/shz-frost-signer@N.service.d/rust.conf
    systemctl daemon-reload && systemctl restart shz-frost-signer@N

The Python member resumes from the state files the Rust member wrote (same format, same bytes).
Do the rollback inside a DLC-safe window as well. **Never restore the forensic copy** of
`nonces.json` or `dlc.json`: an older `nonces.json` lowers the sequence high-water mark, and an
older `dlc.json` drops decision locks, which is the rolled-back-member case of review finding
F-02.
