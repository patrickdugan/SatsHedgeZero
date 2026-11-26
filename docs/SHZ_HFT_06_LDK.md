# HFT-06 Lightning adapter: LDK investigation

Investigated before choosing the production implementation of `shz_dex::routing::ln_fees::LightningAdapter`, which today has only `MockAdapter`. Sources were read on 2026-11-25 from docs.rs and GitHub; the versions below are the ones those pages showed. Nothing here has been compiled against LDK yet.

## What the adapter must prove

1. **Commitment evidence for a lane.** HFT-05 `ChannelAck.evidence` must be an authenticated, channel-specific digest showing the new commitment state is durably persisted before a batch resolves `Commit`, or that the state is irreversibly unchanged for `FencedAbort`.
2. **Fee receipt.** An obligation moves `committed → collected` only on a verified receipt: payment hash, preimage, amount and recipient, with no reuse.
3. **DLC legs in channels.** The longer-term goal is DLC contract outputs inside channel commitments. DLC settlement fees stay zero.

## LDK surface (`lightning` 0.2.8 on docs.rs; `ldk-node` 0.7.1)

| Need | LDK primitive | Notes |
| --- | --- | --- |
| Send fee payment | `ChannelManager::send_payment` (with `Retry`), `send_spontaneous_payment`, `pay_for_offer`, `pay_for_bolt11_invoice` | Each recipient publishes one BOLT12 offer, so group-committed fees need no invoice round trip |
| Payer-side proof | `Event::PaymentSent { payment_id, payment_preimage, payment_hash, amount_msat, fee_paid_msat, bolt12_invoice }` | `sha256(payment_preimage) == payment_hash` is the proof of payment; `fee_paid_msat` is routing cost, booked separately from the obligation |
| Recipient-side proof | `Event::PaymentClaimable`, then `ChannelManager::claim_funds`, then `Event::PaymentClaimed { payment_hash, amount_msat, purpose, htlcs, sender_intended_total_msat, … }` | The recipient attests `(payment_hash, amount_msat, batch_refs)`; this maps to `FeeReceipt` |
| Durable commitment state | `chain::chainmonitor::Persist`: `persist_new_channel`, `update_persisted_channel(monitor_name, Option<&ChannelMonitorUpdate>, &ChannelMonitor)`, `archive_persisted_channel`, returning `ChannelMonitorUpdateStatus` (`Completed` after fsync, or `InProgress` and later `ChainMonitor::channel_monitor_updated` keyed by `ChannelMonitorUpdate::update_id` / `ChannelMonitor::get_latest_update_id`) | No `Event` reports commitment numbers or `revoke_and_ack`. `ChannelDetails` exposes no commitment counter or update id |
| High-level node | `ldk-node` 0.7.1: `Node::bolt11_payment().send`, `open_channel`, `list_channels`, `list_balances`, `wait_next_event` / `event_handled` | Esplora/bitcoind chain sources. Its BOLT12, spontaneous and payment-listing APIs and regtest support were not confirmed from the pages read |

## Design decision

- **Commitment evidence comes from a wrapping `Persist` implementation.** Every `update_persisted_channel` call first writes the monitor durably. It then appends a record `(monitor_name, update_id, sha256(serialized monitor), funding outpoint)` to the router's lane journal and only then returns `Completed`.
  - `ChannelAck.evidence = tagged_hash("SHZ/HFT06/LDK-MONITOR/V1", monitor_name ‖ update_id ‖ monitor_sha256)`.
  - `Head.commitment` maps to the monitor `update_id`, which is monotone per channel. HFT-05's rule "commit advances the commitment counter by exactly one" therefore becomes "the batch's channel update advances `update_id`". Any single SHZ batch may span several LDK monitor updates (HTLC add, commitment_signed, revoke_and_ack), so the adapter reports the update id reached once all HTLCs of the batch are irrevocably committed. Counting exact steps is not required.
  - The independent monitor signature in `ChannelAck` comes from a watchtower-style process that holds a replica of the same persisted monitor stream.
- **Fee collection uses BOLT12 `pay_for_offer` per registered recipient.** It is driven by `ln_fees::SettlementInstruction`, and `Event::PaymentSent` with the preimage is the payer receipt. The recipient's signed `PaymentClaimed` attestation completes `FeeReceipt`. `fee_paid_msat` goes to router cost, never deducted from oracle or router obligations.
- **Peer disconnects and `InProgress` persistence** leave obligations outstanding and lanes unresolved. No timeout releases collateral; this matches `ln_fees` and HFT-05.
- **Library choice:**
  - Build the commitment-evidence path directly on `lightning` (`ChainMonitor` + custom `Persist`), because `ldk-node` hides the `Persist` layer.
  - Use `ldk-node` only for the fee-payment regtest loop, where the high-level API suffices.
- **DLC inside channels is not available off the shelf.** `p2pderivatives/rust-dlc` (MIT, early stage, mainnet use discouraged by its README) shows no sub-channel or split-channel support and no LDK fork on its main page. DLC collateral stays outside LDK channel commitments: SHZ's existing DLC funding plus HFT-05 lane accounting. LN channels carry only fee flows until a custom channel type is built and reviewed; that is a research item, not an adapter task.

## Gates

| ID | Step | Exit criterion |
| --- | --- | --- |
| G-LN-1a | `lightning` `ChainMonitor` with wrapping `Persist` moves each lane's cleared `ClearingRow::net` through a real channel update between regtest LDK nodes; lane evidence from both parties' journaled monitor records is bound into the V3 ack | Balances on both nodes' persisted monitors equal the clearing ledger after batches with gains, losses and fund use; see `SHZ_LDK_SETTLEMENT.md` |
| G-LN-1e | `ldk-node` regtest fee loop: router node pays three recipient offers per `SettlementInstruction`; recipients attest `PaymentClaimed` (listed as G-LN-1a before 2026-11-26) | Ledger `collected == committed` per recipient, duplicate preimage rejected, payer `fee_paid_msat` booked separately |
| G-LN-1b | `lightning` `ChainMonitor` with wrapping `Persist`; lane journal records; `ChannelAck` evidence derived from monitor update ids | Kill the process between monitor fsync and ack: on restart the same ack is re-derived; no resolution without the persisted update |
| G-LN-1c | Independent monitor replica signs acks | Monitor and router disagreement holds the batch unresolved |
| G-LN-1d | DLC outputs in channel commitments | Separate research track; no adapter dependency |

Testnet4 only after G-LN-1a and G-LN-1b pass on regtest.

The `Head.commitment` mapping above was not adopted: `Head.commitment` still advances by exactly one per Commit (HFT-05's rule is unchanged), and the monitor `update_id` reaches the ack through the monitor records hashed into `ChannelAck.evidence` (`SHZ_LDK_SETTLEMENT.md`).
