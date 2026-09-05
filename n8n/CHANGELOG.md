# Changelog

All notable changes to `@cognexuslabs/n8n-nodes-artzain`.

## 0.1.3

### Fixed

- **Both nodes now time out.** The Decision and Envelope nodes called
  `fetch` with no `AbortSignal`, so a stalled server hung the workflow item
  indefinitely. Each node gains a **Timeout (ms)** parameter (default
  10 000); a request that exceeds it is aborted and the item fails closed
  (Deny on the Decision node, an error / `outcome: "deny"` on the Envelope
  node) instead of never returning.

## 0.1.2 — 2026-09-04

### Fixed

- **Decision node: the fallback `request_id` no longer replays another
  execution's verdict.** With Request ID left empty the node sent
  `n8n-<item>-<action>` — `n8n-0-charge_customer` for item 0 of *every*
  execution. The server keys its idempotency ledger on `(user_id,
  request_id)` for 48 h and replays the earlier decision without comparing
  the payload, so a second customer charged within two days received the
  first one's sealed decision and no new audit leaf. The fallback is now
  `n8n-<executionId>-<item>` (a random UUID stands in when n8n exposes no
  execution id), capped at the server's 64-character limit. Set Request ID
  explicitly to a business key when replay across retries is what you want.
