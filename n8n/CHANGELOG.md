# Changelog

All notable changes to `@cognexuslabs/n8n-nodes-artzain`.

## 0.1.5

### Changed

- **The Request ID help text and the README describe replay as the server
  does it now.** A repeat of a request id replays the sealed decision only
  when its inputs (Agent DID, Action, Target, Payload, Payload Kind) match;
  a repeat whose inputs differ is decided and sealed again. Both said the
  server replays the prior decision without looking at the payload, which
  holds only for engines built before 21 September 2026; the README still
  warns about those. Replay itself is the server's; the node sends the same
  request as before.
- README: install from npm (published since 0.1.0). It said to install from
  a git checkout until the package was tagged; a checkout build is now the
  route for an unreleased change.

### Fixed

- **Both nodes time out while reading the response, not only while waiting
  for it.** The Timeout (ms) deadline was cleared once the response headers
  arrived, so a server that sent them and then stopped mid-body hung the
  item indefinitely. The deadline now covers the whole call, and a timed-out
  item fails closed as before (Deny on the Decision node, an error /
  `outcome: "deny"` on the Envelope node).
- **Decision node: a response body that is not JSON reaches Deny.** The node
  read the body as JSON and then, to quote it, read it a second time, which
  always failed because the body was already spent. A proxy's HTML error
  page raised a node error, or with Continue On Fail a Deny quoting "Body is
  unusable", instead of a Deny quoting the page. The body is now read once.
  An empty body routes on its HTTP status.

## 0.1.4

### Changed

- **README: the Request ID section now describes the fallback as the code
  builds it** — the `requestId` parameter is read first, the execution id
  comes from n8n's `getExecutionId()`, a random UUID stands in when n8n
  exposes none (or an empty one), and the result is cut to the server's
  64-character cap. Documentation only; no node behaviour changed.

### Fixed

- The base-URL trailing-slash trim in both nodes (`decisionsUrl`,
  `envelopeCompletionsUrl`) scans instead of using `/\/+$/`, which
  backtracked quadratically on a value made up mostly of slashes — the same
  fix the TypeScript SDK's `config.ts` carries. Shared in `base-url.ts`.

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

## 0.1.1

Published 2026-08-27. Version-only: the first release through npm Trusted
Publishing (OIDC, Sigstore provenance), which also exercised the `n8n-v*`
path of the mirror's publish workflow. No code change.

## 0.1.0

Published 2026-08-23 (bootstrap publish by hand; npm binds a trusted
publisher only to a package that already exists). First release: the
**CogNEXUS Decision** node (allow / review / deny outputs; anything but HTTP
200 with a known outcome routes to Deny — fail closed; `review` is a stop
branch, not a Wait node) and the **CogNEXUS Envelope** node (OpenAI-shaped
chat completions through the CogNEXUS envelope proxy, Bearer envelope key).
