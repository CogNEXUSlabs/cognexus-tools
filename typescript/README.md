# @cognexuslabs/artzain — ArtzAIn Decision API client for Node.js

Gate agent actions through the ArtzAIn decision engine and get back a
sealed, auditable `allow` / `deny` / `review` outcome.

```bash
npm install @cognexuslabs/artzain   # Node >= 18, zero runtime dependencies
```

```ts
import { configure, decide, DecisionError } from "@cognexuslabs/artzain";

configure({ apiKey: process.env.COGNEXUS_API_KEY }); // or just set the env var

const decision = await decide({
  action: "send_email",
  target: "crm:contact:123",
  payload: draftEmailBody,
});

if (decision.outcome === "allow") {
  await sendEmail(draftEmailBody);
} else {
  console.warn(`Blocked (${decision.outcome}) — sealed decision ${decision.decision_id}`);
}
```

On the hosted service a decision from an agent your account has not declared
comes back `deny`, with the finding `agent '<id>' not in registry`, and the
default id, `cognexus-sdk-ts`, is undeclared like any other. Pass your agent's
id as `agentDid` and use a key bound to it: in the dashboard, **API keys**,
**Bind to agent id**.

## Go further with ArtzAIn

This client talks only to the hosted ArtzAIn engine. A free
[Open](https://app.cognexuslabs.ai/?utm_source=npm&utm_medium=readme)
account is enough to start: no card, the plan does not expire, and each
`decide()` result is sealed as a signed, hash-chained receipt (30 days of
receipts, 10,000 sealed decisions per month, a soft cap that never blocks a
decision).

- Create an Open account, set `COGNEXUS_API_KEY`, or run the Python CLI
  `artzain login` and reuse `~/.artzain/credentials.toml`.
- Gate an action and get `allow`, `deny`, or `review` back, already sealed.
- Post the business result of an allowed decision with `postDecisionResult`,
  and open Tokens-to-Outcomes for the workload those decisions belong to.
- Export and check receipts offline with the Python CLI
  (`pip install 'artzain[verify]'`, then `artzain audit verify`). From
  artzain 0.6.70 a bundle whose deployment holds a certificate under the
  CogNEXUS Labs Evidence Root verifies as attested; one without a certificate
  verifies as self-attested.
- Need a longer retention window, more volume, or the compliance bundles?
  Paid plans start at Build. See
  [pricing](https://cognexuslabs.ai/pricing?utm_source=npm&utm_medium=readme).

## Configuration

| Source | Key |
|---|---|
| `configure({ apiKey, baseUrl })` | explicit, wins |
| `COGNEXUS_API_KEY` (or `MYAPP_API_KEY`) | API key from Account → API Keys |
| `~/.artzain/credentials.toml` | Profile written by `artzain login` (Python CLI); read after the env vars on Node 20.16+ / 22.3+. `COGNEXUS_CREDENTIALS_PATH` overrides the path. |
| `COGNEXUS_API_BASE_URL` | your deployment (default `https://app.cognexuslabs.ai`) |

A key goes only to the host it was issued with. The profile's key (or the same
key set another way) goes to the profile's `base_url`; any other key goes to
`configure({ baseUrl })`, then `COGNEXUS_API_BASE_URL`, then the default. When a
host you set is not the profile key's, the call sends nothing and fails with
`DecisionError` (`postSdkEvent` returns `false`); the message names the settings,
not their values. Nor does a redirect move the key: the calls do not follow one,
so a 3xx fails the call with its status, and a `fetchImpl` you pass must not
follow redirects either.

## Surface

- `decide(options)` → `DecisionResponse` — `POST /api/v1/decisions`. Deny/review
  outcomes are **returned**, not thrown; `DecisionError` is thrown for transport
  failures, missing keys, and typed engine refusals (`kill_switch_active`,
  `audit_unavailable` — the engine fails closed and so should you). For a
  request that failed, the message names the error's kind (and, when no answer
  came back, where the base URL came from), not the error's text, which can
  quote the API key or name the host; to see that text, pass a `fetchImpl`
  that wraps `fetch` and records what it, and the response's `json()`, reject
  with.
  `workloadId` and `modelId` name the workload and the model the decision
  belongs to; the Tokens-to-Outcomes page groups by them.
  `parentDecisionIds`, `sessionId`, `traceId`, `spanId`, `toolCallId` and
  `onBehalfOf` are the decision's lineage: the engine signs them into its
  record, and a decision trace is drawn from them.
- `postSdkEvent(options)` — fire-and-forget guard-event telemetry
  (`POST /api/events`); never throws. `tokensIn` and `tokensOut` attach token
  counts to the event.
- `postGenerationOutcome(options)` — report one model call and what it cost
  in tokens; never throws. Pass the `decision_id` from `decide()` as
  `requestId` and the tokens count on that decision.
- `postDecisionResult(decisionId, resultRef)` — post the business result of a
  sealed decision (`POST /api/v1/decisions/{decision_id}/result`). An allowed
  decision with a posted result is an accountable outcome. Throws
  `DecisionError` when refused.
- `fetchApiKeyIdentity()` — validate the configured key (`GET /api/api-keys/me`).

## Divergence from the Python SDK

This SDK is **remote-only**: there is no offline local-guard fallback. If no
API key is configured, `decide()` throws instead of screening locally. Use the
Python SDK (`pip install artzain`) where offline guard parity matters.

## Development

```bash
npm ci
npm run build   # tsc → dist/
npm test        # vitest
```
