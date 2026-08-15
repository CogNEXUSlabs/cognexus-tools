# @cognexus/sdk — CogNEXUS Decision API client for Node.js

Gate agent actions through the CogNEXUS decision engine and get back a
sealed, auditable `allow` / `deny` / `review` outcome.

```bash
npm install @cognexus/sdk   # Node >= 18, zero runtime dependencies
```

```ts
import { configure, decide, DecisionError } from "@cognexus/sdk";

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

## Configuration

| Source | Key |
|---|---|
| `configure({ apiKey, baseUrl })` | explicit, wins |
| `COGNEXUS_API_KEY` (or `MYAPP_API_KEY`) | API key from Account → API Keys |
| `COGNEXUS_API_BASE_URL` | your deployment (default `https://cognexuslabs.ai`) |

## Surface

- `decide(options)` → `DecisionResponse` — `POST /api/v1/decisions`. Deny/review
  outcomes are **returned**, not thrown; `DecisionError` is thrown for transport
  failures, missing keys, and typed engine refusals (`kill_switch_active`,
  `audit_unavailable` — the engine fails closed and so should you).
- `postSdkEvent(options)` — fire-and-forget guard-event telemetry
  (`POST /api/events`); never throws.
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
