# `@cognexuslabs/openclaw-artzain`

OpenClaw **plugin** that registers `api.on("before_tool_call", …)` and calls
the CogNEXUS Decision API before a host tool runs. `deny`, `review`, and
engine refusals (HTTP 503 / missing key) return `{ block: true }`.

This is pattern C. Envelope pattern B (model `base_url` swap) is still
[`docs/sdk/recipes/openclaw-provider.json5`](../../docs/sdk/recipes/openclaw-provider.json5).

## What this is not

- Not a Connectors-panel card.
- Not published on ClawHub from this repository. Dest
  (`CogNEXUSlabs/cognexus-tools`) holds Trusted Publishing. Until that listing
  exists, install from a git checkout.
- Not a mapping of CogNEXUS `review` onto OpenClaw `/approve`.

## Install (from a CogNEXUS checkout)

```bash
openclaw plugins install ./sdk/openclaw
```

Set `COGNEXUS_API_KEY` on the Gateway (sandbox key from `/get-a-key`, **not**
a dashboard JWT and **not** an envelope `cnxe_…` key). Optional:
`COGNEXUS_API_BASE_URL`, or plugin config `apiKey` / `baseUrl` / `agentDid`.

```json5
{
  plugins: {
    entries: {
      "artzain-tool-gate": {
        enabled: true,
        config: {
          // apiKey: "cgnx_…",   // or COGNEXUS_API_KEY
          // baseUrl: "https://app.cognexuslabs.ai",
        },
      },
    },
  },
}
```

## Contract

| Outcome | Plugin result |
|---|---|
| `allow` | tool runs |
| `deny` | `{ block: true, blockReason }` |
| `review` | `{ block: true }` — human owns it in the CogNEXUS Review Queue |
| HTTP 503 / 401 / 422 / missing key | `{ block: true }` (fail closed) |

## Instance announce (v0.2, opt-in)

Instances no scanner can reach (laptops, home labs) can self-register with
the CogNEXUS Agent Wrangler:

```json
{
  "announce": true,
  "instance": "jeans-laptop",
  "announceAgents": ["main"],
  "announceSkills": ["artzain"]
}
```

Once per process (on the first gated tool call), the plugin POSTs this
identity — **names only, never content or config** — to
`POST /api/v1/registry/announce` with the same Decision API key it already
holds. Rows land as source `openclaw` behind the standard sealed
registration gate, in the review queue like every other discovery.
`announceAgents` defaults to the hook's `agentId` (the identity on your
decision leaves), then `agentDid`. Pick a stable `instance` name (no `#`) —
changing it re-namespaces the rows. Announce is telemetry, not a gate: it
never blocks or delays tool gating, and its failure never fails closed.
Transient failures (network, 5xx, 429) retry on a later gated call; a 4xx
refusal means config — fix and restart. The success log line reports the
server's `registered/seen/blocked/deferred` counts; `deferred` rows are
held by capacity and only submitted again on a re-announce.
