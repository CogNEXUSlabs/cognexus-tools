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
