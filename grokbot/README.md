# `@cognexuslabs/grokbot-artzain`

Cooperative **skill** that asks the CogNEXUS Decision API before a Grok Bot
side-effect and, optionally, announces the Bot into the Agent Wrangler.
`deny`, `review`, and engine refusals (HTTP 503 / missing key) fail closed.

This is pattern C. Grok Bot has **no documented** `before_tool_call` host
hook (OpenClaw's plugin is an intercept; this is a skill the operator
installs and the Bot description tells it to use). A Bot that never calls
the skill is ungoverned — which is what the catalog and Marshal already
surface. Envelope pattern B (xAI inference `base_url` swap) is still
optional and does **not** wrap the Bot computer.

If `getHostStatus.capabilities` later grows a real intercept, this skill
graduates to a host plugin in a follow-on. This package is not reopened
for that.

## What this is not

- Not a Connectors-panel card.
- Not published from this repository. Dest
  (`CogNEXUSlabs/cognexus-tools`) holds Trusted Publishing. Until that listing
  exists, install from a git checkout.
- Not a host plugin. There is nothing to `plugins install`.

## Install (from a CogNEXUS checkout)

Copy [`SKILL.md`](SKILL.md) into the Bot's skills folder, or run the CLI
from this package:

```bash
cd sdk/grokbot && npm ci && npm run build
# then, from the Bot:
npx --prefix /path/to/sdk/grokbot grokbot-artzain decide \
  --action send_email --target mailbox \
  --payload '{"tool":"send_email","arguments":{"to":"ops@example.com"}}'
```

Set `COGNEXUS_API_KEY` on the host (sandbox key from `/get-a-key`, **not**
a dashboard JWT and **not** an envelope `cnxe_…` key). Example:
`cnx_…`. Optional:
`COGNEXUS_API_BASE_URL`, `GROKBOT_AGENT_ID`, `GROKBOT_INSTANCE`.

## Contract

| Outcome | CLI / `gateToolCall` |
|---|---|
| `allow` | exit 0 / `{ allow: true }` |
| `deny` | exit 2 / `{ allow: false, blockReason }` |
| `review` | exit 2 — human owns it in the CogNEXUS Review Queue |
| HTTP 503 / 401 / 422 / missing key | exit 2 (fail closed) |

## Instance announce (opt-in)

Hosts no scanner can reach (laptops, home labs) can self-register:

```bash
export GROKBOT_ANNOUNCE=true
export GROKBOT_INSTANCE=ops-desk
grokbot-artzain announce
# or pass --announce on a decide call (fires once per process)
```

Identity only — **names**, never prompts or `gateway.json` — POSTs to
`POST /api/v1/registry/announce` with `source: "grokbot"`. Rows land in
`grokbot-announce:{instance}#agent:{id}` behind the standard sealed
registration gate. Pick a stable `instance` name (no `#`). Announce is
telemetry, not a gate: it never blocks or delays the Decision call.
Transient failures (network, 5xx, 429) retry on a later gated call; a 4xx
refusal means config — fix and restart.

## Pull enroll (default on)

The first gated `decide` call also POSTs identity to
`POST /api/v1/registry/enroll` (`source: "grokbot"`). The reply names the
adapter (`tool_gate`) and never returns a `cnxe_` unless you pass a
one-shot token from Govern / the snippet pack:

```bash
grokbot-artzain enroll --enroll-token "$ENROLL_TOKEN"
# or GROKBOT_ENROLL_TOKEN on the enroll command
```

`GROKBOT_ENROLL=false` or `--no-enroll` skips it. Enroll never blocks or
delays the Decision call. `decide` does not redeem `enroll_token` — that
is the enroll command, so the key can print once on stdout.
