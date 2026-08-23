# `@cognexuslabs/n8n-nodes-artzain`

n8n community nodes that wrap CogNEXUS **Decision** (pattern A) and
**Envelope** (pattern B) so operators do not hand-assemble JSON.

## Nodes

| Node | What it does |
|---|---|
| **CogNEXUS Decision** | `POST /api/v1/decisions`. Three outputs: Allow / Review / Deny. HTTP 503 / 401 / 422 land on **Deny**. Review does **not** wait inside n8n — a human owns it in the dashboard Review Queue. Wire side effects only to Allow. |
| **CogNEXUS Envelope** | `POST /api/v1/envelope/v1/chat/completions` with a `cnxe_…` key. Screens model traffic. It does **not** gate a later Stripe/Gmail node. |

## What this is not

- Not a Connectors-panel card named n8n.
- Not published to npm from this repository. Dest
  (`CogNEXUSlabs/cognexus-tools`) holds Trusted Publishing. Until that
  package is tagged, install from a git checkout.
- Not a Wait node that pretends CogNEXUS `review` resolved inside n8n.
- Not an OpenClaw community node. OpenClaw Chat nodes drive the Gateway;
  this package sits in front of *your* side effects.

## Install (from a CogNEXUS checkout)

```bash
cd sdk/n8n && npm ci && npm run build
```

In n8n: **Settings → Community nodes → Install from npm** is the published
path. Until dest publishes, point n8n at this folder per n8n's custom-node
docs (`N8N_CUSTOM_EXTENSIONS`, or `npm pack` + install the tarball).

Credential for Decision: Header `X-Api-Key` = sandbox key from `/get-a-key`.
**Not** a dashboard JWT. Envelope uses `Authorization: Bearer cnxe_…`.
