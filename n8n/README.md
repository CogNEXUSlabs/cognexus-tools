# `@cognexuslabs/n8n-nodes-artzain`

n8n community nodes that wrap CogNEXUS **Decision** (pattern A) and
**Envelope** (pattern B) so operators do not hand-assemble JSON.

## Nodes

| Node | What it does |
|---|---|
| **CogNEXUS Decision** | `POST /api/v1/decisions`. Three outputs: Allow / Review / Deny. HTTP 503 / 401 / 422 land on **Deny**. Review does **not** wait inside n8n — a human owns it in the dashboard Review Queue. Wire side effects only to Allow. |
| **CogNEXUS Envelope** | `POST /api/v1/envelope/v1/chat/completions` with a `cnxe_…` key. Screens model traffic. It does **not** gate a later Stripe/Gmail node. |

## Request ID (Decision node)

The Decision node's **Request ID** field is the server's idempotency key.
Leave it empty and the node derives `n8n-<executionId>-<item>` — unique per
n8n execution, so two runs of the same workflow never share a key (0.1.1 and
earlier sent `n8n-<item>-<action>`, which was identical for item 0 of every
execution and could replay another run's sealed verdict). Set it explicitly
to your own business key — an order id, an invoice number — when you *want*
server-side replay across retries: the server returns the prior decision for
the same request id for **48 hours** without re-evaluating the payload, so
never reuse a key for a different customer or amount. Max 64 characters.

How the fallback is built (`fallbackRequestId` in `src/decision.ts`): for
each item the node reads the **Request ID** parameter (`requestId`); when it
is empty it calls n8n's `this.getExecutionId()` and sends
`n8n-<executionId>-<item>` (execution id trimmed, `<item>` the zero-based
item index). If the running n8n does not expose `getExecutionId`, or it
returns an empty or blank string, a random UUID stands in for the execution
id — `n8n-<uuid>-<item>` — so the key is still unique per call. Either way
the value is cut to the server's cap of 64 characters before it is sent as
`request_id`.

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
