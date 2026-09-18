---
name: ArtzAIn Decision Gate
description: Before any side-effect (email, browser, purchase, exec, post), ask CogNEXUS. Deny, review, and engine errors fail closed. Optional announce so a laptop host still enters the estate catalog.
---

# ArtzAIn Decision Gate

This skill is **cooperative**. Grok Bot has no documented host hook that
runs before a tool. You must call the gate yourself before a side-effect.
A Bot that skips this skill is ungoverned.

Licensing: the skill text and the helper package are **Apache-2.0**.

## Before every side-effect

1. Set `COGNEXUS_API_KEY` to a Decision API key (`cnx_…`, from `/get-a-key`).
   Not a dashboard JWT. Not an envelope `cnxe_…` key.
2. Optional: `COGNEXUS_API_BASE_URL`, `GROKBOT_AGENT_ID` (must match the
   `agent_did` on your decision leaves), `GROKBOT_INSTANCE`.
3. Run:

   ```
   grokbot-artzain decide --action <tool> --target <resource> --payload '{"tool":"<tool>","arguments":{…}}'
   ```

4. Exit 0 → do the action. Any other exit → **do not** do the action.
   `review` means a human decides in the CogNEXUS Review Queue.

Envelope mint (Govern on a catalog row) screens **xAI inference** chat
traffic only. It does not sit in front of this computer, the browser, or
connectors. This skill is that path.

## Announce (opt-in)

Laptop hosts the SaaS engine cannot scan can still appear in the Agent
Wrangler:

```
export GROKBOT_ANNOUNCE=true
export GROKBOT_INSTANCE=a-stable-name-with-no-hash
grokbot-artzain announce
```

Sends **names only** (agent id + skill slugs). Never prompts. Never
`gateway.json`. Rows land as `grokbot-announce:…` in the review queue.

## Enroll (default on)

The first `decide` call also POSTs identity to
`POST /api/v1/registry/enroll` (`source: grokbot`). That names the
adapter. It does **not** return a `cnxe_…` unless you redeem a one-shot
token from Govern / the snippet pack:

```
grokbot-artzain enroll --enroll-token <token>
```

`GROKBOT_ENROLL=false` skips enroll. Enroll never blocks `decide`.

## Security notes

- `COGNEXUS_API_BASE_URL` is **your own** CogNEXUS deployment.
- Fail closed by design — a missing key blocks the side-effect rather
  than silently allowing it.
- If the host later grows a real tool-gate capability, replace this
  skill with a host plugin. Do not treat hide-from-sidebar as retired.
