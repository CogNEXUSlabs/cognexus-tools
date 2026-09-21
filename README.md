# cognexus-tools

Client SDKs for the CogNEXUS / Artzain decision engine.

This is the **public home** of every CogNEXUS client package. The decision
engine itself lives in a separate private repository and dual-homes copies
for CI and guard-sync until those jobs move here.

| Package | Install | What it is |
|---|---|---|
| **`artzain`** | `pip install artzain` | Python SDK — local guards, `decide()`, CLI (`login`, `quickstart`, `audit`, `policy`, `registry`) |
| **`@cognexuslabs/artzain`** | `npm i @cognexuslabs/artzain` | TypeScript SDK — remote-only Node client (`decide`, events, identity) |
| **`@cognexuslabs/openclaw-artzain`** | `npm i @cognexuslabs/openclaw-artzain` | OpenClaw `before_tool_call` plugin (deny / review / errors block; not `/approve`) |
| **`@cognexuslabs/n8n-nodes-artzain`** | `npm i @cognexuslabs/n8n-nodes-artzain` | n8n Decision + Envelope nodes (fail closed on HTTP 503; `review` does not Wait) |
| **`@cognexuslabs/grokbot-artzain`** | `npm i @cognexuslabs/grokbot-artzain` | Grok Bot cooperative Decision skill, opt-in announce, and pull enroll (no host intercept) |

All five are Apache-2.0.

Putting `decide()` into an agent's tool loop (OpenAI or Anthropic)? Start at
[Gating tool calls](#gating-tool-calls).

```
python/       # PyPI package artzain (Hatchling src-layout)
typescript/   # npm package @cognexuslabs/artzain
openclaw/     # npm package @cognexuslabs/openclaw-artzain
n8n/          # npm package @cognexuslabs/n8n-nodes-artzain
grokbot/      # npm package @cognexuslabs/grokbot-artzain
```

Engine dual-home paths (private repo): `pypi-package/`, `sdk/typescript/`,
`sdk/openclaw/`, `sdk/n8n/`, `sdk/grokbot/`. Seed with `scripts/seed_cognexus_tools.sh` from
the engine tree.

## Python (`artzain`)

```bash
pip install artzain
# optional extras:
pip install "artzain[verify]"   # offline Ed25519 signature verification
pip install "artzain[policy]"   # policy bundle signing (keygen/sign)

export COGNEXUS_API_KEY=cnx_…
artzain login
artzain quickstart
```

```python
import artzain

d = artzain.decide(
    action="send_email",
    target="crm:contact:123",
    payload=draft_email_text,
    kind="model_output",
)
if d["outcome"] == "allow":
    actually_send()
```

Zero mandatory runtime dependencies. Offline `decide()` runs the same local guards when no API key is set (`offline: true`, no audit seal).

See [`python/README.md`](python/README.md) for guards, CLI, and extras.

## Gating tool calls

`artzain` does not hook your LLM client, and nothing intercepts tool calls
automatically. You place `decide()` in the gap between the model proposing a
tool call and your code executing it. That gap is the control point.

```text
user input ──► screen_user_input() ──► model ──► tool call ──► decide() ──► execute
```

| `decide()` argument | Comes from |
|---|---|
| `action` | the tool name the model chose |
| `target` | the resource the call touches, read out of the arguments |
| `payload` | the whole call as JSON: `{"tool": <name>, "arguments": {…}}` |
| `kind` | `"tool_call"`: shape and contract checks on the engine, plus the destructive-action guard |

Only `allow` runs the tool; `review` means a human decides first. `decide()`
raises `DecisionError` on any non-2xx response or when the engine cannot be
reached. Treat that as `deny`. The destructive-action, injection, policy and
PII screens read the serialized call, and every string in it as the tool
receives them: JSON-decoded, including JSON inside a string such as a
stringified `arguments`. The destructive-action screen reads each string on
its own; the others read the strings together, so one argument can change the
result for another. The conduct rules count a client word in any value of the
call; an argument or tool name counts only when it holds the profanity as
well. The PII screen runs on the engine only. A line of only `---` or three
backticks in an argument comes back `review`; inline base64 or escape
sequences written out as text can come back `deny`. Parse arguments with a
strict JSON parser and send the parsed call, as the examples do. The
destructive-action screen also reads a list of strings joined, as an argv list
runs, but a command a tool assembles from separate fields (a `cmd` beside its
`args`) is not seen whole: screen that command inside the step as well
(`screen_agent_action()`).

**OpenAI-style.** Tool calls arrive as a `tool_calls` array and
`function.arguments` is a JSON string. Append the assistant message before the
tool results that answer it.

```python
import json
import artzain

msg = client.chat.completions.create(model=..., messages=messages, tools=tools).choices[0].message
messages.append(msg)

for tc in msg.tool_calls or []:
    name = tc.function.name
    try:
        args = json.loads(tc.function.arguments)
    except json.JSONDecodeError:
        args = None

    if not isinstance(args, dict):
        d = {"outcome": "deny"}  # unparseable arguments: never run them
    else:
        try:
            d = artzain.decide(
                action=name,
                target=str(args.get("id") or args.get("to") or "unknown")[:300],
                payload=json.dumps({"tool": name, "arguments": args}, ensure_ascii=False),
                kind="tool_call",
            )
        except artzain.DecisionError:
            d = {"outcome": "deny"}  # the engine did not decide: fail closed

    result = dispatch(name, args) if d["outcome"] == "allow" else f"Not run ({d['outcome']})."
    messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(result)})
```

**Anthropic.** Tool calls arrive as `tool_use` content blocks and
`block.input` is already a dict. Answer every block with a `tool_result`,
denied ones included: the API requires the pair, and a model told it was
blocked usually re-plans instead of retrying the same call.

```python
import json
import artzain

resp = client.messages.create(model=..., messages=messages, tools=tools, max_tokens=1024)

results = []
for block in (b for b in resp.content if b.type == "tool_use"):
    try:
        d = artzain.decide(
            action=block.name,
            target=str(block.input.get("id") or block.input.get("to") or "unknown")[:300],
            payload=json.dumps({"tool": block.name, "arguments": block.input}, ensure_ascii=False),
            kind="tool_call",
        )
    except artzain.DecisionError:
        d = {"outcome": "deny"}  # the engine did not decide: fail closed

    allowed = d["outcome"] == "allow"
    results.append({
        "type": "tool_result",
        "tool_use_id": block.id,
        "content": str(dispatch(block.name, block.input)) if allowed else f"Not run ({d['outcome']}).",
        "is_error": d["outcome"] == "deny",
    })

if resp.content:
    messages.append({"role": "assistant", "content": resp.content})
if results:
    messages.append({"role": "user", "content": results})
```

Serialize with `ensure_ascii=False`, as both examples do. Escaped, each
non-ASCII character takes six characters of the payload limit (twelve above
U+FFFF, as for most emoji). Offline screens before artzain 0.6.16, and engines
without this change, read a run of those escapes as an encoding attack; current
screens still do when the escaped characters are invisible.

**Cover every tool, not every call site.** Put `decide()` in the one function
your agent dispatches tools through, so a tool added later is gated by
construction. Then make forgotten tools stop: declare the known ones in your
team's policy bundle and escalate the finding an undeclared tool draws.

```json
"guard_config": {
  "tool_contracts": {
    "send_email": { "required_args": ["to"] },
    "*": { "deny_unknown_tools": true }
  },
  "resolution": { "medium": "review" }
}
```

Without the `resolution` line an undeclared tool is only an advisory finding,
and the line escalates every `medium` vote, not just this one. `reasons` names
the tool and says the bundle escalated the call; a batch's other findings are
on the `tool-call-contract` vote in `contributing_agents`. Contracts are checked
only for `kind="tool_call"`, on a running engine with the bundle active
(`artzain local up` is enough). Offline, with no API key, `decide()` runs the
local guards only: `offline: true`, nothing sealed, no shape check, no bundle.
A call allowed offline can come back `review` or `deny` once you connect.

The full guide covers `decide()` versus `screen_agent_action()`, where
intent-level gating stops, and choosing what to gate:
[cognexuslabs.ai/install#tool-calls](https://cognexuslabs.ai/install#tool-calls).

## TypeScript (`@cognexuslabs/artzain`)

```bash
npm install @cognexuslabs/artzain   # Node >= 18, zero runtime dependencies
```

```ts
import { configure, decide, DecisionError } from "@cognexuslabs/artzain";

configure({ apiKey: process.env.COGNEXUS_API_KEY });

const decision = await decide({
  action: "send_email",
  target: "crm:contact:123",
  payload: draftEmailBody,
});
```

Remote-only: a missing API key throws. Use the Python SDK where offline guard parity matters.

See [`typescript/README.md`](typescript/README.md).

## OpenClaw (`@cognexuslabs/openclaw-artzain`)

```bash
npm i @cognexuslabs/openclaw-artzain
openclaw plugins install ./openclaw
```

The plugin registers `api.on("before_tool_call", …)` and calls
`POST /api/v1/decisions`. `deny`, `review`, and transport errors set
`{ block: true }`. It does **not** map CogNEXUS `review` onto OpenClaw
`/approve`. ClawHub listing is dest Trusted Publishing, not a tag from
the engine repo.

See [`openclaw/README.md`](openclaw/README.md).

## n8n (`@cognexuslabs/n8n-nodes-artzain`)

```bash
npm i @cognexuslabs/n8n-nodes-artzain
```

Two nodes:

- **Artzain Decision** — `POST /api/v1/decisions` with Allow / Review / Deny outputs. HTTP 503 fails closed. `review` is a third output, not an n8n Wait node.
- **Artzain Envelope** — `POST /api/v1/envelope/v1/chat/completions` with an envelope credential (`cnxe_…`). Not the Decision API.

See [`n8n/README.md`](n8n/README.md).

## Grok Bot (`@cognexuslabs/grokbot-artzain`)

```bash
npm i @cognexuslabs/grokbot-artzain
```

Cooperative skill (pattern C): Grok Bot has no host `before_tool_call`
intercept. Copy [`grokbot/SKILL.md`](grokbot/SKILL.md) into the Bot's skills
folder, or run `grokbot-artzain decide` before a side-effect. `deny`,
`review`, and transport errors fail closed. Opt-in announce and default-on
pull enroll are in [`grokbot/README.md`](grokbot/README.md).

## Development

Python (3.10–3.12):

```bash
cd python
pip install pytest httpx cryptography pyyaml
PYTHONPATH=src pytest tests/ -q
```

TypeScript (Node ≥ 18):

```bash
cd typescript
npm ci
npm run build   # tsc → dist/
npm test        # vitest
```

OpenClaw plugin, n8n nodes, and Grok Bot skill:

```bash
cd openclaw && npm ci && npm test && npm run build
cd ../n8n && npm ci && npm test && npm run build
cd ../grokbot && npm ci && npm test && npm run build
```

## Releases

- Python: push tag `python-v<version>` (must match `__version__` in `python/src/artzain/__init__.py`; `pyproject.toml` reads it from there). Publishes through a PyPI **Trusted Publisher** — no token, and each artifact carries a PEP 740 attestation. Do not add a `password:` to the publish step: an unset secret still takes the OIDC path at the pinned action version, so the line sits harmless until someone sets the secret — and then the release silently becomes a token publish with no attestation.
- TypeScript: push tag `sdk-ts-v<version>` (must match `typescript/package.json`). Publishes through npm **Trusted Publishing** (OIDC) — no token; npm generates the provenance itself, and `npm audit signatures` verifies it.
- OpenClaw plugin: push tag `openclaw-v<version>` (must match `openclaw/package.json`).
- n8n nodes: push tag `n8n-v<version>` (must match `n8n/package.json`).
- Grok Bot skill: push tag `grokbot-v<version>` (must match `grokbot/package.json`).
- All four npm packages publish through the same `publish-npm.yml` (npm **Trusted Publishing**, OIDC, no token) — each package's npmjs.com binding names that one workflow file. The **first** publish of a new package is an owner bootstrap, because npm only binds a trusted publisher to a package that already exists; the steps live in the engine repo's `scripts/cognexus-tools-seed/APPLY.md`. Do not publish from the engine repo, and never use a bare `v*` tag here.

Nothing publishes from a developer machine (WS-8): the tag is the release, and
the workflows here hold the only credentials involved.

## Security

Please see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. Portions of the Python guards are derived from
[microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
(MIT); notices are in [LICENSE](LICENSE) and the vendored source files.
