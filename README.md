# cognexus-tools

Client SDKs for the CogNEXUS / Artzain decision engine.

This is the **public home** of every CogNEXUS client package. The decision
engine itself lives in a separate private repository and dual-homes copies
for CI and guard-sync until those jobs move here.

| Package | Install | What it is |
|---|---|---|
| **`artzain`** | `pip install artzain` | Python SDK — local guards, `decide()`, CLI (`login`, `quickstart`, `audit`, `policy`, `registry`) |
| **`@cognexuslabs/artzain`** | `npm i @cognexuslabs/artzain` | TypeScript SDK — remote-only Node client (`decide`, events, identity) |
| **`@cognexuslabs/openclaw-artzain`** | `npm i @cognexuslabs/openclaw-artzain` (checkout until the first release) | OpenClaw `before_tool_call` plugin (deny / review / errors block; not `/approve`) |
| **`@cognexuslabs/n8n-nodes-artzain`** | `npm i @cognexuslabs/n8n-nodes-artzain` (checkout until the first release) | n8n Decision + Envelope nodes (fail closed on HTTP 503; `review` does not Wait) |

All four are Apache-2.0.

```
python/       # PyPI package artzain (Hatchling src-layout)
typescript/   # npm package @cognexuslabs/artzain
openclaw/     # npm package @cognexuslabs/openclaw-artzain
n8n/          # npm package @cognexuslabs/n8n-nodes-artzain
```

Engine dual-home paths (private repo): `pypi-package/`, `sdk/typescript/`,
`sdk/openclaw/`, `sdk/n8n/`. Seed with `scripts/seed_cognexus_tools.sh` from
the engine tree.

## Python (`artzain`)

```bash
pip install artzain
# optional extras:
pip install "artzain[verify]"   # offline Ed25519 signature verification
pip install "artzain[policy]"   # policy bundle signing (keygen/sign)

export COGNEXUS_API_KEY=cgnx_…
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

Install from a checkout until a dest tag publishes it:

```bash
openclaw plugins install ./openclaw
```

The plugin registers `api.on("before_tool_call", …)` and calls
`POST /api/v1/decisions`. `deny`, `review`, and transport errors set
`{ block: true }`. It does **not** map CogNEXUS `review` onto OpenClaw
`/approve`. ClawHub listing is dest Trusted Publishing, not a tag from
the engine repo.

See [`openclaw/README.md`](openclaw/README.md).

## n8n (`@cognexuslabs/n8n-nodes-artzain`)

Install from a checkout until a dest tag publishes it. Two nodes:

- **Artzain Decision** — `POST /api/v1/decisions` with Allow / Review / Deny outputs. HTTP 503 fails closed. `review` is a third output, not an n8n Wait node.
- **Artzain Envelope** — `POST /api/v1/envelope/v1/chat/completions` with an envelope credential (`cnxe_…`). Not the Decision API.

See [`n8n/README.md`](n8n/README.md).

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

OpenClaw plugin and n8n nodes:

```bash
cd openclaw && npm ci && npm test && npm run build
cd ../n8n && npm ci && npm test && npm run build
```

## Releases

- Python: push tag `python-v<version>` (must match `__version__` in `python/src/artzain/__init__.py`; `pyproject.toml` reads it from there). Publishes through a PyPI **Trusted Publisher** — no token, and each artifact carries a PEP 740 attestation. Do not add a `password:` to the publish step: an unset secret still takes the OIDC path at the pinned action version, so the line sits harmless until someone sets the secret — and then the release silently becomes a token publish with no attestation.
- TypeScript: push tag `sdk-ts-v<version>` (must match `typescript/package.json`). Publishes through npm **Trusted Publishing** (OIDC) — no token; npm generates the provenance itself, and `npm audit signatures` verifies it.
- OpenClaw plugin: push tag `openclaw-v<version>` (must match `openclaw/package.json`).
- n8n nodes: push tag `n8n-v<version>` (must match `n8n/package.json`).
- All three npm packages publish through the same `publish-npm.yml` (npm **Trusted Publishing**, OIDC, no token) — each package's npmjs.com binding names that one workflow file. The **first** publish of a new package is an owner bootstrap, because npm only binds a trusted publisher to a package that already exists; the steps live in the engine repo's `scripts/cognexus-tools-seed/APPLY.md`. Do not publish from the engine repo, and never use a bare `v*` tag here.

Nothing publishes from a developer machine (WS-8): the tag is the release, and
the workflows here hold the only credentials involved.

## Security

Please see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. Portions of the Python guards are derived from
[microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
(MIT); notices are in [LICENSE](LICENSE) and the vendored source files.
