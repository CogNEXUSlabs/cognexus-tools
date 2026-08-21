# cognexus-tools

Client SDKs for the CogNEXUS / Artzain decision engine.

This is the public home of:

| Package | Install | What it is |
|---|---|---|
| **`artzain`** | `pip install artzain` | Python SDK — local guards, `decide()`, CLI (`login`, `quickstart`, `audit`, `policy`, `registry`) |
| **`@cognexuslabs/artzain`** | `npm i @cognexuslabs/artzain` | TypeScript SDK — remote-only Node client (`decide`, events, identity) |

Both are Apache-2.0. The decision engine itself lives in a separate private repository.

```
python/       # PyPI package artzain (Hatchling src-layout)
typescript/   # npm package @cognexuslabs/artzain
```

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

## Releases

- Python: push tag `python-v<version>` (must match `python/pyproject.toml`). Publishes through a PyPI **Trusted Publisher** — no token, and each artifact carries a PEP 740 attestation. Do not add a `password:` to the publish step: an unset secret still takes the OIDC path at the pinned action version, so the line sits harmless until someone sets the secret — and then the release silently becomes a token publish with no attestation.
- TypeScript: push tag `sdk-ts-v<version>` (must match `typescript/package.json`). Needs `NPM_TOKEN` on the `@cognexuslabs` npm scope, published with `--provenance`.

Nothing publishes from a developer machine (WS-8): the tag is the release, and
the workflows here hold the only credentials involved.

## Security

Please see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. Portions of the Python guards are derived from
[microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
(MIT); notices are in [LICENSE](LICENSE) and the vendored source files.
