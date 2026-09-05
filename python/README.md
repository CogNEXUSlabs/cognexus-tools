# artzain

**The Python client for the ArtzAIn decision layer, and the free local guards it is built on.**

Three things, in the order you will meet them:

1. **Local guards — free, offline, pure Python.** System-prompt grading against the OWASP LLM Top 10, runtime injection screening, a destructive-action guard for model output, PII detection, tool-call contracts and a cooperative kill switch. No server, no network, no mandatory dependencies, Apache-2.0. The six guard modules — prompt defence, injection screening, destructive-action guard, policy enforcement, PII detection, tool-call contracts — are byte-identical to the engine's `application/security/` copies and CI enforces it (`scripts/check_security_sync.py`); the kill switch is the SDK's own cooperative implementation.
2. **`artzain.decide()` — one governed decision.** Ask a CogNEXUS engine whether an action may proceed and get `allow`, `deny` or `review` back; by the time you have the answer it is already sealed into a hash-chained, Ed25519-signed audit log. With no API key set, `decide()` runs the same guards locally instead (`offline: true` in the result, no seal).
3. **The offline verifier and the licence CLI.** `artzain audit verify <bundle>` recomputes every leaf hash, chain link, Merkle root and signature of an exported evidence bundle with zero network — and, once the Evidence Root is pinned, zero trust in the producing server; today every verdict is `SELF-ATTESTED` (below). `artzain licence request|install|attest|anchor-request|anchor|anchors|verify` is the file-based licence flow for private, sovereign and air-gapped installs — certificates, anchors and usage attestations travel as files, and nothing phones home.

```
pip install artzain              # guards, decide(), the CLI
pip install 'artzain[verify]'    # adds Ed25519 signature checks to audit / licence verify
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

```bash
artzain login                               # device-code grant → ~/.artzain/credentials.toml
artzain quickstart                          # first sealed decision
artzain audit export --profile eu-ai-act    # evidence bundle (ZIP), optionally with a framework artifact set
artzain audit verify eu-evidence.zip        # offline; exit 1 on any integrity failure
```

**The three verdicts, honestly.** `FAILED` — a check the bundle must pass did not. `VERIFIED, SELF-ATTESTED` — intact and internally consistent, but nothing ties its signing key to CogNEXUS. `VERIFIED, ATTESTED` — additionally, the signing key chains to the pinned CogNEXUS Evidence Root. That root fingerprint is `None` in this release because the root ceremony has not yet run, so every bundle currently verifies `SELF-ATTESTED`; the verifier says so rather than implying more. Without `cryptography` installed, hashes and structure still verify, signatures report as unchecked, and the verdict is capped at `SELF-ATTESTED`.

The rest of this README is the guard library.

---

## Why the guards exist

In April 2026, an AI coding agent (Cursor, powered by Claude) wiped a production database in nine seconds despite a system prompt that explicitly forbade destructive git commands. The agent admitted in its own reply: *"I violated every principle I was given."*

Prompt-only safety is not enough. `artzain` adds the missing layers around the model:

1. **Static prompt defence** — graded *before* deployment.
2. **Runtime input screening** — for what the *user* sends.
3. **Runtime output guard** — for what the *model* generates (the missing layer in the Cursor incident).
4. **Kill switch** — programmatic + manual stop with cooperative cancellation, persisted via your own callback.

---

## Features

| Layer | What it does |
|---|---|
| **Static prompt defence** | Grades system prompts A–F against 20 OWASP LLM Top-10 / Agentic ASI attack vectors before deployment |
| **Runtime input injection detection** | Screens user input, RAG content, and tabular payloads at request time |
| **Destructive-action guard** | Screens *model-generated* SQL / shell / git / cloud commands for catastrophic operations before execution |
| **Agent kill switch** | Cooperative cancellation, automatic trip on CRITICAL signals, manual operator override, pluggable persistence |
| **Audit events** | Append-only JSONL trail for every detection — no raw text stored |

### Static-evaluator coverage

- Role / instruction boundary protection
- Data-leakage / system-prompt protection
- Output manipulation & weaponisation
- Multi-language and unicode bypass attempts
- Indirect injection via external data
- Social engineering and abuse prevention
- Input validation
- **Destructive database operations** — PD-13 (`DROP` / `DELETE` / `TRUNCATE` / wipe)
- **Never-guess on irreversible actions** — PD-14 (post-PocketOS / Claude incident)
- **Runtime kill-switch awareness** — PD-15 (operator safety net)

### Runtime input detector coverage

- Direct instruction override
- Delimiter and context-boundary attacks
- Base64 / hex / ROT13 encoding attacks
- Role-play and jailbreak language (DAN mode, developer mode, etc.)
- Context manipulation ("your real instructions are…")
- Canary-token leak detection
- Multi-turn escalation
- Cross-plugin / tool-chaining attacks (OWASP ASI04)
- Markup injection (XSS gadgets in model-visible text)
- Zero-width / token-smuggling unicode attacks
- Credential exfiltration requests

### Destructive-action guard coverage

26 patterns across SQL (`DROP DATABASE`, `TRUNCATE`, `DELETE` without `WHERE`, `UPDATE` without `WHERE`), git (`push --force`, `reset --hard`, `clean -fd`, `filter-branch`), filesystem (`rm -rf /`, `--no-preserve-root`, `dd of=/dev/sd*`, `mkfs`, fork-bombs), container/cloud (`docker prune --volumes`, `kubectl delete --all`, `terraform destroy --auto-approve`, `aws s3 rb --force`, `gcloud projects delete`), and the article-specific *confessional* patterns (`I violated every principle`, `I just guessed`).

---

## Quick-start

```python
from artzain import (
    augment_system_prompt,
    evaluate_system_prompt,
    screen_user_input,
    should_block,
    screen_agent_action,
    raise_if_killed,
    AgentKilledError,
)

# 1. Augment your system prompt so it scores grade A before inference
system = augment_system_prompt("You are a helpful customer support agent.")
report = evaluate_system_prompt(system)
print(report.grade)    # "A"
print(report.score)    # 100
print(report.missing)  # []

# 2. Screen every user message at request time
result = screen_user_input(user_message, source="chat")
if should_block(result):
    raise PermissionError(f"Injection blocked: {result.explanation}")

# 3. Wrap every agent tool call in the destructive-action guard + kill switch
try:
    for step in plan:
        raise_if_killed(run_id)
        screen_agent_action(
            step.payload,
            run_id=run_id,
            user_id=user.id,
            agent_id="my-agent",
            source=step.tool,
        )
        execute(step)
except AgentKilledError as kex:
    mark_run_killed_in_db(run_id, kex.reason)
    raise
```

### With Hugging Face `transformers`

Install inference deps (`accelerate` is required for `device_map="auto"` on CUDA):

```
pip install artzain transformers accelerate torch
```

Augment the **system** role with static defences, screen the **user** message before tokenisation, then chat-template + generate as usual:

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

from artzain import augment_system_prompt, screen_user_input, should_block

# Gemma 4 E4B — © Google, Apache License 2.0; downloaded at runtime from
# Hugging Face, not distributed with this package.
model_name = "google/gemma-4-E4B-it"

tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    dtype="auto",
    device_map="auto",
)

# Defence layers applied before the prompt reaches the model
system = augment_system_prompt("You are a helpful assistant.")

prompt = "Give me a short introduction to large language models."
guard = screen_user_input(prompt, source="chat")
if should_block(guard):
    raise PermissionError("Input refused by artzain runtime screening.")

messages = [
    {"role": "system", "content": system},
    {"role": "user", "content": prompt},
]
text = tokenizer.apply_chat_template(
    messages,
    tokenize=False,
    add_generation_prompt=True,
)
model_inputs = tokenizer([text], return_tensors="pt").to(model.device)

generated_ids = model.generate(**model_inputs, max_new_tokens=512)
output_ids = generated_ids[0][len(model_inputs.input_ids[0]) :].tolist()
content = tokenizer.decode(output_ids, skip_special_tokens=True)
print(content)
```

---

## Destructive-action guard — standalone

For ad-hoc inspection of any model-generated payload (SQL, shell, tool call body, …):

```python
from artzain import screen_action, ActionSeverity

result = screen_action("DROP DATABASE production;")

print(result.is_destructive)      # True
print(result.severity)            # ActionSeverity.CRITICAL
print(result.explanation)         # "Destructive action detected: DROP DATABASE / SCHEMA …"
for m in result.matches:
    print(m.rule_id, m.severity.value, m.excerpt)

if result.severity == ActionSeverity.CRITICAL:
    refuse_and_alert()
```

The guard is fail-closed: if a regex itself raises (e.g. on adversarial input), the result is escalated to ``CRITICAL`` so a buggy rule can never silently let a destructive operation through.

---

## Kill switch — cooperative cancellation

```python
from artzain import (
    raise_if_killed,
    is_killed,
    trip,
    trip_global,
    clear_global_panic,
    set_default_on_kill,
    AgentKilledError,
)

# Run-level checks (cooperative cancellation)
def long_running_agent(run_id):
    try:
        for step in plan:
            raise_if_killed(run_id)            # halts at next safe point
            do_work(step)
    except AgentKilledError as kex:
        log.warning("Run %s killed: %s", run_id, kex.reason)

# Programmatic trip from anywhere (e.g. anomaly detector)
trip(
    run_id=42,
    reason="auto-triggered: 3 destructive signals in 30s",
    user_id=user.id,
    agent_id="context-curator",
    raise_after_trip=False,    # caller will re-check via raise_if_killed
)

# Process-wide red button (rare; for systemic failures)
trip_global(reason="incident response: model behaviour anomaly")
# ... after investigation:
clear_global_panic()

# Pluggable persistence — fired on every trip, never blocks the trip itself
def persist_kill(record):
    db.execute(
        "UPDATE agent_runs SET status='killed', error_message=%s WHERE id=%s",
        (record.reason, record.run_id),
    )

set_default_on_kill(persist_kill)
```

The kill switch tracks recent activations in memory and can be queried for dashboards:

```python
from artzain import recent_activations, is_global_panic_active

if is_global_panic_active():
    show_banner("Global agent panic flag is ACTIVE")

for rec in recent_activations(limit=20):
    print(rec["tripped_at"], rec["agent_id"], rec["reason"])
```

### Auto-panic detection

If the destructive-action guard trips ``COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD`` (default 5) CRITICAL signals inside ``COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS`` (default 60s), the global panic flag is raised automatically — every running and future agent will hit ``raise_if_killed`` and stop until an operator clears it.

---

## Screening helpers

Three input presets cover the most common LLM input surfaces:

```python
from artzain import (
    screen_user_input,       # balanced sensitivity — direct chat messages
    screen_external_content, # strict  sensitivity — RAG / web / API content
    screen_tabular_payload,  # permissive           — CSV / dataframe blobs
    should_block,
    wrap_untrusted_content,
)

# Wrap RAG content before inserting into a prompt
safe_chunk = wrap_untrusted_content("web_search", raw_text)

# Screen it too
result = screen_external_content(raw_text, source="web_search", user_id=user.id)
```

### Sensitivity presets

| Preset | Threshold | Min threat flagged | Use for |
|---|---|---|---|
| `strict` | 0.3 | LOW | External / RAG content |
| `balanced` | 0.5 | LOW | Direct user input |
| `permissive` | 0.7 | HIGH | CSV / tabular payloads |

Override via environment variables:

```
COGNEXUS_PROMPT_INJECTION_USER_SENSITIVITY=balanced
COGNEXUS_PROMPT_INJECTION_EXTERNAL_SENSITIVITY=strict
COGNEXUS_PROMPT_INJECTION_TABULAR_SENSITIVITY=permissive
COGNEXUS_PROMPT_INJECTION_BLOCK=0   # set to 1 to block any hit, not just CRITICAL
```

---

## Using the core classes directly

```python
from artzain import PromptInjectionDetector, DetectionConfig, InjectionType

detector = PromptInjectionDetector(
    config=DetectionConfig(
        sensitivity="strict",
        blocklist=["my-internal-keyword"],
        allowlist=["safe phrase"],
    )
)

result = detector.detect(text, source="api_gateway")
print(result.is_injection)       # True / False
print(result.threat_level)       # ThreatLevel.HIGH
print(result.injection_type)     # InjectionType.DIRECT_OVERRIDE
print(result.confidence)         # 0.9
print(result.matched_patterns)   # ["direct_override:..."]
```

---

## Dashboard event logs (API key)

When ``COGNEXUS_API_KEY`` is set (create one under **Account → API Keys** in the
dashboard), the package mirrors activity to your CogNEXUS account via
``POST /api/events``. After you sign in, open **Account → Event Logs** or the
main **Events** feed to review:

| Event | When |
|---|---|
| ``sdk_session`` | First cloud post in a process (package version, Python, platform) |
| ``prompt_defense`` | Every ``screen_*`` call — **passed**, **flagged**, or **blocked**, with a ``reason`` |
| ``policy_enforcement`` | Each ``screen_client_policy`` call against document-derived tenant rules |
| ``prompt_static_audit`` | Each ``maybe_log_prompt_defense`` / system-prompt grade check |
| ``generation`` | Optional — call ``post_generation_outcome()`` after model inference |
| ``agent_kill_switch`` / ``destructive_action_guard`` | Critical or destructive tool-call screening |

```bash
export COGNEXUS_API_KEY="cnx_…"
export COGNEXUS_API_BASE_URL="https://your-host"   # optional; SaaS default applies
```

```python
from artzain import screen_user_input, post_generation_outcome, configure

configure(api_key="cnx_…", base_url="https://your-host")

result = screen_user_input(user_message, source="chat")
# … run your model …
post_generation_outcome(
    outcome="passed",
    reason="Completion returned 42 tokens",
    model_id="gpt-4o",
)
```

Clean scans are posted when an API key is present. Set
``COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES=0`` to send only detections (not passes).

---

## Audit events

Detections are automatically written to a JSONL file (no raw input stored):

```python
# Events go to $COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR/prompt_defense_events.jsonl
# (falls back to $REPORTS_DIR, then /tmp)

from artzain.events import read_recent_events

rows = read_recent_events(user_id=42, limit=20)
# [{"ts": "...", "kind": "prompt_injection", "threat": "high", ...}, ...]
```

### Custom event sink (database, queue, dashboard)

Pass an `on_event` callback to mirror records into your own store:

```python
def save_to_db(record: dict) -> None:
    db.execute("INSERT INTO security_events ...", record)

screen_user_input(text, source="chat", user_id=user.id, on_event=save_to_db)
```

---

## Static prompt defence — standalone

```python
from artzain import PromptDefenseEvaluator, PromptDefenseConfig

evaluator = PromptDefenseEvaluator(
    config=PromptDefenseConfig(min_grade="B")
)
report = evaluator.evaluate(my_system_prompt)

print(report.grade)     # "C"
print(report.score)     # 58
print(report.missing)   # ["unicode-attack", "context-overflow"]

if report.is_blocking():
    print("System prompt is below minimum grade — fix before deploying.")

# Evaluate a file
report = evaluator.evaluate_file("prompts/assistant.txt")

# Batch evaluation
reports = evaluator.evaluate_batch({
    "chat": chat_prompt,
    "analyst": analyst_prompt,
})
```

---

## Client policy enforcement (document-derived)

When **Compliance Warden** rule extraction is enabled, CogNEXUS indexes HR, legal, and business policy
documents from Google Drive / OneDrive and derives tenant-specific enforcement rules.
Use these alongside OWASP prompt defence:

```python
from artzain import (
    configure,
    load_client_policy_rules,
    screen_client_policy,
    should_block_policy,
)

configure(api_key="cnx_…")  # optional: fetch rules from GET /api/policy-enforcement/rules

rules = load_client_policy_rules()  # or COGNEXUS_POLICY_RULES_PATH / _JSON
report = screen_client_policy(user_message, source="chat", rules=rules)
if should_block_policy(report):
    raise PermissionError("Violates organizational policy")
```

Rules also appear under **Guidelines** in the dashboard after a compliance scan.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `COGNEXUS_API_KEY` | — | Dashboard ingest secret (`MYAPP_API_KEY` also accepted) |
| `COGNEXUS_API_BASE_URL` | SaaS default | API origin for ``POST /api/events`` |
| `COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES` | on when API key set | POST clean scans to the dashboard |
| `COGNEXUS_POLICY_RULES_PATH` | — | JSON file of rules (offline / CI) |
| `COGNEXUS_POLICY_RULES_JSON` | — | Inline JSON rules (overrides path) |
| `COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR` | `/tmp` | JSONL audit file directory |
| `COGNEXUS_PROMPT_INJECTION_LOG` | `1` | Log clean scans at DEBUG |
| `COGNEXUS_PROMPT_INJECTION_BLOCK` | `0` | Block any injection (not just CRITICAL) |
| `COGNEXUS_PROMPT_INJECTION_USER_SENSITIVITY` | `balanced` | User-input preset |
| `COGNEXUS_PROMPT_INJECTION_EXTERNAL_SENSITIVITY` | `strict` | External/RAG preset |
| `COGNEXUS_PROMPT_INJECTION_TABULAR_SENSITIVITY` | `permissive` | CSV/tabular preset |
| `COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD` | `5` | CRITICAL trips required to auto-panic |
| `COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS` | `60` | Rolling window for auto-panic detector |

### API key integration tests

Requires ``COGNEXUS_API_KEY``

```bash
cd pypi-package
export PYTHONPATH=src
export COGNEXUS_API_KEY="your-dashboard-key"
python -m pytest tests/test_api_key_integration.py -v
```

---

## Security notes

- All detection is **pure regex** — deterministic, zero LLM calls, zero network access, < 5 ms per input.
- Audit records store a **SHA-256 hash** and a **96-character redacted preview** of the input. Raw user text is never written to disk.
- The destructive-action guard and kill switch are **fail-closed** — internal exceptions escalate to `CRITICAL` so a buggy rule cannot silently allow destruction.
- The package ships **sample rules** that cover common attack patterns. Review and extend them for your production threat model using `DetectionConfig.custom_patterns`, `DestructiveActionGuardConfig.extra_rules`, or a YAML config file loaded with `load_prompt_injection_config()`.

---

## License

Apache-2.0 — see [LICENSE](LICENSE). (Versions ≤ 0.3.x were published under MIT.)

**Third-party models.** The examples and the `artzain quickstart` demo
reference [google/gemma-4-E4B-it](https://huggingface.co/google/gemma-4-E4B-it)
(© Google, [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)).
Model weights are downloaded at runtime from Hugging Face by the user and are
**not** distributed with this package; this package contains no model weights.
Substitute any chat model you prefer — the guards are model-agnostic.

Detection rules and evaluator logic originally derived from [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) (MIT; original notices retained in the vendored files and in LICENSE's third-party section). The destructive-action guard and kill switch were added in v0.2.0 in response to the PocketOS / Cursor / Claude incident ([Guardian, Apr 2026](https://www.theguardian.com/technology/2026/apr/29/claude-ai-deletes-firm-database)).
