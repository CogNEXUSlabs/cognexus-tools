# Changelog

## 0.6.8

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `openclaw` origin (FR-12 v3 Wave D part 2: OpenClaw
  gateway probe — instance agents listed via the gateway's
  OpenAI-compatible `/v1/models` surface).

## 0.6.7

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `n8n` origin (FR-12 v3 Wave D part 1: n8n agentic
  workflow discovery — AI-cluster and ArtzAIn-gated workflows).

## 0.6.6

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `agentforce` origin (FR-12 v3 Wave C: Salesforce
  Agentforce / Einstein Bot discovery over the existing Salesforce
  connection).

## 0.6.5

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `foundry` origin (FR-12 v3 Wave B part 2: Microsoft
  Foundry / Azure AI Foundry per-project agent discovery).

## 0.6.4

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `anthropic` origin (FR-12 v3 Wave A: Anthropic / Claude
  estate discovery — workspaces, API-key inventory, the Claude Code fleet
  row, and Managed Agents).

## 0.6.3

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  now accept the v2 discovery origins `openai`, `code_scan`, and
  `langgraph`, matching the engine's catalog API (FR-12 v3 Wave 0). The
  CLI had been stuck at the v1.5 origin list, so entries from the three
  v2 sources could not be filtered from the terminal.

## 0.6.2

### Fixed

- `artzain local create-admin` could hang forever instead of creating the
  admin. On Windows `getpass` reads the console device rather than
  `sys.stdin`, so with stdin piped or absent — CI, ssh without a tty,
  scripted installs: the exact headless contexts the command exists for —
  it waited on a keyboard that was not there. A new `--password-stdin`
  flag reads the password from the first line of stdin (`docker login`
  style), and without the flag every password prompt in the CLI
  (`quickstart` sign-up and `local activate` sign-in included) now falls
  back to reading stdin whenever no real console is attached — including
  the `< NUL` redirect that fools `isatty` on Windows. Validation is
  unchanged: under 8 characters still exits 2 with the same message.

## 0.6.1

### Fixed

- A malformed `COGNEXUS_API_KEY` is no longer echoed in full. `artzain
  quickstart` reported an unusable key as `invalid or unreachable
  (<key>…)`, truncating to 14 characters — but the fallback for a value
  shorter than that printed the whole thing, so a mistyped key reached
  terminal scrollback and CI logs verbatim. Anything too short to spare a
  prefix now reads `redacted`; `artzain gui` masks its 8-character
  auto-login hint the same way. Well-formed keys display exactly as
  before. Found by CodeQL on the public SDK mirror.

## 0.6.0

### Added

- `artzain local` — the self-serve in-boundary installer (installer plan
  WS-B). `up` renders a `~/.cognexus` workspace from the stable-channel
  manifest (every image pinned **by digest**, including the postgres base),
  generates real secrets once — and repairs a partial `.env` in place rather
  than ever overwriting values — starts the stack, waits for `/health`, and
  hands off to the `/welcome` first-run page. `doctor` prints one remedial
  sentence per failed check (`--port` handles a busy 8080 without editing
  any file); `status` shows health, trial days remaining, and update
  availability; `upgrade` streams a binary `pg_dump` to `backups/` and
  refuses to proceed without it; `down --purge` (and its alias `reset`)
  demands the install id typed back — persisted at up-time so the guard
  holds even with the stack stopped; `create-admin` is the headless first
  run; `activate` verifies and installs a licence certificate, signing in
  with your dashboard email when no API key is configured — the path that
  keeps an expired trial convertible.
- Mutating `local` commands take a workspace lock, so two concurrent `up`s
  cannot split the generated secrets between `.env` and the database volume.

## 0.5.2

### Added

- The GUI renders Roger's clarify cards ("Did you mean one of these?"):
  when a message nearly matches a platform action, the engine now answers
  with an `action_card` of type `clarify`, and each option is a button that
  sends its canonical phrase as an ordinary message. Before this, such a
  card displayed as a dead "pending" stub with no options. The GUI's card
  builder is pinned to the dashboard's by `scripts/check_roger_dock.mjs`
  in the engine repo, so the surfaces cannot drift silently again.

## 0.5.1

A maintenance release: no behaviour changes. It exists because PyPI is
immutable and `scripts/check_sdk_version.py` refuses a tree that differs from
the published 0.5.0 under the same number.

### Changed

- The package is now linted in CI (`ruff`, E/F/W/I). Five modules changed to
  satisfy it — unused imports removed, import blocks sorted, ambiguous `l`
  loop variables renamed — with no change to any public name or behaviour.
- The README opens with what the package does: the local guards are free and
  offline; `decide()` asks an engine for a governed decision; `audit verify`
  and `licence verify` check evidence offline with three verdicts, and today
  every bundle verifies `SELF-ATTESTED` because the Evidence Root is not yet
  pinned. The guard library documentation follows unchanged.

## 0.5.0

The licence CLI and the rotation-aware verifier. Both were written before
0.4.0 was cut and neither reached PyPI, so 0.4.0 users have a verifier that
cannot read a key handover and no `artzain licence` command at all.

### Added

- **`artzain licence`** — the client half of the offline licence flow:
  `request`, `install`, `attest`, `anchor`, `anchors`, `verify`. Everything
  works on files, with no network at any point. That is a requirement rather
  than an optimisation: a sovereign or air-gapped install exports an
  attestation, a person carries it out on whatever medium they already use,
  and it is verified on the other side.
- **`artzain.licence`** — the module behind it. CSRs, anchor records, Sealed
  Usage Attestations, and three-verdict verification matching the audit
  verifier (`VERIFIED, ATTESTED` / `VERIFIED, SELF-ATTESTED` / `FAILED`).
- **Signing-key handovers in `audit verify`.** A bundle that spans a key
  rotation now carries `key-rotations.json`: countersigned records binding a
  retiring key to its successor. The verifier checks both signatures against
  the public keys carried *inside each record*, not through `keys.json`, so an
  edited bundle cannot choose which of its own claims get inspected.
- `audit verify --json` reports `rotations_checked` and `unexplained_key_ids`.

### Changed

- A bundle whose signed manifest commits `key_ids` now fails if `keys.json` is
  missing one of them. Deleting a key was previously invisible, and it silently
  skipped whatever check would have resolved that key.
- `verify_bundle` reports, without failing, a key that signed records in the
  bundle when no sound handover names it. Reported rather than fatal because a
  second process legitimately signs with its own key — but it is also the shape
  a substitution takes, so the reader gets to decide.

### Compatibility

Bundles exported before any of this still verify exactly as they did. A
handover the bundle cannot check — a key absent from `keys.json`, or
`cryptography` not installed — is reported, never fatal: a supplementary
custody claim must not collapse the verdict for an otherwise intact chain.

## 0.4.0 and earlier

Not recorded here. See the git history on
[CogNEXUSlabs/cognexus-tools](https://github.com/CogNEXUSlabs/cognexus-tools).
