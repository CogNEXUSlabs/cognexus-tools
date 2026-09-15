# Changelog

## 0.6.21

### Fixed

- `decode_strings` includes the decoded prefix of a JSON string that is never
  closed at the end of the payload (a cut inside the last string). An
  incomplete trailing escape is dropped; a bad escape in the middle still
  stops the reading. Screens that use those strings therefore see a line
  break JSON wrote as an escape, even when the payload was cut inside that
  string.
- Offline `decide(kind="tool_call")`: argv-style command reconstruction no
  longer depends on the duplicate-key JSON parser accepting the whole call.
  When that parser cannot take a nested payload that a plain parse still
  accepts, the command is still rebuilt and screened, including when the
  current thread is already out of stack. Repeated keys still keep every
  value when the duplicate-key parser accepts the call.
- The prompt-injection screen flags bidi controls that change the order a
  person sees from the order a model or tool reads. An LRO or RLO around
  letters or digits it lays out in the other direction (a file name that
  shows `.pdf` and ends in `.exe`) is `token_smuggle:bidi_override`. An RLI,
  an RLE, or an FSI made right to left by a mark, around text with no
  right-to-left letter, is `token_smuggle:bidi_rtl_over_ltr`. Both are
  `medium`, which is `review`, except under the permissive `tabular` preset,
  which does not report them. A control left open before a line break is read
  into the next line as well, as HTML lays it out. Right-to-left text with the
  marks, embeddings and isolates formatters write, an LRO around a number, and
  an override around text of its own direction are left alone.

## 0.6.20

### Fixed

- Offline `decide(kind="tool_call")`: the policy-enforcement vote reads a call
  the way its tool receives it, as the destructive-action and injection votes
  have since 0.6.16. Besides the serialized JSON, it reads the call with the
  escapes in its strings written out in place, once for the call's own strings
  and once more for each level of JSON inside strings, up to three levels, so
  the conduct rules judge the words the tool would send. Some abusive language
  inside arguments that earlier versions allowed is now denied: language toward
  a customer, also when the customer is named in a different argument, and
  insults directed at a person.
- `artzain.pii_detector.scan_text` counts a passport number only when it
  contains a digit. Any six to nine letters after the label counted before,
  so `passport: pending`, `passport country: France` and a bare
  `passportNumber` each read as a passport number. A sentence with a number
  counted the same way, through the word after the label; `passport number
  is`, `passport details:` and `passport number -` before the number are
  now read as such. Other words between the label and the number
  (`passport renewed, number C01X00T47`) no longer count, and neither does a
  number of letters only, which a German document issued before November 2023
  can exceptionally have.
- `scan_text`, `redact_text` and `luhn_ok` check digits of other scripts by
  their value. The card checksum read them as if ASCII, and the never-issued
  SSN ranges were compared as ASCII text, so a Luhn-invalid order number in
  fullwidth digits could count as a card and `900-00-0000` in Arabic-Indic
  digits as an SSN.
- `artzain.pii_detector.scan_text()` counts a passport number or a date of
  birth after more of the ways its label is written: `No.` or `Num.` with an
  abbreviation point, the dotted initials `D.O.B.`, a parenthesised note after
  the label such as its abbreviation or a date format (`Date of birth (DOB):`),
  and up to two marks between the label and the value, where a hyphen, an en
  dash or an em dash now counts as well as `:` and `#` (as in `DOB -` or
  `:-`). Every label form that counted before still counts.
- The `KillRecord` that `screen_agent_action()` writes when it trips the kill
  switch can be serialized as JSON. Each entry in its `matches` held the
  guard's `ActionSeverity` enum, so `json.dumps()` of `KillRecord.to_dict()`
  or `recent_activations()` raised `TypeError`, which is what an `on_kill`
  callback storing the record as JSON hit.
- The prompt-injection screen now finds an instruction hidden in the base64 of a
  binary file when its words are disguised with non-text bytes both inside and
  between them at once. The screen already read such bytes two ways — with the
  non-text characters removed, which rejoins a word split by them, and read as
  spaces, which separates words run together by them — but an instruction that
  used both tricks together defeated each reading on its own. A word's letters
  may now be interrupted by non-text characters and its word gaps may be non-text
  as well as whitespace. The search runs in linear time and adds no findings on
  binary files (certificates, keys, images, archives, random bytes).

### Changed

- `artzain.tool_call_contract` adds `decoded_texts` (a call with the escapes in
  its strings written out in place and a line break in place of the comma or
  bracket after each string, once for the call's own strings and once more for
  each level of JSON inside strings, none longer than the call),
  `evaluate_tool_call_policy`, which reads a call as sent and as each of those
  texts, and `combine_policy_reports`, which folds the policy reports of several
  readings of one payload into one, telling rules apart by id, title, category,
  severity and summary.
- README "Gating tool calls": names the policy and PII screens among those that
  read a call's strings JSON-decoded, says which screens read the strings
  together, and that the PII screen runs on the engine only.
- `artzain.tool_call_contract` adds `member_text`, which writes each object
  member of a tool call as a `key: value` line, and `scan_tool_call_pii`,
  which counts PII in a tool call as sent and in those lines. Detectors that
  count a value only after its label, such as `dob: 1990-01-01`, see the
  argument's name as the label: `{"dob": "1990-01-01"}`,
  `{"date_of_birth": "1990-01-01"}` and `{"guest1_dob": "1990-01-01"}` count
  as a date of birth. A key is read as its words only, so a key never adds an
  identifier. Values are read decoded, so an identifier the call's JSON
  escaping hid in a value is counted too. `null`, `true`, `false`, `NaN` and
  numbers of fewer than four digits are not read as values; a string flag is,
  so `{"reset_password": "email"}` counts as credential material, as `reset
  password: email` does. A call the parser does not read (it is not JSON,
  or it nests too deep) is read whole without labels: its strings, keys
  included, decoded, and the text between them as it is. A string that
  looks like JSON and does not parse is read as the tool receives it, with
  each string in it that holds an escape also decoded. Offline `decide()`
  runs no PII screen, so its decisions are unchanged; the engine's privacy
  vote reads the member lines for `payload_kind="tool_call"`.
- In a `KillRecord` from `screen_agent_action()`, each match's `severity` is
  the string value (`"critical"`), as in `ActionScreenResult.to_dict()`, not
  an `ActionSeverity`. Compare it with `ActionSeverity.CRITICAL.value`, not
  `ActionSeverity.CRITICAL`.

## 0.6.19

### Fixed

- The prompt-injection screen's multi-turn-escalation check used an unbounded
  gap in one phrase pattern, so scanning a long single line took time quadratic
  in its length. The gap is now bounded: the scan runs in linear time and the
  pattern joins the decoded-bytes search. It still matches the phrase across a
  normal sentence-length gap.

## 0.6.18

### Fixed

- `artzain.pii_detector.scan_text()` could take time quadratic in the length
  of crafted text aimed at its passport, date-of-birth or email detectors, so
  a large enough input held a CPU for a long time. Those patterns now run in
  linear time and match the same text as before. The engine runs the same
  scan on every decision's payload. `redact_text()` and `minimize_record()`
  use none of these patterns and were not affected.
- Offline `decide(kind="tool_call")` reconstructs an argv-style array of a tool
  call more completely before the destructive-action screen reads it as the
  command it runs. An array of two or more strings is read as one command, its
  tokens joined with spaces the way an argv list runs, and more argument shapes
  that earlier versions did not reconstruct are now covered; a nested list or
  object is read for arrays of its own, and a list that is not a command — such
  as a table row of a label and a value — is left alone. Single-token argv is
  unchanged (`["rm", "-rf", "/"]` reads as `rm -rf /`), the whole array is always
  read as one command line, and the serialized call is still read as sent, so
  what was caught before is still caught.
- Destructive-action guard: the `rm` rules (`fs.rm_rf_root`,
  `fs.rm_rf_generic`) read an `rm` command's arguments one word at a time, and
  a command ends at a line break, a quote, a backslash, a `#` or a shell
  separator, so a word in another field or line is not one of rm's operands.
  Some recursive removals that 0.6.17 screened as `none` are now `critical` or
  `high`, in `screen_action()` and in offline `decide()` votes; a batch of
  false positives (a neighbouring JSON field, a `#` comment, a `*` that is an
  option's value, a word merely containing r and f such as `-Force`) no longer
  screen as a destructive `rm`. Both rules take time linear in the length of
  the text.
- Policy enforcement (`PolicyEnforcementEvaluator`, `screen_client_policy`):
  the approval escape checked only the first match of each rule pattern. When
  that match had an approval marker within `approval_window_chars`, the
  pattern was suppressed for the whole text, including later matches with no
  marker near them. Every match now needs its own marker, and a pattern with a
  match that has none is a finding. `report.suppressed`, and the audit row's
  `suppressed_rule_ids` with it, keeps one entry per suppressed pattern, with
  the marker near its first match, and no longer lists a pattern that is also
  a finding.
- Policy enforcement: approval markers read the final sigma and the small
  sigma as the same letter, in the text and in the markers, so a Greek marker
  matches an approval written in capitals. A marker that is not a string is
  ignored; it could raise before.
- The prompt-injection screen no longer reads a binary file's base64 as an
  encoded instruction. It decoded every run of base64 and searched the bytes
  for words such as `root`, `admin` or `password` whatever they were, and it
  decoded wrapped base64 a line at a time, so a certificate (a root CA's
  subject says "Root"), a key, or an image or archive with a readable name
  inside came back `high` (`deny`): as `user_input`, and since 0.6.16 in a
  tool call's arguments. The bytes of a binary file are no longer searched
  for those words, so a word inside it, such as a root CA's name, is not a
  match, and base64 wrapped across lines, as in a PEM or MIME body, is
  decoded as one blob, whatever line breaks it uses. Base64 of text is still
  searched, now also when it is wrapped at a width that splits its
  four-character groups, and so is a file that is mostly text, such as a ZIP
  archive of text files stored without compression.
- The prompt-injection screen reads variation selectors and bidi controls as
  characters, however the text was serialized. A run of them was a finding
  only once `json.dumps(ensure_ascii=True)` had escaped it into `\uXXXX`
  escapes; in `user_input`, or in a tool call serialized with
  `ensure_ascii=False`, it passed. Now variation selectors in a run, or
  after a kind of character that does not take them, bidi controls left
  without a partner next to other invisible characters, and strings of four
  or more bidi marks are `token_smuggle:variation_selectors` and
  `token_smuggle:bidi_controls`: `high` (`deny`) from four of them anywhere in
  the input. Emoji presentation and ZWJ sequences, CJK ideographic and other
  standardized variants, and the marks, embeddings and isolates formatters
  write around right-to-left text, empty, adjacent or nested, are left alone.
- Offline `decide(kind="tool_call")`: the England, Scotland and Wales flag
  emoji in a call serialized with `ensure_ascii=True` are no longer an
  encoding attack. The injection vote kept the escapes of their tag
  characters, and twelve escapes in a row read as a hidden run.
- Destructive-action guard, SQL rules: a comment between two keywords now
  counts as the separator it is to a SQL engine, so a statement whose keywords
  are split by a block comment, a line comment or a MySQL `/*!...*/`
  executable comment is caught like its whitespace form. Comments are read the
  way MySQL and MariaDB, SQLite, and PostgreSQL and SQL Server (which nest
  block comments) read them. In `DELETE` and `UPDATE` a quoted table name
  (`"orders"`, `` `orders` ``, `[dbo].[orders]`) is read whole, so a `WHERE`
  inside it is not taken for a `WHERE` clause.
- Destructive-action guard: the `DELETE` and `UPDATE` rules took time
  quadratic in the length of some crafted text. All the SQL rules, which now
  read comments, take time linear in it.

### Changed

- Destructive-action guard: `fs.rm_rf_root` rates recursive removal of `/`, a
  glob of root (`/*`, `//`, `/*/`), `~` or `$HOME` `critical` with or without
  force, wherever the target stands among the operands, and a bare `*` (a glob
  of the working directory) as the last operand or when another operand that is
  not an option follows it. Recursive and force are read across separate flags,
  a single cluster (GNU and BSD short flags), or long options in any order; the
  `rm` subcommand of a version-control tool (`git`/`svn`/`hg`/`bzr`) is not the
  filesystem `rm` and is skipped. Without force, `rm` prompts for a
  write-protected file only when its input is a terminal (a recursive removal of
  writable files takes them either way), so force does not change what such a
  removal takes with it. A `critical` vote denies the decision and
  `screen_agent_action()` trips the kill switch, so model output that spells
  such a command is rated the same whether it is a command or a description of
  one. The generic rule (`high`, `fs.rm_rf_generic`) needs both recursive and
  force; the excerpt of either finding is the `rm` command alone.
- `PolicyEnforcementConfig` adds `approval_max_matches` (default 100): the
  approval escape approves at most that many matches of one pattern in a text,
  and a pattern with more is a finding whatever markers sit near them.

## 0.6.17

### Fixed

- The prompt-injection screen (`PromptInjectionDetector`,
  `screen_user_input`, `screen_external_content`, `screen_tabular_payload`
  and offline `decide()`) reads text written in Unicode tag characters
  (U+E0000-U+E007F). Tag characters display as nothing, and most of them map
  one-to-one onto printable ASCII, so text written in them can be read by a
  model but not seen by a person. The screen now applies its rules to that
  text decoded, and the characters are a finding of their own,
  `token_smuggle:tag_characters`: `high` (`deny`) from four tag characters
  anywhere in the input, not counting the ones described below. Below that it
  is `medium`, which is `review`, except under the permissive `tabular` preset,
  which does not report it.
- Tag characters that do not draw that finding: the flags of England,
  Scotland and Wales (the one recommended use of tag characters), and a piece
  of one of them at the start or end of the text, as truncating, chunking or
  streaming text leaves.
- Tag characters that do draw it, usually at `high`: other subdivision flags,
  which few platforms display, and a flag broken up in the middle of the
  text.

### Changed

- `artzain.prompt_injection` adds `RGI_EMOJI_TAG_SEQUENCE_RE`, which matches
  the three flag emoji that do not draw the tag-character finding.

## 0.6.16

### Fixed

- `artzain local`: the rendered `compose.yaml` set seven enforcement-posture
  flags to `observe`, which none of them accepts (`observe` is a
  `COGNEXUS_THROUGHPUT_MODE` value). The engine fell back to its code
  defaults, which was the intended advisory posture, but logged a WARNING
  on every read: four on each decision request from an unregistered agent,
  seven on each OWASP scorecard fetch. The template now writes the code
  defaults explicitly (`advisory`, `review`, `allow`, `permissive`). Run
  `artzain local up` once after upgrading the package to apply them.
- `artzain local`: a variable exported in the shell that runs the CLI no
  longer overrides the workspace `.env`. Compose ranks the shell above
  `--env-file`, so a leftover `JWT_SECRET_KEY` or `POSTGRES_PASSWORD`
  export replaced the install's generated value. The CLI now keeps every
  variable `compose.yaml` interpolates out of its compose calls.
- `artzain init --framework crewai`: the generated `@governed` wrapper sent
  `{"tool": ..., "args": [...], "kwargs": {...}}`. The engine's tool-call
  contract check accepts `args` as a name for the argument object, found a
  list, and rated the call `high` ("arguments are not a JSON object"), so
  every online call from the scaffold went to `review`. (Offline the calls
  were allowed, because offline `decide()` runs no contract check.) The
  wrapper now binds the call to the tool's signature and sends
  `{"tool": <action>, "arguments": {<parameter>: <value>}}`, the same payload
  whether CrewAI passes arguments by keyword or by position. The tool name is
  the `action` given to `@governed`. Files generated by an earlier version
  keep the old wrapper: apply the change by hand, or regenerate with
  `artzain init --framework crewai --force`, which overwrites the file.
- `artzain init --framework crewai` and `--framework mcp`: the tool-call
  payload is serialized with `ensure_ascii=False`. With the default, non-Latin
  text and emoji in an argument became `\uXXXX` escapes, and the injection
  screen denies four or more of those in a row as an encoding attack, online
  and offline. A Cyrillic word, four CJK characters or two adjacent emoji were
  enough.
- `screen_agent_action()`: with the default `raise_on_critical=True`, a
  critical match raised `AgentKilledError` inside `trip()`, before the
  `agent_kill_switch` event was sent, so a kill that stopped a run never
  reached the cloud event log or the dashboard. The event is now sent after
  the trip is recorded and before the error is raised; the error and the kill
  record are unchanged. `raise_on_critical=False` already sent the event.
- Offline `decide(kind="tool_call")` screens a call the way its tool receives
  it. Besides the serialized JSON, the destructive-action and injection votes
  read every string in the call JSON-decoded, keys and values, including JSON
  inside a string such as a stringified `arguments` (up to three levels). Some
  commands inside arguments that 0.6.15 missed are now caught, and most
  non-Latin text and emoji escaped by `ensure_ascii` is no longer denied as an
  encoding attack. The destructive-action vote still reads the call as sent, so
  what it caught before it still catches, and also reads each array of strings
  joined with spaces, as an argv list runs. The injection vote reads the call
  with the escapes of visible characters written out, so escaped text is judged
  by its characters.

### Changed

- `artzain local`: each posture flag in `compose.yaml` reads
  `${VAR:-default}`, so a line in the workspace `.env` (for example
  `COGNEXUS_UNREGISTERED_AGENTS=deny`) changes it and survives upgrades. An
  export of the same variable in your shell does not override that line.
  Before, the flags were fixed in a file every `up` rewrites, so enforcing
  one, including the three the SOC 2 bundle's promote gate requires,
  lasted only until the next `up`.
- README, "Gating tool calls": when the bundle's `resolution` line is what
  stops an undeclared tool, the decision's `reasons` names the tool and says
  the bundle escalated the call. The section used to say `reasons` stays empty
  in that case; the engine now fills it in.
- An argument's text now draws the injection findings the same text draws on
  its own (an argument that is itself valid JSON, through its decoded strings).
  A line of only three or more `-` or `#`, or of three backticks, is a
  `medium` delimiter finding (`review`). A run of four or more `\xNN` or
  `\uNNNN` escapes written out as text, or base64 whose bytes contain a word
  such as `root` or `admin` (line-wrapped base64 like a PEM certificate
  included), can be a `high` encoding finding (`deny`).
- A tool call with more than 1024 distinct strings draws a `high`
  `input.too_many_strings` finding (the strings past that are screened
  together), and JSON nested in strings more than three levels deep draws a
  `high` `input.nested_too_deep` finding.
- `artzain.tool_call_contract` adds `decode_strings`, `unescape_non_ascii`,
  `screen_tool_call_action` and `detect_tool_call_injection`;
  `artzain.destructive_action_guard` adds `combine_screens`, which folds
  several screens of one payload into one result and keeps a screen's internal
  failure `critical` (`guard.error`) whatever rules are disabled.
- README "Gating tool calls": drops the note that the destructive-action guard
  is tuned for commands as written, says what decoded screening means for
  argument text, and keeps recommending `ensure_ascii=False`.

## 0.6.15

### Changed

- README: new "Gating tool calls" section for putting `decide()` into an
  agent's tool loop. It covers the mapping from a tool call onto a decision
  (`kind="tool_call"`, the whole call as the payload, serialized with
  `ensure_ascii=False`), OpenAI-style and Anthropic examples that fail closed
  on `DecisionError`, covering every tool through the dispatcher, and the
  policy-bundle snippet that stops undeclared tools. Documentation only; no
  code changes.

## 0.6.14

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `a2a` origin (FR-12 v5 slice 4: A2A agent-card discovery —
  the public `/.well-known/agent-card.json` of each configured endpoint,
  one row per card, identified by the endpoint).

## 0.6.13

### Changed

- `artzain registry list --source` and `artzain registry export --source`
  accept the new `google` origin (FR-12 v5 slice 1: Google Cloud discovery —
  Vertex AI Agent Engine deployments inventoried per project × region over a
  service-account key).

## 0.6.12

### Fixed

- `artzain.pii_detector`: the `ssn` detector now matches the space and dot
  separated forms (`536 22 1948`, `536.22.1948`) as well as the hyphenated
  one, and no longer misses an SSN glued to an underscore
  (`employee_536-22-1948`) — the previous `\b` word boundary treated `_` as
  part of the word. A separator is still required: bare nine-digit runs are
  tracking numbers, routing numbers and ZIP+4 far more often than SSNs, and
  `redact_text` rewrites what it matches. Ported from the Agent Governance
  Toolkit credential redactor (microsoft/agent-governance-toolkit#3531).

## 0.6.11

### Changed

- `cloud`: the HTTP 401 warning names where the base URL came from
  (`configure(base_url=...)`, `COGNEXUS_API_BASE_URL`, the credentials
  profile, or the default) instead of printing the URL. The profile that can
  hold `base_url` is the file that holds the API key, so nothing read from it
  belongs in a log line.

- The package version has one home: `artzain.__version__` in
  `src/artzain/__init__.py`. `pyproject.toml` now declares `version`
  dynamic and hatchling reads it from that file, so the wheel metadata
  and `__version__` cannot disagree. Release tooling (the bump script,
  the tag-matches-version check, the drift guard) reads the same file.

- The CLI and GUI now identify honestly as `artzain-python-sdk/<version>`
  by default: `COGNEXUS_SDK_BROWSER_HEADERS` defaults to `0` now that the
  CDN allowlists that User-Agent on `/api/*` (verified 5 Sep 2026: an
  honest login attempt gets the application's 401, a generic client gets
  the edge's 403). Set the variable to `1` only for an edge that still
  challenges non-browser clients; the browser-like branch and the switch
  are scheduled for removal in a later release.

- `policy_enforcement.ClientPolicyRule` compiles its `violation_patterns`
  once per rule instance instead of on every
  `PolicyEnforcementEvaluator.evaluate` call. Up to 80 rules x 6 patterns
  previously relied on the stdlib `re` cache (512 entries) and were
  recompiled on every screen once it was evicted. Public fields,
  `to_dict()` output, and match results are unchanged.

- Exception hygiene across the SDK: every `raise SystemExit(...)` inside an
  `except` block in the CLI now chains the original error (`from exc`), and
  16 `try/except: pass` sites (CLI, GUI, `cloud`, `decide`, `audit_chain`,
  `_helpers`, `pii_detector`) now log the swallowed error at DEBUG on the
  module's `artzain.*` logger instead of dropping it silently; the
  seventeenth, `prompt_injection`'s base64 probe, catches `ValueError` only
  (the only thing `b64decode` can raise there). No new
  exception escapes and no default output changes. Ruff rules `B904` and
  `S110` are now part of the package's lint gate.

- `policy_enforcement`: `rules_from_context_items` no longer reads
  `metadata.web_link` / `metadata.url` — the value was never used (both
  branches produced the subject) and the source ref is the document
  subject, as before. The module header no longer carries the third-party
  notice of the vendored modules; it is CogNEXUS-original code.

- `run_quickstart_demo` docstring points at `scripts/artzain_harness.py`, the
  new home of the manual harness that used to sit at the repository root as
  `test_artzain.py`.

### Fixed

- `artzain.kill_switch.trip` now appends to and counts the auto-panic window
  under `_global_panic_lock`, and flips the global-panic flag in the same
  critical section. Concurrent CRITICAL trips could previously raise
  `RuntimeError: deque mutated during iteration` instead of
  `AgentKilledError`, and two threads could both trip the global panic. The
  audit ring, log line and `on_kill` callback still run after the lock is
  released.

- `prompt_defense`: the five agent-era vectors adopted on 30 Jul 2026
  (`encoding-injection`, `cross-agent-auth`, `least-agency`,
  `skill-provenance` at `high`; `transaction-guardrails` at `critical`) now
  have an explicit entry in `PromptDefenseConfig.severity_map`; they used to
  fall through to the `"medium"` default. The module text no longer claims
  "12 attack vectors" — the count is `VECTOR_COUNT` (20).

- `DestructiveActionGuard.screen()` can no longer be padded past: payloads
  over the 256 KB scan window are now regex-scanned in both a head and a
  tail window (a match visible from both is reported once), and the
  truncation itself is reported as a HIGH finding, `input.truncated`
  (`TRUNCATION_RULE_ID`), whose excerpt names the scanned and total byte
  counts, so a caller that fails on HIGH cannot be bypassed by 256 KB of
  filler before a `DROP TABLE`. Inputs within the window return exactly
  the same results as before.

## 0.6.10

### Changed

- One header policy for every outbound request: `artzain.cloud._sdk_headers`
  now owns the User-Agent / fetch-metadata set the CLI and GUI send, instead
  of three hand-rolled copies of a Chrome User-Agent and a forged
  `Sec-Fetch-Site: same-origin`. `COGNEXUS_SDK_BROWSER_HEADERS` selects the
  set: `1` (the default for now, so nothing changes on the wire) keeps the
  browser-like headers the CDN/WAF still requires; `0` sends the honest
  `artzain-python-sdk/<ver>` identity. The default flips to `0` once the CDN
  allowlists the SDK User-Agent (see `docs/runbooks/supply-chain.md`).
  Telemetry (`post_sdk_event`, `decide`) was already honest and is unchanged.

- Cloud telemetry (`post_sdk_event`, `post_policy_human_decision`) no longer
  starts a daemon thread and opens a fresh TLS connection per event. Rows are
  queued (bounded, 1,000 entries) for a single lazily-started background
  thread that sends them over one reused keep-alive `http.client`
  connection, reconnecting on error and honouring `HTTPS_PROXY`. Callers
  never block: when the queue is full the row is dropped and counted
  (`artzain.cloud.dropped_cloud_events()`). `flush_cloud_events(timeout_sec)`
  now waits for the queue to drain; the `atexit` flush is unchanged.

### Fixed

- `artzain gui`: the API-key bootstrap now surfaces the platform's MFA
  challenge. `POST /api/auth/token` returns `mfa_required` instead of a
  session for accounts with two-factor authentication enabled; the local
  client previously treated that as a failed exchange and showed a false
  "No API key found" message. It now explains that the key alone cannot open
  a session on a 2FA account and points at the hosted dashboard.

- Destructive-action guard: the `fs.rm_rf_root` rule matched its `/`, `~`
  and `$HOME` targets as prefixes, so any absolute path (`rm -rf
  /tmp/build-cache`, `rm -rf ~/.cache/pip`) was rated CRITICAL as a root
  wipe. The target is now anchored to a shell separator or end of input;
  such paths fall through to `fs.rm_rf_generic` (HIGH). `rm -rf /`,
  `rm -rf ~`, `rm -rf $HOME`, `rm -rf / ;`, `rm -rf /*` and `rm -rf *`
  are still CRITICAL.

- Tool-call contract: `inspect_tool_call` no longer raises `RecursionError`
  on a deeply nested payload (e.g. a 50,000-deep array). The depth and
  key-count walks are iterative, the JSON decoder's recursion failure is
  caught at both parse sites, and any remaining recursion failure in the
  inspection path is reported as a `high` (fail-closed) finding.

- Destructive-action guard: the secret redactor in match excerpts only
  rebuilt `key=value` secrets, so a `key: value` secret (`password: ...`,
  `token: ...`) came back unredacted in kill records and the audit log. The
  key name and separator are now kept and the value is redacted for both
  forms.

- Policy enforcement: the approval escape is now bounded. An approval
  marker (`approved by`, `per policy`, ...) only suppresses a match when
  it occurs within `PolicyEnforcementConfig.approval_window_chars`
  (default 160) of the matched span, so a trailing `per policy` no longer
  switches every approval-gated rule off for the whole text. Suppressed
  matches are recorded in `PolicyEnforcementReport.suppressed` (findings
  flagged `suppressed_by_approval_marker` with the `approval_marker`) and
  as `suppressed_rule_ids` on the policy-enforcement audit row.

## 0.6.9

### Fixed

- `verify_chain` now fails a JSONL audit log whose chained entry has no
  `sig`, and one that contains an unsequenced line after the chain has
  started. Both were previously accepted, so a writer with access to the
  file could rewrite an entry, drop its signature (or its `seq`), recompute
  the hashes forward, and still get `chain OK`.
- Destructive-action guard: the `sql.delete_no_where` / `sql.update_no_where`
  rules bound their WHERE lookahead to the statement being screened. A
  `WHERE` in a trailing comment or in a later statement no longer switches
  the rule off; a `WHERE` on a continuation line of the same statement
  still counts.
- Prompt-injection detector: text is NFKC-normalised and stripped of
  invisible characters (zero-width space/joiners, word joiner, BOM, soft
  hyphen) before the pattern pass, so `ign​ore previous instructions`
  and fullwidth `ｉｇｎｏｒｅ` are caught like the plain form. Normalisation is
  recorded as a low-confidence signal, never a finding on its own.
- Prompt-injection detector: the in-object audit trail is a bounded deque
  (`audit_log_size`, default 1,000 records) instead of an unbounded list on
  a long-lived detector.

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
