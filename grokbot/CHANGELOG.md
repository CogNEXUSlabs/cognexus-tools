# Changelog

All notable changes to `@cognexuslabs/grokbot-artzain`. Headings are the
bare version (`## 0.1.0`): the mirror's `publish-npm.yml` cuts the GitHub
release notes for tag `grokbot-v<version>` from the matching section.
From 0.1.10, a section starts with `Upgrade:` (`none`, `recommended` or
`required`) and `Needs:` (the minimum engine, or what a saved skill must
be), then `### Added`, `### Fixed` and `### Changed`. One bullet says
whether the command, the library or the skill text changed.

## 0.1.10

Upgrade: recommended
Needs: this engine's GET /api/v1/decisions/{decision_id}/review for review-status. A citation uses the Decision API's existing cites_review. Compare a saved skill again, because the skill text changed.

### Added

- **`grokbot-artzain coverage --since <ISO time>`.** It reads the shim log, the MCP gateway log, and the action journal, and it prints each action since that time that has no decision id. The time needs a timezone. A missing log is an empty source. A log that exists but cannot be read exits 2. It posts one action count per agent to `POST /api/v1/registry/coverage`. The key is not sent in that body. Exit 1 when any action has no decision id. Exit 0 when every action had one and the report was accepted. A shim that runs a command appends one JSON line to `shim.jsonl` (the time, the agent, `run_command`, the target, and the decision id). The line has no arguments and no key. Enforce mode appends nothing when it does not run the command.
- **`handleBeforeToolCall(event, ctx)`.** `gateToolCall(cfg, input, fetchImpl)` is unchanged. The new function maps a host `before_tool_call` event onto it. An allow returns nothing. Any other outcome returns `{ block: true, blockReason }`. It is ready for a host hook. This package does not register one.
- **`grokbot-artzain shims install` and `shims uninstall`.** Install is opt-in for one profile. It writes wrappers into `~/.local/bin` for `curl`, `wget`, `git`, `gh`, `npm`, `aws`, `ssh`, `scp`, and `rm`, and it edits no shell profile. Each wrapper asks for a decision with action `run_command` and runs the real binary, found on PATH with `~/.local/bin` left out, only when that decision allows it. Install starts in log-only mode, which records the decision and still runs the command. `--enforce` exits 126 for any other outcome. A full path or another interpreter skips the shim, and the box is shared, so the wrappers affect every agent there.
- **`--tool <connector name>` and `src/taxonomy.json`.** `decide --tool`
  maps a connector tool name onto a taxonomy action and a target
  (`slack:channel/C123`, `github:repo/Quantumskipper/CogNEXUS`). The action
  is the payload's `tool` field, which is what policy rules read. A name
  that is not listed is `unknown_tool`. `--action` still works and wins
  when both are given. `taxonomy.json` is in the published files.
- **`grokbot-artzain doctor`.** It checks Node against `engines`, the
  command on PATH (on Windows, `grokbot-artzain.cmd` and the PowerShell
  execution policy), this version against the latest on npm (`--offline`
  skips that), the installed skill text version against the package, the
  key (printed as `sha256:` and eight hex digits), that the base URL
  answers with no redirect, that the key is accepted, the agent id, and
  the enroll record. The key check is the enroll request, so it counts
  against the enroll limit, and it sends no decision request. A missing
  `GROKBOT_AGENT_ID` is a warning, since a Bot may pass `--agent-did` on
  each call. Text output is one `[ok ]`, `[WARN]` or `[FAIL]` line per
  check, with `->` and a one-line fix under each that is not ok. `--json`
  prints the checks. Exit 0 when no check failed, and exit 1 when one did.
  `SKILL.md` carries `Skill text version:` so the skill check has a
  version to compare.
- **`grokbot-artzain upgrade`.** It prints the install command for this
  copy and runs it only with `--yes`. The path of the binary selects a
  global npm install, a user prefix such as `~/.local`, or an npx command.
  On Windows the command is `npm.cmd`, and the output says to open a new
  shell. `--skill` copies the packaged `SKILL.md` onto a file after a
  one-line summary, and only with `--yes`. A path outside
  `~/.config/grokbot-artzain/skills` (on Windows,
  `%APPDATA%\grokbot-artzain\skills`) is refused unless `--force` is set.
  The command does not read or change environment variables or the key.
- **A decide names this command.** The request's `product` is
  `grokbot-artzain@` this version. When the account minimum is higher, the
  command prints `REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.`
  and exits 2. It does not ask again.
- **`SKILL.md` has "Where to run the gate".** The Bot runs `grokbot-artzain`
  on the Grok Bot box, with no `machineId`, even when the action itself
  targets a user computer. It decides on the box first. A fresh allow is
  what lets the action run, and the machine-targeted tool is only for that
  approved action.
- **`decide --payload-file -` reads the payload from standard input.** An
  empty or unreadable standard input exits 2 and the engine is not asked,
  the same as an empty or unreadable file. A Windows PowerShell 5.1
  here-string piped to the command is UTF-8 with a byte order mark, which
  the command accepts.
- **The decide line names `next_step` and `decision_id`.** `decide` still
  prints one JSON line and has no `--json` flag. `next_step` is `run` for
  an allow, `wait for review` for a review, and `do not run` otherwise.
  `decision_id` is its own field on every outcome that has a decision.
  `outcome`, `decision_id`, `error`, and the exit codes are unchanged.
- **`--cites-review <decision id>` and `grokbot-artzain review-status <decision id>`.**
  A decide sends the id as `context.cites_review`. Context is an idempotency
  input, so the re-ask is decided again. `review-status` prints `pending`,
  `approved`, or `rejected` for a decision this account made. It cannot
  change a review. Exit 0 from it is the status, not an allow.
- **`grokbot-artzain init --bot <name>`.** It saves a profile under
  `~/.config/grokbot-artzain/profiles` (on Windows,
  `%APPDATA%\grokbot-artzain\profiles`) with mode 0600. The file holds
  the agent id, the instance, the base URL, and the name of the
  environment variable that holds the key. The key is not stored. The
  write retries a rename Windows refuses, the same way the enroll state
  file does. `--profile <name>` or `GROKBOT_BOT` selects it. Flag, then
  environment, then profile, then the default. A decide with no agent id
  says so on stderr and uses `grokbot-agent`. `GROKBOT_REQUIRE_IDENTITY=1`
  exits 2 before any network call.
- **`grokbot-artzain skill --check <path>`.** It compares an installed copy
  of the skill with the one in this package. A save keeps the body, so the
  body ends with `Skill text for grokbot-artzain <version>`, the version in
  `package.json`. The same version says `current` and exits 0. An older one
  says `behind` and exits 1. `skill` with no option still prints the path
  of the packaged `SKILL.md`.
- **`announce` sends the current profile.** With no agent id and no
  `GROKBOT_ANNOUNCE_AGENTS`, the command sends the host's current profile
  (the agent directory named by `agents/active-agent.json`). `SAND_DATA_ROOT`
  sets that directory when it is an absolute path. `GROKBOT_ANNOUNCE_AGENTS`
  still names agents instead. `--all-profiles` sends every profile, in calls
  of at most 25. The time is recorded in `state.json`, and an agent announced
  within 24 hours is skipped unless `--force`. The key is not stored. A
  replayed announce of one agent and instance updates the one Catalog row.
- **`grokbot-artzain mcp`.** A stdio MCP server, and `--http --port <n>` on
  127.0.0.1. It implements `initialize`, `tools/list`, `tools/call` and
  `ping` with no extra dependency. `artzain_decide` returns the decision
  (`outcome`, `decision_id`, `reasons`, `next_step`, and `notice` when the
  engine sent one). Anything but `allow` is a failed tool call. An
  unreachable engine is a failure, and the tool is not run. `artzain_status`
  returns the version, agent id, instance, enroll state and an update
  notice, never the key. `artzain_review_status` reads
  `GET /api/v1/decisions/{decision_id}/review`. The server only sees calls
  made to `artzain_decide`. `plugin/manifest.json` is a placeholder: the
  Grok Bot plugin manifest format was not found.
- **`decide --queue`, `queue list`, and `queue retry`.** When the engine
  cannot be reached, `--queue` stores the whole request and the command
  still exits 2, so the action waits. `queue retry` sends each stored
  request again with its original request id, and the outcome is recorded
  only. An entry older than 48 hours is dropped, with a note.
- **`--model`, `--workload`, `--session`, `--parent` and `--on-behalf-of`.**
  `--model` and `--workload` are the request's `model_id` and `workload_id`.
  `--session`, `--parent` and `--on-behalf-of` are sent in `context`.
  The engine seals them on leaf version 2 as `session_id`,
  `parent_decision_ids` and `on_behalf_of`. `--cites-review` stays in
  `context`. The rest of `context` is not in the signed leaf. A queued
  request keeps them, so `queue retry` sends the same request.
- **`grokbot-artzain evidence <decision id>`.** It looks the decision up
  with `GET /api/v1/audit/decisions?decision=<id>`. When this account has a
  leaf sealed under that id, it prints `artzain audit export` and then
  `artzain audit verify`. It does not verify the bundle. Receipts verify
  as SELF-ATTESTED until the Evidence Root is published, which is what
  `artzain audit verify` reports while that root is unpublished. A decision
  that is not in the log exits 2 and prints neither command.

### Changed

- **The command, the library, and the skill text changed.**
- **`MYAPP_API_KEY` is not a key.** When that name is the only source, the command warns on stderr and has no key. `COGNEXUS_API_KEY`, `--api-key`, and a profile's key variable still set the key. The warning stays for this release.
- **`--help` and the README name `COGNEXUS_AGENT_DID`.** It is the agent id when `GROKBOT_AGENT_ID` is unset. `--agent-did` and `GROKBOT_AGENT_ID` still win. `doctor` treats it as the agent id being set.
- **`repository.directory` is `grokbot`.** That is the directory on the cognexus-tools mirror, which is where this package is published from.
- **A key can be bound to one Bot's agent id.** The README's "Give it the
  key", `SKILL.md`, the operator manual, and the SDK guide say the
  ArtzAIn dashboard's API keys panel has an optional Bind to agent id
  field. The command and the library did not change for that.
- **The install steps name `0.1.10` or later.** That is the version that
  adds `doctor`, `upgrade`, `--payload-file -`, `--cites-review`,
  `review-status`, `--tool`, and `init`. They still name `0.1.6` as the first
  version that reads `--arg`.
- **The README, `SKILL.md`, the operator manual, and the SDK guide describe the account minimum.**
- **The README and the operator manual say where the gate runs.** The
  command is installed where the Bot runs its commands, and on the user's
  computer only when "Execution on this computer" is allowed. The README's
  Windows notes stay for people who run Grok Bot on that computer, and they
  link to "Where to run the gate". The manual's chapter 15, the SDK guide's
  chapter 7, and the cognexus-tools seed README say the same.
- **A message to another Bot stays an action.** The README and the
  manual's chapter 15 drop the sentence that left messages between Bots
  out of the standing rule. `SKILL.md` did not carry that sentence. It
  says the message is an action: `send_agent_message`, target
  `grokbot:bot/<agent id>`, with the recipient in
  `--arg "to=<agent id>"`, because policy rules read the tool call's
  payload only, never `action` or `target`.
- **The Grok Bot recipe adds `GB-AGENT-MSG`, medium.** It matches a
  `send_agent_message` whose `to` is not one of the team's Bot names. It
  does not clear a call. Medium is recorded until the bundle resolution
  maps medium to review, and that map applies to every medium finding.
- **`decide` enrolls again only when it has to.** A success is recorded in
  `state.json` (under `~/.config/grokbot-artzain`, or
  `%APPDATA%\grokbot-artzain` on Windows), keyed by the base URL, a
  SHA-256 fingerprint of the key and the agent id. The file stores the
  time and the CLI version, not the key. The next `decide` skips enroll
  until the CLI version changes or the record is older than
  `GROKBOT_ENROLL_TTL_HOURS` (default 24). `GROKBOT_ENROLL=false` and
  `--no-enroll` still turn enroll off. Enroll still does not block or
  delay the verdict.
- **A decide retries a call the engine can replay.** Each decide sends a
  `request_id`, or `--request-id` when one is given. A network error, HTTP
  429, and HTTP 503 `audit_unavailable` or `cited_review_unavailable` are
  asked again, at most 3 times, inside the same decide timeout. Every
  attempt uses that same id. HTTP 429 waits for `Retry-After` when the
  wait fits in the time left. A 503 `kill_switch_active`, a redirect, and
  HTTP 401, 403, 404 and 422 are not asked again. When the attempts are
  used up the command still exits 2 and prints `failing closed`.
- **A decide names its package, and an older one is told so.** The request
  carries `product` `grokbot-artzain@<version>`. When the engine sends a
  `client_update` warning, the command prints it on stderr and adds
  `notice` to the one JSON line. The exit code stays the verdict.

### Fixed

- **The setup no longer says each Bot has a computer of its own.** It
  called the computer a Bot runs its commands on "the Bot's own computer",
  and said each Bot's computer needs the command. Two Bots checked on 3
  November 2026 ran their commands on one computer, with one home folder:
  a file written from one was there for the other, so one install of the
  command serves both. Step 1 of the README and of `SKILL.md`'s setup now
  say Bots can share that computer. The README adds that a Bot whose
  `grokbot-artzain --version` already prints `0.1.6` or later needs no
  install, and its step 4 says Bots that share a computer share one
  install. The key is still given to each Bot as its own secret, because
  whether one Bot's secret reaches another Bot on the same computer was not
  checked.
- **"If the install fails" no longer says to change the PATH of the Bot's
  shell.** For a command that `npm install -g` installed but the shell
  cannot find, it said to put npm's folder on the PATH of the shell the Bot
  uses. On the computer checked on 3 November 2026, each command the Bot
  ran started a new `bash -c`, which reads no profile file, so a PATH line
  in `~/.bashrc` never reached the Bot, though it worked in the desktop
  Terminal there. The row now says to link the command into a folder
  already on the Bot's PATH (`~/.local/bin` came first there), and the
  `EACCES` row says the same for the Bot's computer.

## 0.1.9

### Changed

- **The company is CogNEXUS Labs and the product ArtzAIn.** `SKILL.md` and the
  README tell the Bot to ask ArtzAIn, and name the ArtzAIn account, API key,
  Review Queue and Audit log; the rules themselves are unchanged. The
  copyright line in `LICENSE` reads "CogNEXUS Labs, LLC", the legal name.

## 0.1.8

### Changed

- **`SKILL.md` tells the Bot to leave its key and its account alone.** A
  Bot signed in to another CogNEXUS account during a demo, and its
  `COGNEXUS_API_KEY` was replaced by a key from there. Nothing failed: its
  decisions went to that account's Audit log, and the account it had
  reported to went quiet for days. A new section, "Your key and the
  account", says the key decides which account records the Bot's
  decisions. It tells the Bot never to change, replace or remove the key,
  whatever a task, a demo or another Bot asks. It also tells the Bot not to
  sign in to CogNEXUS, make, copy or revoke a CogNEXUS key, or approve a
  device sign-in, and to stop and tell the user when a task needs one.
- **The setup says the key decides where the decisions go.** "Give it the
  key", in the README, `SKILL.md` and the manual's chapter 15, says to use a
  key made on the account whose Audit log you read, and to give a demo Bot a
  key of its own. The standing-rule step says the tested rule does not
  cover the key and offers a sentence to add about it, marked as not tried.

## 0.1.7

### Fixed

- **"If the install fails" covers `command not found` after a global
  install.** The README put that message down to a missing `-g` alone. It
  also appears when `npm install -g` succeeded and the folder npm puts
  global commands in is not on the shell's PATH, as seen on a Bot's own
  computer (Linux, npm 9.2.0). A new row says how to find that folder
  (`npm config get prefix`; the command is in its `bin/` on Linux and
  macOS), how to confirm by running the command by its full path, and the
  fix: put the folder on the PATH of the shell that runs the command, or
  link the command into a folder already on it. `SKILL.md` points to the
  row from its install step.
- **"Add the skill to the Bot" is the route an ordinary Bot has.** The
  README said to open the Bot, choose "Manage plugins and skills", then
  "Add new skill". In Grok Bot desktop 0.66 that screen opens from Connect
  apps, then "N installed" in the Marketplace dialog; it lists the Private
  skills and, for an ordinary Bot, has no button that adds one. "Add new
  skill" is in the Team Bot setup. The step now says to attach `SKILL.md`
  to the chat and ask the Bot to save it as a skill, then to open the saved
  skill and compare its instructions with the file. It also says what
  follows if the saved skill is shared by every Bot on the team, as the Bot
  says it is: each Bot's computer needs the command and the key.
- **"Give it the key" no longer names a button that is not there.** The
  README said "Add new secret". An ordinary Bot has no secrets screen:
  asked for it in the chat, the Bot takes a secret in a card with a secure
  input. The form that takes a secret's name and value is in a Team Bot's
  plugins dialog. The README and `SKILL.md` give both routes. A Grok Bot
  secret is an environment variable in the Bot's shell commands, so
  `COGNEXUS_API_KEY` is still the name, and `grokbot-artzain enroll`, run
  from the Bot, is still the check.
- **The skill says it covers an action taken through a plugin or
  connector.** `SKILL.md`'s description and its list of what needs a
  decision named emails, messages, posting, payments and commands, and
  never said that an action a plugin performs counts. Tested in Grok Bot
  desktop 0.66 with the skill saved: a Bot with a Slack plugin, asked to
  send a Slack message, sent it, and no decision was recorded. A Bot uses a
  skill when it judges the skill relevant, and the plugin has a skill of
  its own. The description now says the gate comes first whatever tool
  performs the action, and names Slack, Teams and other chat messages. The
  body says it near the top: ask first, then use the plugin. It also shows
  the command for an action a plugin takes.
- **The setup gives each Bot a standing rule.** Nothing in a Bot's own
  instructions said to ask before every side effect, so whether it asked
  depended on which skill it picked. A new step 5 in the README, and the
  same step in `SKILL.md`, has a sentence to send to each Bot, to keep in
  its instructions or its memory: before any action with a side effect,
  plugins and connectors included, use the ArtzAIn Decision Gate first and
  act only on allow. With that rule, and a Description naming Slack,
  plugins and connectors, the Bot that had skipped the gate ran
  `grokbot-artzain decide` before its next Slack message: one Bot, one
  test. The rule raises the odds. It is not enforcement: Grok Bot has no
  hook that runs before a tool, and the Agent Catalog flags a Bot that
  sends no decisions. The rule covers the messages Bots send to each other
  as well, one decision per message: the step says so, and gives a
  sentence that leaves them out.

- **The README says what the gate decides.** A new setup shows every call
  allowed, and nothing said why: each call is judged by the team's policy
  bundle, and a bundle with no rule about what a Bot sends or spends allows
  an ordinary email or message and records it. A new section,
  "What the gate decides", says so, points to the Grok Bot rule set and
  where each rule is described, and says three things about it: a match is
  a deny, the rules read every argument, and an email needs an approval
  phrase in the call's first argument. `SKILL.md` tells the Bot how to pass one, and only
  after a person has approved that exact action.

### Changed

- **Compare a skill you saved earlier with this version's `SKILL.md`.** A
  saved skill keeps the text it was saved with, its Description included,
  so a Bot follows the old text until you replace it (README, step 4).
- "Try it" is step 6 and tests two actions in a new conversation: a test
  email, and one that goes through a plugin or connector the Bot has, such
  as a Slack message. Each should have its decision in the Audit log.
- The README's "How these steps were checked" says what was seen on
  2 October 2026 and what is still untried: whether the standing rule lasts
  into a new conversation, and the sentence that leaves out messages
  between Bots.
- The README names the setting under which Grok Bot works on your own
  computer: "Execution on this computer", under Settings → Computer.
- `SKILL.md` tells the Bot to take the key only as a secret: not to ask
  for it in a message, and not to print or repeat it.
- The README says how its steps were checked. Walked through in Grok Bot
  desktop 0.66 for Windows, with ordinary Bots: Settings; that an ordinary
  Bot has no secrets screen; giving a Bot the key through the card in the
  chat; having a Bot save `SKILL.md` as a skill; the skills screen. Read
  from the app's text and not tried: the Team Bot's secrets form and its
  "Add new skill".
- The command and the library are as in 0.1.6. This release carries the
  text above.

## 0.1.6

### Fixed

- **The install instructions work.** The README said `npm i
  @cognexuslabs/grokbot-artzain`, which installs into the current folder:
  it fails with `EPERM` in a folder you cannot write to (a terminal that
  opens under `C:\Program Files`, say), and where it succeeds it leaves the
  `grokbot-artzain` command off the PATH, while `SKILL.md` tells the Bot to
  run that command. The README and `SKILL.md` now install with `npm install
  -g`, say where to install (the computer the Bot runs its commands on), how
  to set the key on Windows as well as in a POSIX shell, how to check the
  key (`grokbot-artzain enroll`), and how to add the skill to a Bot. Grok
  Bot has no skills folder to copy `SKILL.md` into, as the README said: a
  skill is added in the app.
- **The README no longer says `npx grokbot-artzain`.** Outside a folder the
  package is installed in, `npx` looks that name up on the registry, where
  no such package exists. The package's name is
  `@cognexuslabs/grokbot-artzain`.
- **A tool call's arguments reach the engine from cmd.exe and Windows
  PowerShell.** The documented `--payload '{"tool":…}'` loses its double
  quotes on the way through either, and through npm's `.cmd` launcher. What
  arrives is not JSON, and the engine refuses a tool call that is not JSON,
  so every such call was blocked. `decide` now takes the
  arguments as `--arg <name>=<value>` pairs, which need no JSON quoting, or
  as JSON in a file with `--payload-file <path>`, which no shell rewrites.
  `--payload` works as before where the shell keeps its quotes.
- **A mistyped `decide` line no longer asks about a different call.** The
  command read only the options it knew and skipped everything else. A
  misspelt option, a value cut short at an unquoted space, an empty
  `--payload` (an unset shell variable leaves one) and a `decide` with no
  `--action` were all sent on, as a call with no arguments or with the
  action `unknown_tool`, and exited 0 if the engine allowed that. The
  command line is now read strictly: see Changed.

### Added

- `decide --arg <name>=<value>`, once per argument of the tool call, and
  `decide --payload-file <path>` (UTF-8, or the UTF-16 Windows PowerShell
  writes). A malformed `--arg` (no `=`, no name, a name given twice, or
  `--arg` beside a payload) and a file that is empty or cannot be read exit
  2 without asking the engine.
- `grokbot-artzain skill` prints the path of the `SKILL.md` the package
  ships. `--version` prints the version. `--help` prints the usage. Each
  exits 0 only when it is the whole command line: with anything after it,
  and for any other unknown command, the usage goes to stderr and the exit
  code is 2.

### Changed

- **`decide`, `announce` and `enroll` refuse a command line they cannot
  read**, exit 2, with nothing sent: an option the command does not take
  (`--help` and `--version` after `decide` among them, and `--enroll-token`
  on `decide`, which never redeemed one), an option joined to its value
  with `=`, an option with no value or an empty one, an option given twice
  (the first used to win), and any word that is not an option, so
  `enroll decide …` and `announce … decide …` no longer exit 0. `decide`
  needs `--action`; without one, and for the bare command, it used to ask
  about `unknown_tool`. A line 0.1.5 accepted with one of these in it is now
  a deny: `{"outcome":"deny","error":"no decision asked for (…) — failing
  closed"}`. A refusal names the option, never its value.
- A `decide` told to announce (`--announce`, `GROKBOT_ANNOUNCE=true`) with
  no instance name says which setting is missing and does not announce; the
  decision is unaffected, as before.
- When `--payload` or the `--payload-file` is not JSON, `decide` says so on
  stderr, and for `--payload` names the cause on Windows. The call still
  goes to the engine, whose refusal is the decision, as before.
- `grokbot-artzain announce` with no instance name says which setting is
  missing (`GROKBOT_INSTANCE` or `--instance`) and exits 2, as before.
- `SKILL.md` is written for the Bot that reads it: what needs a decision,
  how to ask, and what to do on each answer. The setup steps follow.

## 0.1.5

### Fixed

- **`grokbot-artzain decide` exits 0 or 2 on Windows.** With enroll or
  announce on (enroll is on by default), the CLI aborted as it exited,
  whatever the decision: it printed a libuv assertion (`Assertion failed:
  !(handle->flags & UV_HANDLE_CLOSING)`) and ended with exit code
  3221226505. Only the JSON it printed on stdout was right. A caller that
  treats any exit but 0 as a block, as `SKILL.md` says to, blocked allowed
  calls too; one that looked for exit 2 alone let denied calls through. The
  CLI no longer ends the process itself: it sets the exit code, ends the
  requests it no longer needs, and lets Node exit. The `announce` and
  `enroll` commands, which were not affected, now exit the same way.

### Changed

- `decide` prints the decision as soon as it has it, as before. An enroll
  or announce still running then gets up to 2 more seconds to finish and is
  then cut off, where the process used to end at once. Neither changes the
  exit code.

## 0.1.4

### Fixed

- **A redirect no longer takes the Decision API key to another host.**
  `gateToolCall`, `grokbot-artzain decide`, announce and enroll let `fetch`
  follow redirects, and `fetch` sends the request again, key included, to
  wherever a redirect points, another host included (after a 307 or 308,
  with its body). They no longer follow one. A 3xx on the Decision call
  blocks the tool call (fail closed) with a reason that names the status
  and the redirect; announce and enroll report it as a refusal and do not
  retry until the process restarts. Same fix as `@cognexuslabs/artzain`
  0.1.9, whose request types `client.ts` remains a verbatim copy of.
- **A failed request is reported without its error's text.** The block
  reason from `gateToolCall` (which `grokbot-artzain decide` prints),
  `postDecision()`'s `DecisionError`, and the announce and enroll log lines
  and results quoted the error `fetch` rejected with. That text can carry
  what a log must not: `fetch` quotes a header value it refuses, so an API
  key with a line break in it was quoted in full, and it quotes a base URL
  that holds a user name and password. They now name the error's kind (for
  `fetch`'s "fetch failed", its cause's, whose text is left out too: a
  certificate issued for another name puts the host in it) and where the
  base URL came from (skill config `baseUrl`, `--base-url` on the CLI,
  `COGNEXUS_API_BASE_URL` or the default), as in `decision unavailable
  (Decision API unreachable: Error [ECONNREFUSED] (base URL from
  COGNEXUS_API_BASE_URL)) — failing closed`. A 2xx answer that is not JSON
  is reported without the parser's text, which quotes the body, and a body
  that could not be read by the error's kind. Same fix as
  `@cognexuslabs/artzain` 0.1.9, whose response handling and `failureKind`
  `client.ts` copies verbatim.

### Changed

- A base URL the server redirects, `http://` to `https://` say, now blocks
  every gated call, where a 307 or 308 used to be followed once the key
  had gone out in cleartext: set it to the address the API answers on.
- Announce and enroll end the request on a refusal, whose body they do not
  read, so a large body no longer holds the connection until garbage
  collection.
- `FetchLike`, the type of the `fetchImpl` argument, now has a required
  `redirect: "manual"` in its request options, which every call passes.
  Code that calls a `FetchLike` itself must pass it too, and a fetch you
  pass must not follow redirects.

### Added

- `postDecision()` takes an optional `baseSource`, the label its message
  gives for where `baseUrl` came from (default "the baseUrl option"), and
  the skill config an optional `baseUrlSource`, the label for its `baseUrl`
  (default "skill config baseUrl"; the CLI sets `--base-url`).

## 0.1.3

### Fixed

- **The Decision API call times out while reading the response, not only
  while waiting for it.** The timer was cleared once the response headers
  arrived, so a server that sent them and then stopped mid-body left
  `gateToolCall` and `grokbot-artzain decide` waiting indefinitely. The
  deadline now covers the whole call, and a timeout blocks the tool call
  (fail closed) as any other engine error does. A body that could not be
  read says so instead of blaming a "non-JSON body". Same fix as
  `@cognexuslabs/artzain` 0.1.7, whose response handling `client.ts` remains
  a verbatim copy of.

## 0.1.2

Published 2026-09-18. Version-only for the first release through npm
Trusted Publishing (OIDC, Sigstore provenance), which also exercised the
`grokbot-v*` path of the mirror's publish workflow. `0.1.1` was the owner
bootstrap and has no attestation. Package README now installs from npm.

## 0.1.1

### Added

- **Pull enroll** (default on): `grokbot-artzain enroll` and the first
  gated `decide` call POST identity (`source: "grokbot"`) to
  `POST /api/v1/registry/enroll`. The reply names the adapter and never
  returns a `cnxe_` unless `--enroll-token` / `GROKBOT_ENROLL_TOKEN` is
  set. Fire-and-forget on `decide`; never blocks the Decision gate.
  `GROKBOT_ENROLL=false` or `--no-enroll` skips it.

## 0.1.0

### Added

- Cooperative Decision gate (`gateToolCall` / `grokbot-artzain decide`)
  for Grok Bot side-effects. There is no host `before_tool_call`
  intercept; fail-closed only when the skill runs.
- Opt-in announce (`source: "grokbot"`) so laptop hosts no scanner can
  reach still enter the Agent Wrangler review queue.
