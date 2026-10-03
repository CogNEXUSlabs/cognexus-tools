# Changelog

All notable changes to `@cognexuslabs/grokbot-artzain`. Headings are the
bare version (`## 0.1.0`): the mirror's `publish-npm.yml` cuts the GitHub
release notes for tag `grokbot-v<version>` from the matching section.

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
