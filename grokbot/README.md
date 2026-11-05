# `@cognexuslabs/grokbot-artzain`

A skill and a command that make a Grok Bot ask ArtzAIn before it does
anything with a side effect: send an email, post a message, pay, run a
command that changes something. It makes no difference what performs the
action: a message sent through a plugin or connector (Slack, Gmail) counts
as much as a shell command. `allow` lets the action through. `deny`,
`review` and every error stop it.

```
grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com"
```

The gate is **cooperative**. Grok Bot has no hook that runs before a tool,
so nothing calls the gate for the Bot: the skill tells the Bot to call it. A
Bot that does not have the skill, or skips it, is ungoverned. A Bot uses a
skill when it judges the skill relevant, so the setup also gives each Bot a
standing rule (step 5) and tests it on more than one kind of action
(step 6).

The MCP server has the same limit. `grokbot-artzain mcp` only sees calls
made to `artzain_decide`. A tool the Bot runs on its own is not gated there.

## Set it up

You need Node.js 18 or later and a Decision API key (it starts `cnx_…`; get
one at `/get-a-key` on your ArtzAIn deployment, or under API keys in the
dashboard). A dashboard sign-in token and an envelope key (`cnxe_…`) do not
work here.

### 1. Install the command

```bash
npm install -g @cognexuslabs/grokbot-artzain
```

`-g` puts the `grokbot-artzain` command on the PATH, and works from any
folder. Check it:

```bash
grokbot-artzain --version
```

It must print `0.1.10` or later. That version adds `doctor`, `upgrade`,
`--payload-file -`, `--cites-review`, `review-status`, `--tool`, `init`, and `evidence`.
`--payload-file -` reads the decide payload from standard input, and the
printed decision line includes `next_step`. A version
older than `0.1.6` ignores `--arg`, so the engine would be asked about a
call with no arguments. Run the install command again to update it. If the
shell says `command not found`, see [If the install fails](#if-the-install-fails).

Install it **where the Bot runs its commands**. That is the Bot's
computer: ask the Bot to run the two commands above. Bots can share one.
Two Bots checked on 3 November 2026 ran their commands on the same
computer, with one home folder, so a command installed from one Bot was
there for the other. Ask each Bot to run `grokbot-artzain --version`: if it
prints `0.1.10` or later, that Bot needs no install. If you have also
let Grok Bot work on your own computer, install the command there too. The
setting is **Execution on this computer**, in the app's Settings → Computer
("Let Grok Bot open files and run tasks on your computer"). That is the
app's settings page, not the Computer tab beside a Bot, which shows the
screen of the computer the Bot runs on.

The gate runs on the Grok Bot box, where the Bot runs its commands, with no
`machineId`, even when the action itself targets a user computer. Decide on
the box first, then use the machine-targeted tool only for the approved
action. Your own computer gets the command only when **Execution on this
computer** is allowed. The Bot's copy of this is
[Where to run the gate](SKILL.md#where-to-run-the-gate).

Check the install:

```bash
grokbot-artzain doctor
```

Each check is one line, `[ok ]`, `[WARN]` or `[FAIL]`. A check that is not
ok prints `->` and a one-line fix under it. Exit code 0 means no check
failed. A warning keeps that exit code. Exit code 1 means a check failed.
`--json` prints the same checks for a Bot. `--offline` skips the comparison
with the latest version on npm.

The checks cover Node, the command on PATH, this version against npm, the
skill text in this install against the package version, the key, the base
URL, acceptance of the key, the agent id, and the enroll record. On Windows
the PATH check also looks for `grokbot-artzain.cmd` and the PowerShell
execution policy, as in [If the install fails](#if-the-install-fails). The
key is shown as `sha256:` and the first eight hex digits of its SHA-256
fingerprint. The key check is the enroll request from step 3, including
when `GROKBOT_ENROLL=false`, so it counts against the enroll limit.
`doctor` sends no decision request. A missing `GROKBOT_AGENT_ID` is a
warning when `COGNEXUS_AGENT_DID` is also unset: a Bot may pass `--agent-did` on each call. `doctor` reads the
`SKILL.md` in this install (the line `Skill text version:`). The copy
saved in the app is the one you compare in the editor in step 4. That
copy's last line is `Skill text for grokbot-artzain` and the package
version. `grokbot-artzain skill --check <path>` reads that line and says
current or behind.

Update the command:

```bash
grokbot-artzain upgrade
```

The line it prints is the install command for this copy. A global npm
install prints `npm install -g @cognexuslabs/grokbot-artzain@` and the
latest version. A binary under a user prefix such as `~/.local` prints
that prefix in the command. A binary in the npx cache prints an `npx`
command for the scoped package. Nothing is installed until you run it
again with `--yes`. On Windows the command is `npm.cmd` (or `npx.cmd`),
and a global or prefix install also says to open a new shell so it finds
the updated command. The command does not read or change environment
variables or the key.

`--skill <path>` prints a one-line summary of how that file differs from
the packaged `SKILL.md`. With `--yes` it copies the packaged file onto
that path after the summary. A path outside
`~/.config/grokbot-artzain/skills` (on Windows,
`%APPDATA%\grokbot-artzain\skills`) is refused unless `--force` is set.
The copy saved in the app is still the one you compare in step 4.

### 2. Give it the key

The command reads the key from the `COGNEXUS_API_KEY` environment variable
of the shell that runs it. `MYAPP_API_KEY` is not a key. When that name is
the only one set, this release warns on stderr and the command has no key.
Use a key made on the account whose Audit log
you read: the key decides where this Bot's decisions are recorded. A Bot
used for demos gets a key of its own, on its own Bot, so that the demo
account's key never replaces this one.

On the ArtzAIn dashboard, API keys has an optional **Bind to agent id**
field. Put this Bot's agent id there (the same name as `GROKBOT_AGENT_ID`)
when you mint its key. The field stores that id. It does not store the
key. The key is still the `cnx_…` value in `COGNEXUS_API_KEY`. The account
leaves this off until
`POST /api/agents/grokbot-identity-binding/config` turns
`enforce_grokbot_identity_binding` on. With it on, a decide that asserts a
different agent id is refused before a decision is recorded (HTTP 422
`identity_binding`), and the command exits 2 without running the action.
With it off, the deployment-wide binding mode is what applies. The
operator manual names that mode.

- **On the Bot's computer:** give Grok Bot the key as a secret named
  `COGNEXUS_API_KEY`. A Grok Bot secret is an environment variable in the
  Bot's shell commands, so the secret's name is the variable's name. Never
  put the key in a chat message or in the skill text. Where the secret is
  entered depends on the kind of Bot. A Team Bot is one set up for teammates
  to share, in Grok Bot's Team Bot setup. Any other Bot is an ordinary Bot
  here.

  - **An ordinary Bot** has no secrets screen, in Settings or under Manage
    plugins and skills. Ask the Bot, in the chat, to request the secret. For
    example:

    > I need to give you a secret. Ask me for it with the secure secret
    > input, not in chat. Environment variable name: COGNEXUS_API_KEY. It is
    > the ArtzAIn Decision API key for the grokbot-artzain command.

    The Bot shows a card with a secure input: paste the key into the card,
    not into a message. Once the key is saved the card reads "Saved securely
    and kept private". If no card appears, stop: do not send the key as a
    message.
  - **A Team Bot** has a **Secrets** section in its plugins dialog (the
    Bot's details, under Plugins). Fill in **Environment variable name**
    with `COGNEXUS_API_KEY`, **What it's for**, which the Bot is shown, and
    **Secret value**, then choose **Save secret**. The secret is saved for
    everyone who uses that Bot. This form is read from the app's text and
    was not tried: see
    [How these steps were checked](#how-these-steps-were-checked).

  Step 3 tells you whether the key arrived.
- **On your own computer**, for every new shell:

  ```bash
  # macOS, Linux, Git Bash: add this line to ~/.bashrc or ~/.zshrc
  export COGNEXUS_API_KEY=cnx_…
  ```

  ```powershell
  # Windows PowerShell: stored for your user, read by shells opened afterwards
  [Environment]::SetEnvironmentVariable("COGNEXUS_API_KEY", "cnx_…", "User")
  ```

If you run your own ArtzAIn deployment, set `COGNEXUS_API_BASE_URL` to its
address the same way. Without it the command calls
`https://app.cognexuslabs.ai`.

### 3. Check the key and the address

```bash
grokbot-artzain enroll
```

Exit code 0 and a line starting `{"adapter":` mean the key and the address
work. It asks which adapter this Bot should use, and creates nothing.
`grokbot-artzain doctor` sends this same request for its key check, so
that check counts against the enroll limit too.
Otherwise the line on stderr says what is wrong:

| It says | Meaning |
|---|---|
| `enroll skipped: no API key configured` | `COGNEXUS_API_KEY` is not set in this shell |
| `enroll refused: HTTP 401` or `403` | the key is wrong or revoked, or it is not a Decision API key |
| `enroll refused: HTTP 3xx` | the address redirects: set `COGNEXUS_API_BASE_URL` to the address the API answers on |
| `enroll failed: …` | the address could not be reached from this computer |

Run it from the Bot too: ask the Bot to run `grokbot-artzain enroll`. If
the Bot gets `enroll skipped: no API key configured`, the key did not reach
the Bot's shell as `COGNEXUS_API_KEY`: check the secret's name.

### 4. Add the skill to the Bot

The skill is the file [`SKILL.md`](https://github.com/CogNEXUSlabs/cognexus-tools/blob/main/grokbot/SKILL.md).
`grokbot-artzain skill` prints where the installed copy is.

Skills a Bot has saved are listed in the app under **Private skills**. For
an ordinary Bot that screen has no button that adds one: you ask a Bot to
save the skill, and then check what it saved.

1. Attach `SKILL.md` to the chat and ask the Bot to save it as a skill:
   "Please save the attached as a skill, unchanged." The Bot saves it under
   the name in the file, **ArtzAIn Decision Gate**.
2. Find the skill. Choose **Connect apps**, at the bottom of the Bot list.
   In the Marketplace dialog, choose **N installed**, at the top right (N is
   a number). That opens **Manage plugins and skills**, which lists the
   installed plugins and, under **Private skills**, the skills. (Until a Bot
   has saved one, that list reads "No private skills yet. Ask your Bot to
   create one for you.") Choose the skill in the list: it opens in an
   editor.
3. Compare it with the file. **Name** and **Description** should be the
   `name` and `description` at the top of `SKILL.md`, and **Instructions**
   the text below them. If the Bot reworded or shortened the instructions,
   replace them with the file's text and choose **Save**.

A saved skill keeps the text it was saved with. After you update the
package, compare the skill with the new `SKILL.md` again, the
**Description** included: the description is what tells a Bot when the
skill applies. `grokbot-artzain skill --check <path>` does that
comparison for the saved text and says current or behind.

A Team Bot is given skills in the Team Bot setup: **Add new skill** there
picks from the skills in your library. That is read from the app's text and
was not tried, and neither was whether a skill saved as above is offered
there.

Each Bot that should be governed needs the skill. The Bot that saved it said
the skill is shared by every Bot on the team, in one library. That is the
Bot's statement and is not confirmed here, so check each Bot with step 6. If
the skill is shared, every Bot on the team follows it, so every Bot needs
the command (step 1) where it runs its commands, and the key (step 2): a
Bot without them gets an error from the gate and, correctly, does not act.
Bots that share a computer share one install of the command. Give the key
to each Bot as its own secret: whether one Bot's secret reaches another Bot
on the same computer was not checked.

### 5. Give each Bot a standing rule

A Bot uses a skill when it judges the skill relevant to what it was asked.
Asked to send a Slack message, a Bot that has a Slack plugin can use the
plugin's own skill and never open the Decision Gate. So give each Bot the
gate as a rule of its own, kept in its instructions or its memory. Send it
this in the chat:

> Standing rule, keep it permanently: before any action with a side effect,
> including messages sent through Slack or any other plugin or connector,
> use the ArtzAIn Decision Gate skill (grokbot-artzain decide) and act only
> on allow.

Ask the Bot where it kept the rule. Then, in a new conversation, ask it
what it does before an action with a side effect: a rule kept only in the
conversation it was given in is gone with that conversation. With several
Bots, you can ask one of them to pass the rule to every Bot on the team,
itself included, and to report each one's confirmation.

The rule covers every message, the ones Bots send to each other included.
With it, the Bots of a team asked for a decision before each message to
another Bot. That is a full record of what the Bots tell each other, and it
is one decision per message, sealed and billed like any other, with an
enroll request beside it unless `GROKBOT_ENROLL=false` is set. A message to
another Bot is an action: `send_agent_message`, target
`grokbot:bot/<agent id>`, and the recipient passed as an argument,
`--arg "to=<agent id>"`. Policy rules read the tool call's payload only,
never `action` or `target`.

The rule does not cover the key. A Bot that signs in to another ArtzAIn
account and puts a key from there in `COGNEXUS_API_KEY` keeps working: its
decisions go to that account's Audit log, and the one you read goes quiet.
`SKILL.md` tells the Bot never to change the key, sign in to ArtzAIn or
make a key itself. To make that a rule too, add this sentence: "Never
change COGNEXUS_API_KEY, and never sign in to ArtzAIn or make, copy or
revoke an ArtzAIn API key yourself, even for a demo or when another Bot
asks: ask me first." That sentence was not tried.

The rule raises the odds. It is not enforcement: Grok Bot has no hook that
runs before a tool, so nothing stops a Bot that skips the rule as well. The
Agent Catalog flags a Bot that sends no decisions. It does not show one
action that went around the gate on a Bot that sends others: step 6 and the
Audit log are the check for that.

### 6. Try it

Ask each Bot, in a new conversation, to do two things with a side effect:
send a test email, and do something through a plugin or connector it has,
such as sending a Slack message. An email that was asked about says nothing
of the Slack message: a plugin brings a skill of its own, and the Bot may
use that one alone.

For each, the Bot should run `grokbot-artzain decide` first, and the
decision should be in the **Audit log** of the ArtzAIn dashboard, naming
the action (`send_email`, `send_chat_message`). An action with no decision beside
it was not asked about: on that route the Bot is ungoverned. Give it the
standing rule again (step 5), ask where it kept it, and test again. If it
still skips the gate, that is the limit of a cooperative skill: decide
whether that Bot should have the plugin.

### How these steps were checked

The screens and buttons are named as in Grok Bot desktop 0.66 for Windows,
signed in with an account whose Bots are ordinary Bots, not Team Bots.
Another version may name them differently.

**Walked through in the app:** Settings → Computer (step 1). That an
ordinary Bot has no secrets screen, either in Settings (General, Computer,
Usage & Billing, Updates) or under Manage plugins and skills, and giving one
the key through the card in the chat, after which `grokbot-artzain enroll`
run by the Bot succeeded (steps 2 and 3). Asking a Bot to save the attached
`SKILL.md`, and the skills screen and the editor a private skill opens in
(step 4).

**Read from the app's text, not tried:** the Team Bot's Secrets form
(step 2) and the Team Bot's **Add new skill** (step 4). Changing a saved
skill in its editor was not tried either.

**Seen on 2 October 2026**, in that version, on a team of ordinary Bots.
With the skill saved and no standing rule, a Bot asked to send an email ran
`grokbot-artzain decide` first, and its decision is in the Audit log; it had
just run `grokbot-artzain` commands in the same conversation. A Bot with a
Slack plugin, asked to send a Slack message, sent it, and no decision was
recorded. Asked afterwards, it said it had not run the gate. One Bot was
then asked to give the standing rule of step 5 to every Bot on the team, and
the saved skill's Description was replaced with one that names Slack,
plugins and connectors. That Bot said it had kept the rule in its "profile
memory" and in "shared user memory", and reported each teammate's
confirmation. Asked again, the Bot that had skipped the gate ran
`grokbot-artzain decide` before it sent a Slack message through its plugin,
and the decision was recorded. That is one Bot and one test, with both
changes made together. The Bots also asked before each message to another
Bot.

**Not tried:** whether the standing rule lasts into a new conversation.
Where the rule is kept is the Bot's own account, not seen in the app. The
Description that was tested is worded a little differently from the one in
`SKILL.md`.

Steps 3 and 6 check the result whichever route you took.

## If the install fails

| You see | Cause and fix |
|---|---|
| `EPERM: operation not permitted, mkdir '…\node_modules'` | `npm i` without `-g` installs into the current folder, and this one (for example under `C:\Program Files`) is not yours to write to. Use `npm install -g`, which does not depend on the folder. |
| `grokbot-artzain` is not recognized, or `command not found`, after an install without `-g` | The command is inside that folder's `node_modules`. Install it with `-g`. |
| `command not found`, or not recognized, although `npm install -g` said `added 1 package` | The package is installed, but the folder npm puts global commands in is not on this shell's PATH. `npm config get prefix` prints npm's global folder: the command is in its `bin/` folder on Linux and macOS, and in the folder itself on Windows. Run it by its full path to confirm, on Linux and macOS `"$(npm config get prefix)/bin/grokbot-artzain" --version`. On your own computer, put that folder on the PATH of the shell that runs the command, or link the command into a folder that is already on it. On the Bot's computer, link the command: each command the Bot runs starts a new `bash -c`, which reads no profile file, so a PATH line added to `~/.bashrc` does not reach it. The desktop Terminal there is an interactive shell that does read `~/.bashrc`, so a command that runs in that Terminal can still be missing for the Bot. Ask the Bot to run `echo "$PATH"`, and link the command into a folder listed there that you can write to. On the computer checked on 3 November 2026 the list began with `~/.local/bin`: `ln -s "$(npm config get prefix)/bin/grokbot-artzain" ~/.local/bin/` (not tried). Then ask the Bot to run `grokbot-artzain --version`. |
| `EACCES` on macOS or Linux | npm's global folder belongs to root. Use a Node version manager, or `npm config set prefix ~/.npm-global` and add `~/.npm-global/bin` to the PATH. On the Bot's computer, install again after setting the prefix and link the command as in the row above: a PATH change does not reach the Bot's commands. Do not use `sudo`. |
| PowerShell: `running scripts is disabled on this system` | PowerShell is refusing npm's `.ps1` launcher. Run `grokbot-artzain.cmd`, or allow local scripts with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |

To run it once without installing, give `npx` the package's full name,
scope included: `npx @cognexuslabs/grokbot-artzain --version`. No package
exists under the name without the scope.

## Asking for a decision

```bash
grokbot-artzain decide --action send_email --target mailbox \
  --arg "to=ops@example.com" --arg "subject=Q3 report"
```

| Option | Meaning |
|---|---|
| `--action <name>` | The taxonomy action about to run: `send_email`, `send_chat_message`, `purchase`, `run_command`. Wins over `--tool` when both are given. |
| `--tool <name>` | A connector tool name. The command maps it to an action and a target (`slack_send_message` with `--arg "channel=C123"` is `send_chat_message` on `slack:channel/C123`). A name that is not in `src/taxonomy.json` is the action `unknown_tool`. Give `--action` or `--tool`. |
| `--target <resource>` | What it acts on. With `--tool`, the taxonomy fills it (`<system>:<kind>/<id>`, for example `github:repo/Quantumskipper/CogNEXUS`). An explicit `--target` wins. With `--action` alone, the default is `grokbot:tool:<action>`. |
| `--arg <name>=<value>` | One argument of the tool call. Repeat it for each argument. |
| `--payload '<json>'` | The whole tool call as JSON, `{"tool":"…","arguments":{…}}`, in place of `--arg`. |
| `--payload-file <path>` | The same JSON read from a file, or from standard input when `<path>` is `-`. An empty or unreadable standard input exits 2 and the engine is not asked, the same as an empty or unreadable file. |
| `--request-id <id>` | An id of your own for the call (64 characters at most). It replaces the id the command generates. It is the Decision API's idempotency key: the same inputs repeated with the same id get the first decision back. |
| `--profile <name>` | The saved profile for this Bot. `GROKBOT_BOT` selects the same profile when the flag is absent. |
| `--cites-review <decision id>` | Cite an approved review of this same action, target, and arguments. The command sends it as `context.cites_review`. Context is an idempotency input, so this is decided again even when `--request-id` matches the review. |
| `--model <id>` | The model that produced the payload. Sent as `model_id`. |
| `--workload <id>` | The workload this decision belongs to. Sent as `workload_id`. |
| `--session <id>` | Sent in `context` as `session`. |
| `--parent <decision id>` | Sent in `context` as `parent`. |
| `--on-behalf-of <principal>` | Sent in `context` as `on_behalf_of`. |
| `--queue` | When the engine cannot be reached, store this request and exit 2. `queue list` prints what is waiting. `queue retry` sends each stored request again. |

`--session`, `--parent`, `--on-behalf-of` and `--cites-review` go in `context`
with any other keys a caller already set. The engine seals `--session`,
`--parent` and `--on-behalf-of` on leaf version 2 as `session_id`,
`parent_decision_ids` and `on_behalf_of`. `--cites-review` stays in `context`.
The rest of `context` is not in the signed leaf. An enforcer that reads a key
records what it read in its own vote.

Policy rules read the tool call's arguments, so pass them. A call with no
`--arg` and no payload is judged on its action and target alone.

Give `--action` or `--tool`. Put each `--arg` pair in double quotes. A shell
still rewrites some characters inside them: when a value holds `$`, `%`,
`&`, a quote, a backtick, a backslash or a line break, write the call as
JSON to a file and pass `--payload-file`. On Windows PowerShell the same
JSON can be a here-string piped to `--payload-file -`.

The command line is read strictly, because the caller acts on exit 0. A
misspelt option, an option given twice or with no value, an option joined to
its value with `=`, and a stray word (an unquoted space leaves one) all exit
2, and the engine is not asked.

**On Windows, prefer `--arg` or `--payload-file`.** cmd.exe and Windows
PowerShell take the double quotes out of `--payload '{"tool":…}'` before
the command sees it. What is left is not JSON, and the engine refuses a tool
call that is not JSON. The command says so on stderr when that happens.

People who run Grok Bot on this Windows computer follow that note: the
command runs in cmd.exe or Windows PowerShell. When the Bot runs on the
Grok Bot box and the action targets a user computer, the gate runs on the
box. See [Where to run the gate](SKILL.md#where-to-run-the-gate).

### A profile for each Bot

```bash
grokbot-artzain init --bot ops --instance ops-desk --key-env BOT_API_KEY
```

This writes `profiles/ops.json` under `~/.config/grokbot-artzain` (on Windows, `%APPDATA%\grokbot-artzain`) with mode 0600. The file holds the agent id (the bot name, unless `--agent-did` is set), the instance, the base URL, and `key_env`, the name of the environment variable that holds the key. The key is not written.

`--profile <name>` selects that file. `GROKBOT_BOT` selects it when the flag is absent. For the agent id, the instance, the base URL, and the key, the order is the flag, then the environment, then the profile, then the default. A named profile that cannot be read exits 2, and the engine is not asked.

A decide with no agent id uses `grokbot-agent` and says so on stderr. `GROKBOT_REQUIRE_IDENTITY=1` makes that decide exit 2 before any network call.

### Command shims

```bash
grokbot-artzain shims install --profile ops
grokbot-artzain shims install --profile ops --enforce
grokbot-artzain shims uninstall --profile ops
```

Install is opt-in for one profile. It writes wrappers for `curl`, `wget`, `git`, `gh`, `npm`, `aws`, `ssh`, `scp`, and `rm` into `~/.local/bin`, and it edits no shell profile. The Bot's commands run in `bash -c`, which reads no profile, and the PATH they inherit already puts `~/.local/bin` before `/usr/bin`.

Each wrapper asks the Decision API with action `run_command` and a target parsed from the command. `curl` and `wget` ask only when the request is not a GET. `git` asks on `push`. `gh` asks on write subcommands. `npm` asks on `publish`. `aws` asks on mutating verbs. `ssh` and `scp` always ask. `rm -rf` asks when a path is outside `/tmp` and `/workspace`. The wrapper then runs the real binary by its absolute path. It finds that binary by searching PATH with `~/.local/bin` left out.

Install starts in log-only mode: the shim asks for a decision, the decision is recorded, and the command runs. `--enforce` records enforce mode on that profile. Enforce exits 126 and prints the reason on stderr for any outcome other than allow, and the command does not run.

A full path (`/usr/bin/curl`) or another interpreter (`python`, `node`) skips the shim. The box is shared, so these shims affect every agent there.

`shims uninstall` deletes the files listed in the manifest install wrote. It leaves `grokbot-artzain` and every other file in `~/.local/bin`.

When a wrapper runs the real command, it appends one JSON line to `shim.jsonl` in the same directory as the enroll state. The line is the time, the agent id, `run_command`, the target, and the decision id. It does not include the arguments or the key. Enforce mode writes nothing when it refuses to run the command.

### Coverage

```bash
grokbot-artzain coverage --since 2026-11-04T08:00:00-08:00
```

This reads three logs and prints each action since that time that has no decision id. `--since` is an ISO-8601 time with a timezone. The shim log is `shim.jsonl`. The gateway log is `gateway.jsonl` under `~/.config/artzain-mcp-gateway` (on Windows, `%APPDATA%\artzain-mcp-gateway`), or `ARTZAIN_GATEWAY_LOG`. The action journal is `actions.jsonl` beside the enroll state, or `GROKBOT_ACTION_JOURNAL`. `--shim-log`, `--gateway-log`, and `--journal` name different files. A missing file is an empty source.

Each line is JSON: `at`, `agent`, `action`, `target`, and `decision_id`. Two lines that share a decision id count as one action. The command posts those per-agent counts. It does not post the lines, the arguments, or the key. Exit 1 when any action has no decision id. Exit 0 when every action had one and the report was accepted.

### The answer

| Outcome | Exit code | Printed on stdout |
|---|---|---|
| `allow` | 0 | `{"outcome":"allow","decision_id":"…","next_step":"run"}` |
| `deny` | 2 | `{"outcome":"deny","decision_id":"…","error":"REFUSED: …","next_step":"do not run"}` |
| `review` | 2 | `{"outcome":"review","decision_id":"…","error":"QUEUED FOR REVIEW: …","next_step":"wait for review"}`. A person decides in the ArtzAIn Review Queue. |
| the account minimum (`client_too_old`) | 2 | `{"outcome":"deny","error":"REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.","next_step":"do not run"}` |
| no key, HTTP 401, a 422 other than `client_too_old`, HTTP 503, a timeout, an unreachable engine | 2 | `{"outcome":"deny","error":"decision unavailable (…) — failing closed","next_step":"do not run"}` |
| a redirect (HTTP 3xx) | 2 | not followed, so the key stays with the configured host |
| a command line it cannot read (see above), no `--action` and no `--tool`, a malformed `--arg`, an empty or unreadable `--payload-file` (a path, or `-` for standard input) | 2 | `{"outcome":"deny","error":"no decision asked for (…) — failing closed","next_step":"do not run"}`. The engine is not asked. |

A network error, HTTP 429, and HTTP 503 `audit_unavailable` or
`cited_review_unavailable` are asked again, up to 3 times, inside the same
12 second limit. Every attempt uses the same request id, so a replay returns
the first decision instead of sealing another. HTTP 429 waits for the
`Retry-After` header when that wait fits in the time left. A 503
`kill_switch_active`, a redirect, and HTTP 401, 403, 404 and 422 are not
asked again. When the attempts are used up, the command still exits 2 and
prints `failing closed`.

With `--queue`, that unreachable decide is also written under
`~/.config/grokbot-artzain/queue` (on Windows,
`%APPDATA%\grokbot-artzain\queue`). The file holds the request the engine
decides on, payload included, and `model_id`, `workload_id` and `context`
when the decide sent them. The API key stays in the environment.
The command still exits 2, so the action waits for a later decide that
exits 0. `queue list` prints each stored request. `queue retry` sends each
one again with its original request id. It prints the recorded outcome and
exits 2, so a recorded allow leaves the action waiting. An entry older
than 48 hours is dropped, with a note. That matches the Decision API's
idempotency window: past it, the same request id is a new decision.

Every decide sends `product` as `grokbot-artzain@` this command's version.
An account can require a minimum version of this command. That switch stays
off until `POST /api/agents/grokbot-min-version/config` turns it on. When it
is on and this command is below the minimum, the engine answers HTTP 422
`client_too_old` before it decides, so nothing is sealed and nothing is
billed. The command prints the sentence in the table, exits 2, and does not
ask again. A decide with no product is not this refusal. The operator manual
names the setting. When the engine answers with a `client_update` warning,
that text is printed on stderr and the JSON line gains `notice`. The exit
code stays the verdict in the table.

Only `decide` is a gate: exit 0 from it always means `allow`. `announce`,
`enroll`, `skill`, `doctor`, `upgrade`, `queue`, `review-status`, `evidence`,
`init`, `mcp`, `--version` and `--help` exit 2 when anything they do not take
follows them, a `decide` call included. `queue list` exits 0. `queue retry`
exits 2 when it recorded an outcome or a request is still waiting. `doctor`
exits 0 when no check failed and 1 when a check failed. `skill --check <path>`
exits 0 when the installed copy is current and 1 when it is behind.
`upgrade` exits 0 when it printed the command, or when `--yes` and the
install finished. It exits 1 when the install failed or the copy's path
does not show how it was installed. It exits 2 when `--skill` names a path
outside the directory above and `--force` is absent.
`review-status <decision id>` prints `pending`, `approved`, or `rejected`
for a decision this account made, and exits 0 when it read that status. It
exits 2 when it could not. That exit code is not an allow. The command
cannot change the review. Exit 0 from `decide` is still the only allow.
`evidence <decision id>` looks the decision up with
`GET /api/v1/audit/decisions?decision=<id>`. When this account has a leaf
sealed under that id, it prints `artzain audit export` and then
`artzain audit verify`. Those commands check the receipt. This command does
not: the anchoring state is the verifier's. Receipts verify as
SELF-ATTESTED until the Evidence Root is published. It exits 0 when the
decision is in the log, and 2 when it is not or the log could not be read.
That exit code is not an allow. `init` writes a profile and exits 0 when
it wrote the file. That exit code is not an allow.
`mcp` answers MCP calls. It exits 0 when the server stops. That exit code
is not an allow.

## What the gate decides

The command asks; your ArtzAIn policy answers. Each call is judged by the
engine's built-in checks and by the rules in your team's policy bundle. A
bundle with no rule about what a Bot sends or spends lets an ordinary email
or message through: it is allowed and recorded, which is what a new setup
shows in the Audit log.

To have the gate refuse things, add rules to the team's bundle. ArtzAIn
ships a starter set for Grok Bot (external sends, spending, secrets,
destructive commands): see the SDK guide, chapter 7 "Orchestrators", in the
dashboard's Docs panel, and the operator manual's chapter 4 for what each
rule matches. Run the bundle in shadow before promoting it. Three things to
know about that set:

- A high or critical match is a deny, not a review. A medium match is
  recorded. It is a review when the bundle's resolution maps medium to
  review, and that map applies to every medium finding.
- The rules read the tool name and every argument, message text included.
  They do not read `action` or `target`.
- An email is refused unless the call carries an approval phrase in its
  **first argument**, close to the tool name:

  ```bash
  grokbot-artzain decide --action send_email --target mailbox \
    --arg "approval=approved by Jean" --arg "to=ops@example.com"
  ```

  The approval is text the Bot writes. It is sealed with the decision, and
  it is no proof that a person gave it. The starter rule still clears a
  deny that way. Retiring the phrase takes a change to that recipe first.
  A citation does not clear the deny.

A `review` is a different stop. Tell the person the decision id and the
ArtzAIn dashboard Review Queue, `https://app.cognexuslabs.ai/#/reviews`.
Once they approve, decide again with `--cites-review` set to that decision
id. Context is an idempotency input, so the re-ask is decided again.
`review-status` only reads the state.

A message to another Bot is `send_agent_message`, target
`grokbot:bot/<agent id>`, with the recipient in `--arg "to=<agent id>"`.
`GB-AGENT-MSG` in the starter set is medium. It matches that call when `to`
is not one of the team's Bot names, and it does not clear any call.

## Settings

Each can be an environment variable or, where one is listed, an option.

| Variable | Option | Meaning |
|---|---|---|
| `COGNEXUS_API_KEY` | `--api-key` | Decision API key. Prefer the variable: an option shows in the process list and the shell history. |
| `COGNEXUS_API_BASE_URL` | `--base-url` | Your ArtzAIn deployment. Default `https://app.cognexuslabs.ai`. |
| `GROKBOT_AGENT_ID` | `--agent-did` | The name decisions are recorded under, and the Bot's name in the Agent Catalog. Default `grokbot-agent`. Give each Bot its own, and keep it stable. |
| `COGNEXUS_AGENT_DID` | `--agent-did` | The same name when `GROKBOT_AGENT_ID` is unset. `--agent-did` and `GROKBOT_AGENT_ID` win over it. |
| `GROKBOT_INSTANCE` | `--instance` | A stable name for this host, with no `#` in it. Announce needs it. |
| `GROKBOT_ANNOUNCE=true` | `--announce` | Announce beside each `decide`. |
| `GROKBOT_ENROLL=false` | `--no-enroll` | Skip enroll. The value is compared with exactly `false`. |
| `GROKBOT_ENROLL_TTL_HOURS` | | Hours before `decide` enrolls again for the same base URL, key and Bot. Default 24. |
| `GROKBOT_ENROLL_TOKEN` | `--enroll-token` | A one-time token to redeem with `enroll`. |
| `GROKBOT_ANNOUNCE_AGENTS` | | Comma-separated Bot names to announce, in place of `GROKBOT_AGENT_ID`. |
| | `--all-profiles` | With `announce`, send every profile on this host. |
| | `--force` | With `announce`, send again within 24 hours. |
| `GROKBOT_ANNOUNCE_SKILLS` | | Comma-separated skill names to record. Default `artzain`. |

## Compatibility

Flags and environment variables from 0.1.x keep working through 0.x. A
deprecation warns on stderr for at least one minor version before that flag
or variable stops working. Each release states, in its changelog, the
minimum engine it needs.

`MYAPP_API_KEY` is the exception in 0.1.10: it is not a key. When it is the
only name set, the command warns on stderr and has no key. That warning
stays for this release.

## Announce: list the Bot in the Agent Catalog

The Agent Wrangler can list Bots by reading a Grok Bot host's gateway, but
only a host it can reach. A Bot on a laptop, or on a computer Grok Bot runs
for you, is not one. Such a Bot can register itself:

```bash
export GROKBOT_INSTANCE=ops-desk        # PowerShell: $env:GROKBOT_INSTANCE = "ops-desk"
export GROKBOT_AGENT_ID=research-bot    # PowerShell: $env:GROKBOT_AGENT_ID = "research-bot"
grokbot-artzain announce
```

With no agent id and no `GROKBOT_ANNOUNCE_AGENTS`, `announce` sends the current profile's agent. That is `activeAgentId` in `agents/active-agent.json` under the host's sand-data directory: `SAND_DATA_ROOT` when that path is absolute, otherwise `SAND_USER_DATA_DIR/sand-data`, otherwise `/home/box/sand-data`. The command sends the folder id. It does not read `profile.json` or `gateway.json`. `GROKBOT_ANNOUNCE_AGENTS` still names the agents to send instead of that profile. `--all-profiles` sends every profile on the host and ignores both.

A list longer than 25 agents is several calls, at most 25 names each. A call stays within the server's 50-name cap and its 25 new rows. The command records the time of each agent it stored in `~/.config/grokbot-artzain/state.json` (on Windows, `%APPDATA%\grokbot-artzain\state.json`). The key is not stored. An agent announced within 24 hours is skipped unless `--force`.

Or set `GROKBOT_ANNOUNCE=true`, and each `decide` run announces as well,
which keeps the row's last-seen time current. The engine limits announce
per account: 60 an hour by default, once a larger first burst is used up.

Announce sends **names only**: the instance, the Bot names and the skill
names. Never prompts, conversations, or the host's `gateway.json`. Rows
arrive as `grokbot-announce:{instance}#agent:{name}` and go through the same
review as every discovered agent. Changing the instance name makes new rows,
so pick one and keep it.

Announce is not a gate. It never blocks, delays, or changes a decision. The
command is a new process each time, so a failed announce is simply tried
again by the next run that announces. A 3xx or 4xx means a setting is wrong.

## Enroll

Beside the decision, `decide` sends the same names to
`POST /api/v1/registry/enroll`. The reply names the adapter (`tool_gate`
for Grok Bot) and is logged on stderr. It never blocks or changes a
decision, and the decision is printed without waiting for it.

`decide` enrolls when this copy of the command has not enrolled for this
base URL, this key and this Bot within `GROKBOT_ENROLL_TTL_HOURS` (default
24). The record is `state.json` in `~/.config/grokbot-artzain` (on Windows,
`%APPDATA%\grokbot-artzain`). It stores the time and the CLI version. The
key is not stored: the record is keyed by a SHA-256 fingerprint of it,
with the base URL and the Bot's id. A newer CLI version enrolls again.
`GROKBOT_ENROLL=false` (exactly `false`) or `--no-enroll` turns enroll off.

The engine limits enroll per account: 60 an hour by default, once a larger
first burst is used up. Past that the log line reads `enroll refused: HTTP
429`, and the decision is unaffected.

`grokbot-artzain enroll` does the same on its own and prints the reply. With
a one-time token from **Govern** in the Agent Catalog, it prints an envelope
key (`cnxe_…`) once, on stdout:

```bash
grokbot-artzain enroll --enroll-token <token>
```

An envelope key is for a program that calls the xAI API
(`https://api.x.ai/v1`) directly. The envelope screens that model traffic.
It does not sit in front of the Bot's computer, its browser, or its
connectors: this skill is the control for those. `decide` never redeems a
token.

## In your own code

```ts
import { gateToolCall, handleBeforeToolCall } from "@cognexuslabs/grokbot-artzain";

const result = await gateToolCall(
  { apiKey: process.env.COGNEXUS_API_KEY, agentDid: "research-bot" },
  { toolName: "send_email", target: "mailbox", params: { to: "ops@example.com" } },
);
if (!result.allow) throw new Error(result.blockReason);

const blocked = await handleBeforeToolCall(
  { toolName: "send_email", params: { to: "ops@example.com" }, toolCallId: "call-1" },
  { agentId: "research-bot", pluginConfig: { apiKey: process.env.COGNEXUS_API_KEY } },
);
if (blocked) throw new Error(blocked.blockReason);
```

`gateToolCall(cfg, input, fetchImpl)` is the library call. A failed request
does not throw: it comes back as `allow: false` with the reason in
`blockReason`. In a process that stays up, announce goes out once, with the
first call. Enroll goes out when the saved record is missing, from another
CLI version, or older than `GROKBOT_ENROLL_TTL_HOURS`.

`handleBeforeToolCall(event, ctx)` is the same decision in the shape a host
uses for `before_tool_call`. The event carries `toolName`, `params`, and
`toolCallId` or `runId`. The config is `event.context.pluginConfig` when
that object is present, and `ctx.pluginConfig` otherwise. `ctx.agentId` is
the agent id. An allow returns nothing, so the tool can run. Any other
outcome returns `{ block: true, blockReason }`. This package does not
register the hook. A host that has one can call this function from it.

## MCP server

`grokbot-artzain mcp` speaks MCP on stdin and stdout, one JSON-RPC message
per line. `--http --port <n>` listens on `127.0.0.1` instead. The package
has no MCP library: `initialize`, `tools/list`, `tools/call` and `ping` are
implemented here.

```bash
grokbot-artzain mcp
grokbot-artzain mcp --http --port 8765
```

The tools are `artzain_decide`, `artzain_status` and
`artzain_review_status`.

`artzain_decide` takes `tool` and `arguments`, and optionally `action`,
`target`, `cites_review` and `request_id`. It returns `outcome`,
`decision_id`, `reasons`, `next_step`, and `notice` when the engine sent a
`client_update` warning. `next_step` is `run` on allow, `wait for review`
on review, and `do not run` on anything else. Anything but `allow` is a
failed tool call (`isError`). An unreachable engine is a failed tool call
too, and the reason says `failing closed`. This server does not run the
tool. It does not enroll or announce; those stay the `enroll` and
`announce` commands.

`artzain_status` returns this package's version, the agent id, the
instance, the enroll state and an update notice. It does not return the
key. `artzain_review_status` takes `decision_id` and reads
`GET /api/v1/decisions/{decision_id}/review`. A pending, approved or
rejected status is the answer. It does not change the review.

This layer only sees calls made to `artzain_decide`. A tool the Bot runs
on its own is not gated here.

The settings a plugin form would name are `COGNEXUS_API_KEY` (a secret),
`GROKBOT_AGENT_ID`, `COGNEXUS_AGENT_DID` (the same agent id when
`GROKBOT_AGENT_ID` is unset), `GROKBOT_INSTANCE`, and `COGNEXUS_API_BASE_URL`
(optional). Those secret fields exist only for a Team Bot. That form was
read from the app's text and was not tried. An ordinary Bot has no secrets
screen. It takes a secret through a card in the chat: paste the key into
the card, and do not send the key as a message. Neither route is known to
configure this MCP server. The Grok Bot plugin manifest format was not
found in this repository. Until that question (Q1) is answered, do not
treat `plugin/manifest.json` as a format the app loads. It is a
placeholder so the settings are not forgotten.

## What this is not

- Not registered as a `before_tool_call` hook. Grok Bot documents no such
  hook, so there is nothing to `plugins install`, and nothing stops a Bot
  that skips the skill. `handleBeforeToolCall` is ready for a host that has
  that hook, and this package does not register it. Until a host calls it,
  the Bot reaches the gate through this skill. `grokbot-artzain mcp` is not
  that hook: it only sees calls made to `artzain_decide`. The files under
  `plugin/` are not a manifest the app is known to load.
- Not a card in the ArtzAIn Connectors panel. The Grok Bot source is under
  Agent Catalog → Discovery sources.
- Not the envelope. See Enroll above.

## From source

This package is published from
[`CogNEXUSlabs/cognexus-tools`](https://github.com/CogNEXUSlabs/cognexus-tools)
(`grokbot/`). `package.json` sets `repository.directory` to `grokbot`, the
directory this package has on that mirror. In a checkout:

```bash
npm ci && npm run build
node dist/cli.js --version
```
