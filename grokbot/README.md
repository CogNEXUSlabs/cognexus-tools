# `@cognexuslabs/grokbot-artzain`

A skill and a command that make a Grok Bot ask CogNEXUS before it does
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

## Set it up

You need Node.js 18 or later and a Decision API key (it starts `cnx_…`; get
one at `/get-a-key` on your CogNEXUS deployment, or under API keys in the
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

It must print `0.1.6` or later. An older version prints its usage instead,
and it ignores `--arg`: the engine would be asked about a call with no
arguments. Run the install command again to update it. If the shell says
`command not found` instead, see [If the install fails](#if-the-install-fails).

Install it **where the Bot runs its commands**. That is the Bot's own
computer: ask the Bot to run the two commands above. If you have also let
Grok Bot work on your own computer, install the command there too. The
setting is **Execution on this computer**, in the app's Settings → Computer
("Let Grok Bot open files and run tasks on your computer"). That is the
app's settings page, not the Computer tab beside a Bot, which shows the
Bot's own screen.

### 2. Give it the key

The command reads the key from the `COGNEXUS_API_KEY` environment variable
of the shell that runs it.

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
    > the CogNEXUS Decision API key for the grokbot-artzain command.

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

If you run your own CogNEXUS deployment, set `COGNEXUS_API_BASE_URL` to its
address the same way. Without it the command calls
`https://app.cognexuslabs.ai`.

### 3. Check the key and the address

```bash
grokbot-artzain enroll
```

Exit code 0 and a line starting `{"adapter":` mean the key and the address
work. It asks which adapter this Bot should use, and creates nothing.
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
skill applies.

A Team Bot is given skills in the Team Bot setup: **Add new skill** there
picks from the skills in your library. That is read from the app's text and
was not tried, and neither was whether a skill saved as above is offered
there.

Each Bot that should be governed needs the skill. The Bot that saved it said
the skill is shared by every Bot on the team, in one library. That is the
Bot's statement and is not confirmed here, so check each Bot with step 6. If
the skill is shared, every Bot on the team follows it, so each Bot's
computer needs the command (step 1) and the key (step 2): a Bot without them
gets an error from the gate and, correctly, does not act.

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
enroll request beside it unless `GROKBOT_ENROLL=false` is set. To leave
those messages out, add a sentence to the rule: "Messages to other Bots on
this team need no decision." That sentence was not tried.

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
decision should be in the **Audit log** of the CogNEXUS dashboard, naming
the action (`send_email`, `post_message`). An action with no decision beside
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

**Not tried:** whether the standing rule lasts into a new conversation, and
the sentence that leaves out messages between Bots. Where the rule is kept
is the Bot's own account, not seen in the app. The Description that was
tested is worded a little differently from the one in `SKILL.md`.

Steps 3 and 6 check the result whichever route you took.

## If the install fails

| You see | Cause and fix |
|---|---|
| `EPERM: operation not permitted, mkdir '…\node_modules'` | `npm i` without `-g` installs into the current folder, and this one (for example under `C:\Program Files`) is not yours to write to. Use `npm install -g`, which does not depend on the folder. |
| `grokbot-artzain` is not recognized, or `command not found`, after an install without `-g` | The command is inside that folder's `node_modules`. Install it with `-g`. |
| `command not found`, or not recognized, although `npm install -g` said `added 1 package` | The package is installed, but the folder npm puts global commands in is not on this shell's PATH. `npm config get prefix` prints npm's global folder: the command is in its `bin/` folder on Linux and macOS, and in the folder itself on Windows. Run it by its full path to confirm, on Linux and macOS `"$(npm config get prefix)/bin/grokbot-artzain" --version`. Then put that folder on the PATH of the shell that runs the command (on the Bot's computer, the shell the Bot uses), or link the command into a folder that is already on it. |
| `EACCES` on macOS or Linux | npm's global folder belongs to root. Use a Node version manager, or `npm config set prefix ~/.npm-global` and add `~/.npm-global/bin` to the PATH. Do not use `sudo`. |
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
| `--action <tool>` | Required. The tool or action about to run: `send_email`, `purchase`, `run_command`. |
| `--target <resource>` | What it acts on. Default `grokbot:tool:<tool>`. |
| `--arg <name>=<value>` | One argument of the tool call. Repeat it for each argument. |
| `--payload '<json>'` | The whole tool call as JSON, `{"tool":"…","arguments":{…}}`, in place of `--arg`. |
| `--payload-file <path>` | The same JSON read from a file: for long or multi-line values. |
| `--request-id <id>` | An id of your own for the call (64 characters at most). It is the Decision API's idempotency key: the same call repeated with the same id gets the first decision back. |

Policy rules read the tool call's arguments, so pass them. A call with no
`--arg` and no payload is judged on its action and target alone.

`--action` is required. Put each `--arg` pair in double quotes. A shell
still rewrites some characters inside them: when a value holds `$`, `%`,
`&`, a quote, a backtick, a backslash or a line break, write the call as
JSON to a file and pass `--payload-file`.

The command line is read strictly, because the caller acts on exit 0. A
misspelt option, an option given twice or with no value, an option joined to
its value with `=`, and a stray word (an unquoted space leaves one) all exit
2, and the engine is not asked.

**On Windows, prefer `--arg` or `--payload-file`.** cmd.exe and Windows
PowerShell take the double quotes out of `--payload '{"tool":…}'` before
the command sees it. What is left is not JSON, and the engine refuses a tool
call that is not JSON. The command says so on stderr when that happens.

### The answer

| Outcome | Exit code | Printed on stdout |
|---|---|---|
| `allow` | 0 | `{"outcome":"allow","decision_id":"…"}` |
| `deny` | 2 | `{"outcome":"deny","error":"REFUSED: …"}` |
| `review` | 2 | `{"outcome":"review","error":"QUEUED FOR REVIEW: …"}`. A person decides in the CogNEXUS Review Queue. |
| no key, HTTP 401 / 422 / 503, a timeout, an unreachable engine | 2 | `{"outcome":"deny","error":"decision unavailable (…) — failing closed"}` |
| a redirect (HTTP 3xx) | 2 | not followed, so the key stays with the configured host |
| a command line it cannot read (see above), no `--action`, a malformed `--arg`, an empty or unreadable `--payload-file` | 2 | `{"outcome":"deny","error":"no decision asked for (…) — failing closed"}`. The engine is not asked. |

Only `decide` is a gate: exit 0 from it always means `allow`. `announce`,
`enroll`, `skill`, `--version` and `--help` exit 2 when anything they do not
take follows them, a `decide` call included.

## What the gate decides

The command asks; your CogNEXUS policy answers. Each call is judged by the
engine's built-in checks and by the rules in your team's policy bundle. A
bundle with no rule about what a Bot sends or spends lets an ordinary email
or message through: it is allowed and recorded, which is what a new setup
shows in the Audit log.

To have the gate refuse things, add rules to the team's bundle. CogNEXUS
ships a starter set for Grok Bot (external sends, spending, secrets,
destructive commands): see the SDK guide, chapter 7 "Orchestrators", in the
dashboard's Docs panel, and the operator manual's chapter 4 for what each
rule matches. Run the bundle in shadow before promoting it. Three things to
know about that set:

- A match is a deny, not a review.
- The rules read the tool name and every argument, message text included.
- An email is refused unless the call carries an approval phrase in its
  **first argument**, close to the tool name:

  ```bash
  grokbot-artzain decide --action send_email --target mailbox \
    --arg "approval=approved by Jean" --arg "to=ops@example.com"
  ```

  The approval is text the Bot writes. It is sealed with the decision, and
  it is no proof that a person gave it.

## Settings

Each can be an environment variable or, where one is listed, an option.

| Variable | Option | Meaning |
|---|---|---|
| `COGNEXUS_API_KEY` | `--api-key` | Decision API key. Prefer the variable: an option shows in the process list and the shell history. |
| `COGNEXUS_API_BASE_URL` | `--base-url` | Your CogNEXUS deployment. Default `https://app.cognexuslabs.ai`. |
| `GROKBOT_AGENT_ID` | `--agent-did` | The name decisions are recorded under, and the Bot's name in the Agent Catalog. Default `grokbot-agent`. Give each Bot its own, and keep it stable. |
| `GROKBOT_INSTANCE` | `--instance` | A stable name for this host, with no `#` in it. Announce needs it. |
| `GROKBOT_ANNOUNCE=true` | `--announce` | Announce beside each `decide`. |
| `GROKBOT_ENROLL=false` | `--no-enroll` | Skip the enroll that goes beside each `decide`. |
| `GROKBOT_ENROLL_TOKEN` | `--enroll-token` | A one-time token to redeem with `enroll`. |
| `GROKBOT_ANNOUNCE_AGENTS` | | Comma-separated Bot names to announce, in place of `GROKBOT_AGENT_ID`. |
| `GROKBOT_ANNOUNCE_SKILLS` | | Comma-separated skill names to record. Default `artzain`. |

## Announce: list the Bot in the Agent Catalog

The Agent Wrangler can list Bots by reading a Grok Bot host's gateway, but
only a host it can reach. A Bot on a laptop, or on a computer Grok Bot runs
for you, is not one. Such a Bot can register itself:

```bash
export GROKBOT_INSTANCE=ops-desk        # PowerShell: $env:GROKBOT_INSTANCE = "ops-desk"
export GROKBOT_AGENT_ID=research-bot    # PowerShell: $env:GROKBOT_AGENT_ID = "research-bot"
grokbot-artzain announce
```

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

Each `grokbot-artzain decide` is a new process, so each one enrolls. The
engine limits enroll per account: 60 an hour by default, once a larger
first burst is used up. Past that the log line reads `enroll refused: HTTP
429`, and the decision is unaffected.
Once the Bot is set up, `GROKBOT_ENROLL=false` (or `--no-enroll`) turns it
off and saves the request.

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
import { gateToolCall } from "@cognexuslabs/grokbot-artzain";

const result = await gateToolCall(
  { apiKey: process.env.COGNEXUS_API_KEY, agentDid: "research-bot" },
  { toolName: "send_email", target: "mailbox", params: { to: "ops@example.com" } },
);
if (!result.allow) throw new Error(result.blockReason);
```

A failed request does not throw: it comes back as `allow: false` with the
reason in `blockReason`. In a process that stays up, announce and enroll go
out once, with the first call.

## What this is not

- Not a host plugin. Grok Bot documents no `before_tool_call` hook, so there
  is nothing to `plugins install`, and nothing stops a Bot that skips the
  skill. If Grok Bot gains such a hook, a host plugin replaces this skill.
- Not a card in the CogNEXUS Connectors panel. The Grok Bot source is under
  Agent Catalog → Discovery sources.
- Not the envelope. See Enroll above.

## From source

This package is published from
[`CogNEXUSlabs/cognexus-tools`](https://github.com/CogNEXUSlabs/cognexus-tools)
(`grokbot/`). In a checkout:

```bash
npm ci && npm run build
node dist/cli.js --version
```
