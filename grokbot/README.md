# `@cognexuslabs/grokbot-artzain`

A skill and a command that make a Grok Bot ask CogNEXUS before it does
anything with a side effect: send an email, post a message, pay, run a
command that changes something. `allow` lets the action through. `deny`,
`review` and every error stop it.

```
grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com"
```

The gate is **cooperative**. Grok Bot has no hook that runs before a tool,
so nothing calls the gate for the Bot: the skill tells the Bot to call it. A
Bot that does not have the skill, or skips it, is ungoverned.

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
arguments. Run the install command again to update it.

Install it **where the Bot runs its commands**. That is the Bot's own
computer: ask the Bot to run the two commands above. If you have also let
Grok Bot run commands on your computer, install it there too.

### 2. Give it the key

The command reads the key from the `COGNEXUS_API_KEY` environment variable
of the shell that runs it.

- **On the Bot's computer:** keep the key in Grok Bot's secrets
  (**Add new secret**, named `COGNEXUS_API_KEY`), not in the chat and not in
  the skill text.
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

Run it from the Bot too. A Bot that reports no key does not have the secret
in its shell under that name.

### 4. Add the skill to the Bot

The skill is the file [`SKILL.md`](https://github.com/CogNEXUSlabs/cognexus-tools/blob/main/grokbot/SKILL.md).
`grokbot-artzain skill` prints where the installed copy is.

In Grok Bot, open the Bot, choose **Manage plugins and skills**, then
**Add new skill**, and add `SKILL.md`: the file itself, or its text as the
skill's instructions. (Names as in Grok Bot desktop 0.66.) Each Bot that
should be governed needs the skill.

### 5. Try it

Ask the Bot to do something with a side effect, such as sending a test
email. It should run `grokbot-artzain decide` first, and the decision shows
up in the CogNEXUS dashboard.

## If the install fails

| You see | Cause and fix |
|---|---|
| `EPERM: operation not permitted, mkdir '…\node_modules'` | `npm i` without `-g` installs into the current folder, and this one (for example under `C:\Program Files`) is not yours to write to. Use `npm install -g`, which does not depend on the folder. |
| `grokbot-artzain` is not recognized, or `command not found` | The package was installed without `-g`, so the command is inside that folder's `node_modules`. Install it with `-g`. |
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
