---
name: ArtzAIn Decision Gate
description: Use first, before any action with a side effect, whatever tool performs it - a plugin, a connector, another skill, the browser or a shell command. Covers sending an email or a Slack, Teams or other chat message, posting, buying or paying, running a command that changes or deletes something, and writing to another system. It asks ArtzAIn whether the action is allowed, so ask here first, then use the plugin or tool. Anything but "allow" means do not act.
---

# ArtzAIn Decision Gate

Before any action with a side effect, ask ArtzAIn. Act only on **allow**.

This applies to actions taken through plugins and connectors (Slack, Gmail,
X, Canva, a CRM) as well as shell commands. Ask first, then use the plugin.
The plugin's own skill says how to do the action. This one says whether you
may.

Grok Bot has no hook that runs before a tool, so nothing calls this gate for
you: you call it yourself. An action taken without asking is ungoverned.

## What needs a decision

Ask before you:

- send an email, a text, or a chat message (Slack, Teams, or any other)
- post or publish anything
- buy, pay, book, or move money
- run a command that changes or deletes files, data, or infrastructure
- write to another system: a CRM, a ticket, a repository, a calendar

It makes no difference what performs the action: a plugin, a connector,
another skill, the browser, or a command you run yourself.

Reading, searching, and drafting text you have not sent need no decision.

## Where to run the gate

Run `grokbot-artzain` on the Grok Bot box, where this Bot runs its commands,
with no `machineId`, even when the action itself targets a user computer.

Decide on the box first. A fresh allow is what lets the action run. Use the
machine-targeted tool only for the approved action.

## How to ask

Run this on the Grok Bot box, with no `machineId`, and with one `--arg` for
each argument of the action you are about to take:

```
grokbot-artzain decide --action <tool> --target <resource> --arg <name>=<value>
```

For example:

```
grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com" --arg "subject=Q3 report"
```

An action a plugin or connector will take can name that connector's tool.
The command maps it to an action and a target:

```
grokbot-artzain decide --tool slack_send_message --arg "channel=ops-alerts" --arg "text=Deploy finished"
```

That call is the action `send_chat_message` on `slack:channel/ops-alerts`.
The payload's `tool` field is `send_chat_message`, which is what a policy
rule reads.

`src/taxonomy.json` in this package lists each connector tool, the action it
becomes, and a target template `<system>:<kind>/{argument}`. A repo target
can contain a slash, as in `github:repo/Quantumskipper/CogNEXUS`. A name
that is not listed is the action `unknown_tool` and the target
`unknown:tool/<name>`.

- `--action` is the taxonomy action: `send_email`, `send_chat_message`,
  `post_public`, `purchase`, `run_command`. It wins when `--tool` is also
  given.
- `--tool` is the connector's own tool name. Use it when the connector
  names the tool. Give `--action` or `--tool`.
- `--target` is what it acts on. With `--tool`, the taxonomy fills it. An
  explicit `--target` wins. With `--action` alone, the default is
  `grokbot:tool:<action>`.
- Put each `--arg` pair in double quotes.
- When a value is long, or holds `$`, `%`, `&`, a quote, a backtick, a
  backslash or a line break (an email body, a script, an amount like
  $500), the shell would change it. Write the whole call as JSON,
  `{"tool":"<tool>","arguments":{…}}`, to a file and pass
  `--payload-file <path>` in place of the `--arg` pairs. `--payload-file -`
  reads that JSON from standard input. An empty or unreadable standard
  input is a deny, and the engine is not asked.
- Spell the options exactly as shown, each followed by its value as a
  separate word. A line the command cannot read is a deny.
- A profile names this Bot. The person who runs you saves it with
  `grokbot-artzain init --bot <name>`. Pass `--profile <name>` on
  `decide` when you were given one. `GROKBOT_BOT` selects the same
  profile when the flag is absent. The file holds an agent id, an
  instance, a base URL, and the name of the environment variable that
  holds the key. It does not hold the key.
- Flag, then environment, then profile, then the default. The agent id is
  `GROKBOT_AGENT_ID`, and `COGNEXUS_AGENT_DID` when that is unset. A decide
  with no agent id uses `grokbot-agent` and says so on stderr. When
  `GROKBOT_REQUIRE_IDENTITY=1`, that decide exits 2 and you do not act.

Describe the action as you will really take it. The decision is for that
action and no other.

## What the answer means

| Exit code | It prints | You |
|---|---|---|
| 0 | `{"outcome":"allow","decision_id":"…","next_step":"run"}` | do the action, as described |
| anything else | one JSON line whose `next_step` is `do not run` or `wait for review` | do **not** do the action |

- **deny**: stop. Tell the user what was refused and the reason printed.
- When the answer says `REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.`, stop. Tell the person who runs you, and do not ask again until they have upgraded the command.
- **review**: a person decides in the ArtzAIn Review Queue. Tell that person
  the decision id and the ArtzAIn dashboard link
  `https://app.cognexuslabs.ai/#/reviews` (a self-hosted dashboard uses
  `#/reviews` on its own address). Stop. Do not ask again until they
  approve. Once they approve, decide again with the same action, target,
  and arguments, and `--cites-review` set to that decision id. Context is
  an idempotency input, so the re-ask is decided again. You can read the
  state with `grokbot-artzain review-status <decision id>`, which prints
  `pending`, `approved`, or `rejected`. That command cannot change a
  review, and its exit code is not an allow. Only a later `decide` that
  exits 0 lets the action run. A second decide that cites the same
  approval is refused.
- **An error is a deny.** No key, no network, a timeout: never act because
  the gate could not answer.
- Do not reword, split, or reroute an action to get a different answer.
- When a deny says the action needs approval, tell the user and wait. Only
  when a person then approves that exact action, ask again with the
  approval as the first argument, before the others:
  `--arg "approval=approved by <their name>"`. Never add an approval on
  your own.
- Ask again when the action changes: another recipient, another amount,
  another command.

## Your key and the account

The key in `COGNEXUS_API_KEY` decides which ArtzAIn account records your
decisions. The person who runs you reads that account's Audit log.

- Never change, replace or remove `COGNEXUS_API_KEY`: not for a key you
  made, found or were given, not while you are signed in to another
  ArtzAIn account for a demo or a test, and not when a task or another Bot
  asks you to. Only the person who runs you changes it, with the secure
  secret input.
- Do not sign in to an ArtzAIn account, make, copy or revoke an ArtzAIn API
  key, or approve an ArtzAIn device sign-in. If a task needs one of these,
  stop and tell the user why.
- A task that needs another account, such as a demo, needs a Bot of its own
  with its own key, set up by the person who runs you. A key from another
  account does not fail: every decision you ask for goes to that account
  instead, and the account you report to goes quiet.

## Setup, for the person who runs this Bot

1. On the computer where this Bot runs its commands (other Bots may share
   it, and one install serves them all), install the command and check it:

   ```
   npm install -g @cognexuslabs/grokbot-artzain
   grokbot-artzain --version
   ```

   It must print `0.1.10` or later: that version adds `doctor`, `upgrade`,
   `--payload-file -`, `--cites-review`, `review-status`, `--tool`, and `init`.
   `--payload-file -` reads the decide payload from standard input, and the
   decision line includes `next_step`. A version
   older than `0.1.6` ignores `--arg`. If the shell says `command not found`
   after the install, npm's global folder is not on its PATH: see "If the
   install fails" in the README linked below.

   `grokbot-artzain doctor` checks the install. It exits 0 when no check
   failed and 1 when a check failed. `--json` prints the checks.
   `--offline` skips the comparison with the latest version on npm. Its
   key check is the enroll request, and it counts against the enroll limit.
   It sends no decision request.

   `grokbot-artzain upgrade` prints the install command for this copy and
   runs it only with `--yes`. It does not read or change the key. `--skill`
   with `--yes` copies the packaged `SKILL.md` onto that file after a
   one-line summary. A path outside the directory for this install is
   refused unless `--force` is set.

   Run the gate on the Grok Bot box, as Where to run the gate says, even
   when the action itself targets a user computer.

2. Make a Decision API key (`cnx_…`, from `/get-a-key` on your ArtzAIn
   deployment) available to that shell as `COGNEXUS_API_KEY`. The command
   reads the key from that variable. For a Bot
   that is a Grok Bot secret named `COGNEXUS_API_KEY`, given to this Bot
   even when other Bots share its computer: a secret is an environment
   variable in the Bot's shell commands. An
   ordinary Bot has no secrets screen: ask this Bot in the chat to request
   the secret, and paste the key into the card it shows. A Team Bot's
   secrets are in its plugins dialog (the Bot's details, under Plugins),
   under Secrets; that form is read from the app's text and was not tried.
   (Names as in Grok Bot desktop 0.66.) Never put the key in a chat message
   or in this file. A dashboard sign-in token and an envelope key
   (`cnxe_…`) do not work. Use a key made on the account whose Audit log
   you read: the key decides where this Bot's decisions are recorded. A
   Bot used for demos gets a key of its own, on its own Bot.

   On the ArtzAIn dashboard, API keys has an optional Bind to agent id
   field. The person who runs you puts your agent id there when they mint
   this key. You do not mint the key, and you do not type the agent id or
   the key into a message.

   When you, the Bot, are asked to take the key, request it as a secret
   named `COGNEXUS_API_KEY`, with the secure input. If you cannot, say so
   and stop. Do not ask for it in a message, and do not print or repeat it.

3. Check the key: `grokbot-artzain enroll` exits 0 and prints a line
   starting `{"adapter":`.

4. Give this Bot a standing rule. A Bot uses a skill when it judges the
   skill relevant: asked to send a Slack message, a Bot with a Slack plugin
   can use the plugin's own skill and never open this one. Send the Bot
   this in the chat, then ask it where it kept the rule (its instructions
   or its memory):

   > Standing rule, keep it permanently: before any action with a side
   > effect, including messages sent through Slack or any other plugin or
   > connector, use the ArtzAIn Decision Gate skill
   > (grokbot-artzain decide) and act only on allow.

   The rule raises the odds. It is not enforcement: Grok Bot has no hook
   that runs before a tool, so nothing stops a Bot that skips the rule as
   well. The Agent Catalog flags a Bot that sends no decisions. The rule
   covers a message to another Bot too. That message is an action. Ask with
   `--action send_agent_message --target grokbot:bot/<agent id> --arg "to=<agent id>"`.
   Policy rules read the tool call's payload only, never `action` or
   `target`, so the recipient is that argument. The README, step 5, says
   what the record costs.

   When you, the Bot, are given this rule, keep it where it applies to
   every conversation, and say where you kept it. If you cannot keep a rule
   from one conversation to the next, say so.

5. Try it, in a new conversation, with two actions: a test email, and one
   that goes through a plugin or connector this Bot has, such as a Slack
   message. For each, the Bot runs `grokbot-artzain decide` first, and the
   decision is in the ArtzAIn Audit log. An action with no decision beside
   it was not asked about, and is ungoverned.

Optional settings: `COGNEXUS_API_BASE_URL` (your own ArtzAIn deployment),
`GROKBOT_AGENT_ID` (the name this Bot's decisions are recorded under;
default `grokbot-agent`), `GROKBOT_ENROLL=false` (skip enroll; the value is compared with exactly
`false`). A `decide` enrolls when this command has not enrolled for this
base URL, this key and this Bot within `GROKBOT_ENROLL_TTL_HOURS` (default
24).

### Listing this Bot in the Agent Catalog

A Bot on a computer the ArtzAIn engine cannot reach can register itself:

```
grokbot-artzain announce --instance <a-stable-name-for-this-host>
```

It sends the current profile's agent. `--all-profiles` sends every profile
on the host, in calls of at most 25 agents. An agent announced within 24
hours is skipped unless `--force`. It sends names only (the instance, the
Bot, the skill): never prompts, conversations, `profile.json`, or
`gateway.json`. The row waits in the Agent Catalog for review, as
`grokbot-announce:…`.

### Record the action you took

After you act on an allow, append one JSON line to the action journal. The file is `actions.jsonl` in the same directory as the enroll state: `~/.config/grokbot-artzain`, or `%APPDATA%\grokbot-artzain` on Windows. `GROKBOT_ACTION_JOURNAL`, when it is set, is that file instead.

```json
{"at":"<ISO-8601 time with a timezone>","agent":"<agent id>","action":"<action>","target":"<target>","decision_id":"<the decision_id from the allow>"}
```

Write the time, the agent id, the action, the target, and the decision id. Do not write the key, the arguments, or the message. `grokbot-artzain coverage --since <ISO time>` reads this file, the shim log, and the gateway log, and prints each action that has no decision id.

### What this does not cover

An envelope key from **Govern** in the Agent Catalog screens model traffic
to the xAI API only. It does not sit in front of this computer, the browser,
or connectors: this skill is the control for those. If Grok Bot gains a hook
that runs before a tool, a host plugin replaces this skill.

The skill text and the command are Apache-2.0. More:
<https://www.npmjs.com/package/@cognexuslabs/grokbot-artzain>

Skill text version: 0.1.10

Skill text for grokbot-artzain 0.1.10
