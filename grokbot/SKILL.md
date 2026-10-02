---
name: ArtzAIn Decision Gate
description: Use before any action with a side effect - sending an email or a message, posting, buying or paying, running a command that changes or deletes something, writing to another system. It asks CogNEXUS whether the action is allowed. Anything but "allow" means do not act.
---

# ArtzAIn Decision Gate

Before any action with a side effect, ask CogNEXUS. Act only on **allow**.

Grok Bot has no hook that runs before a tool, so nothing calls this gate for
you: you call it yourself. An action taken without asking is ungoverned.

## What needs a decision

Ask before you:

- send an email, a text, or a chat message
- post or publish anything
- buy, pay, book, or move money
- run a command that changes or deletes files, data, or infrastructure
- write to another system: a CRM, a ticket, a repository, a calendar

Reading, searching, and drafting text you have not sent need no decision.

## How to ask

Run this, with one `--arg` for each argument of the action you are about to
take:

```
grokbot-artzain decide --action <tool> --target <resource> --arg <name>=<value>
```

For example:

```
grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com" --arg "subject=Q3 report"
```

- `--action` is the tool or action: `send_email`, `post_message`,
  `purchase`, `run_command`.
- `--target` is what it acts on: a mailbox, a channel, a shop, a host.
- Put each `--arg` pair in double quotes.
- When a value is long, or holds `$`, `%`, `&`, a quote, a backtick, a
  backslash or a line break (an email body, a script, an amount like
  $500), the shell would change it. Write the whole call as JSON,
  `{"tool":"<tool>","arguments":{…}}`, to a file and pass
  `--payload-file <path>` in place of the `--arg` pairs.
- Spell the options exactly as shown, each followed by its value as a
  separate word. A line the command cannot read is a deny.

Describe the action as you will really take it. The decision is for that
action and no other.

## What the answer means

| Exit code | It prints | You |
|---|---|---|
| 0 | `{"outcome":"allow",…}` | do the action, as described |
| anything else | `{"outcome":"deny",…}` or `{"outcome":"review",…}` | do **not** do the action |

- **deny**: stop. Tell the user what was refused and the reason printed.
- **review**: a person decides in the CogNEXUS Review Queue. Stop, and tell
  the user the action is waiting for review. Do not ask again in a loop.
- **An error is a deny.** No key, no network, a timeout: never act because
  the gate could not answer.
- Do not reword, split, or reroute an action to get a different answer.
- Ask again when the action changes: another recipient, another amount,
  another command.

## Setup, for the person who runs this Bot

1. On the computer where this Bot runs its commands, install the command
   and check it:

   ```
   npm install -g @cognexuslabs/grokbot-artzain
   grokbot-artzain --version
   ```

   It must print `0.1.6` or later: an older version ignores `--arg`.

2. Make a Decision API key (`cnx_…`, from `/get-a-key` on your CogNEXUS
   deployment) available to that shell as `COGNEXUS_API_KEY`. Keep it in
   Grok Bot's secrets, not in the chat and not in this file. A dashboard
   sign-in token and an envelope key (`cnxe_…`) do not work.

3. Check the key: `grokbot-artzain enroll` exits 0 and prints a line
   starting `{"adapter":`.

Optional settings: `COGNEXUS_API_BASE_URL` (your own CogNEXUS deployment),
`GROKBOT_AGENT_ID` (the name this Bot's decisions are recorded under;
default `grokbot-agent`), `GROKBOT_ENROLL=false` (skip the enroll request
that goes beside each decision).

### Listing this Bot in the Agent Catalog

A Bot on a computer the CogNEXUS engine cannot reach can register itself:

```
grokbot-artzain announce --instance <a-stable-name-for-this-host>
```

It sends names only (the instance, the Bot, the skill): never prompts,
conversations, or `gateway.json`. The row waits in the Agent Catalog for
review, as `grokbot-announce:…`.

### What this does not cover

An envelope key from **Govern** in the Agent Catalog screens model traffic
to the xAI API only. It does not sit in front of this computer, the browser,
or connectors: this skill is the control for those. If Grok Bot gains a hook
that runs before a tool, a host plugin replaces this skill.

The skill text and the command are Apache-2.0. More:
<https://www.npmjs.com/package/@cognexuslabs/grokbot-artzain>
