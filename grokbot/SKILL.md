---
name: ArtzAIn Decision Gate
description: Use first, before any action with a side effect, whatever tool performs it - a plugin, a connector, another skill, the browser or a shell command. Covers sending an email or a Slack, Teams or other chat message, posting, buying or paying, running a command that changes or deletes something, and writing to another system. It asks CogNEXUS whether the action is allowed, so ask here first, then use the plugin or tool. Anything but "allow" means do not act.
---

# ArtzAIn Decision Gate

Before any action with a side effect, ask CogNEXUS. Act only on **allow**.

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

An action a plugin or connector will take is asked about the same way. Name
the action and what it acts on:

```
grokbot-artzain decide --action post_message --target slack --arg "channel=ops-alerts" --arg "text=Deploy finished"
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
- When a deny says the action needs approval, tell the user and wait. Only
  when a person then approves that exact action, ask again with the
  approval as the first argument, before the others:
  `--arg "approval=approved by <their name>"`. Never add an approval on
  your own.
- Ask again when the action changes: another recipient, another amount,
  another command.

## Setup, for the person who runs this Bot

1. On the computer where this Bot runs its commands, install the command
   and check it:

   ```
   npm install -g @cognexuslabs/grokbot-artzain
   grokbot-artzain --version
   ```

   It must print `0.1.6` or later: an older version ignores `--arg`. If
   the shell says `command not found` after the install, npm's global
   folder is not on its PATH: see "If the install fails" in the README
   linked below.

2. Make a Decision API key (`cnx_…`, from `/get-a-key` on your CogNEXUS
   deployment) available to that shell as `COGNEXUS_API_KEY`. On the Bot's
   own computer that is a Grok Bot secret named `COGNEXUS_API_KEY`: a
   secret is an environment variable in the Bot's shell commands. An
   ordinary Bot has no secrets screen: ask this Bot in the chat to request
   the secret, and paste the key into the card it shows. A Team Bot's
   secrets are in its plugins dialog (the Bot's details, under Plugins),
   under Secrets; that form is read from the app's text and was not tried.
   (Names as in Grok Bot desktop 0.66.) Never put the key in a chat message
   or in this file. A dashboard sign-in token and an envelope key
   (`cnxe_…`) do not work.

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
   covers the messages Bots send to each other too: the README, step 5,
   says what that costs and how a rule can leave them out.

   When you, the Bot, are given this rule, keep it where it applies to
   every conversation, and say where you kept it. If you cannot keep a rule
   from one conversation to the next, say so.

5. Try it, in a new conversation, with two actions: a test email, and one
   that goes through a plugin or connector this Bot has, such as a Slack
   message. For each, the Bot runs `grokbot-artzain decide` first, and the
   decision is in the CogNEXUS Audit log. An action with no decision beside
   it was not asked about, and is ungoverned.

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
