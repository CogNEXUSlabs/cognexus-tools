#!/usr/bin/env node
/**
 * Cooperative CLI for a Grok Bot skill.
 *
 *   grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com"
 *   grokbot-artzain decide --action send_email --payload '{"tool":"send_email"}'
 *   grokbot-artzain announce
 *   grokbot-artzain enroll
 *   grokbot-artzain skill
 *   grokbot-artzain --version
 *
 * `decide`: exit 0 = allow. Exit 2 = deny / review / engine refusal (fail
 * closed). Announce and enroll never change the exit code of `decide`.
 *
 * A caller acts on exit 0, so a command line is read strictly: a word that
 * is not an option of the command, an option with no value, and an option
 * given twice all exit 2 with nothing sent. Read loosely, a mistyped option
 * drops out and the engine is asked about a call with no arguments.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { announceInstance } from "./announce.js";
import type { FetchLike } from "./client.js";
import { enrollInstance } from "./enroll.js";
import { gateToolCall, type SkillConfig } from "./gate.js";

/**
 * How long an announce or enroll still in flight once `decide` has its
 * verdict may run on before it is cut off. They are telemetry: the exit,
 * which carries the verdict, must not wait out their own 10-second timeout.
 */
const TELEMETRY_GRACE_MS = 2_000;

const USAGE = `usage: grokbot-artzain <command> [options]

  decide     ask before a side-effect: exit 0 = allow, any other exit = do not act
               --action <tool>          required
               --target <resource>
               --arg <name>=<value>     one per argument of the tool call
               --payload '<json>'       the whole tool call, in place of --arg
               --payload-file <path>    the same, read from a file
               --request-id <id>
               --announce               also announce (see announce)
               --no-enroll              skip the enroll that goes beside the decision
  announce   list this Bot in the Agent Catalog (needs --instance or GROKBOT_INSTANCE)
  enroll     print the adapter this Bot should use; a way to check the key and URL
               --enroll-token <token>   redeem a one-time token for an envelope key
  skill      print the path of the SKILL.md to add to the Bot
  --version  print the version
  --help     print this text

  any of the first three: --api-key <key>  --base-url <url>  --agent-did <id>  --instance <name>
  environment: COGNEXUS_API_KEY  COGNEXUS_API_BASE_URL  GROKBOT_AGENT_ID  GROKBOT_INSTANCE
               GROKBOT_ANNOUNCE  GROKBOT_ENROLL  GROKBOT_ENROLL_TOKEN
               GROKBOT_ANNOUNCE_AGENTS  GROKBOT_ANNOUNCE_SKILLS
`;

/** Options every command that calls the engine takes. Each has a value. */
const SHARED = ["--api-key", "--base-url", "--agent-did", "--instance"];

/** The options of each command: those followed by a value, and switches. */
const OPTIONS: Record<string, { valued: string[]; switches: string[] }> = {
  decide: {
    valued: [...SHARED, "--action", "--target", "--arg", "--payload", "--payload-file", "--request-id"],
    switches: ["--announce", "--no-enroll"],
  },
  announce: { valued: SHARED, switches: [] },
  enroll: { valued: [...SHARED, "--enroll-token"], switches: [] },
};

/** Every option any command takes: none of them can be another's value. */
const EVERY_OPTION = new Set(Object.values(OPTIONS).flatMap((o) => [...o.valued, ...o.switches]));

interface CommandLine {
  /** The value of each option given, by name. `--arg` is in `pairs`. */
  values: Map<string, string>;
  /** Each `--arg` value, in order. */
  pairs: string[];
  switches: Set<string>;
}

/**
 * Reads a command's options. A `problem` names what cannot be read. It never
 * quotes a value: `--api-key=<key>` is one word, and a refusal must not
 * print the key in it.
 */
function readOptions(command: string, args: string[]): CommandLine | { problem: string } {
  const { valued, switches } = OPTIONS[command] ?? { valued: [], switches: [] };
  const line: CommandLine = { values: new Map(), pairs: [], switches: new Set() };
  for (let i = 0; i < args.length; i++) {
    const word = args[i] ?? "";
    if (switches.includes(word)) {
      line.switches.add(word);
      continue;
    }
    if (!valued.includes(word)) {
      const name = /^--[a-z][a-z-]*/.exec(word)?.[0];
      if (!name) return { problem: "a word that is not an option; put a value with a space in it in double quotes" };
      return {
        problem: word === name
          ? `${name} is not an option of ${command}`
          : `${name} was joined to something; an option and its value are two words`,
      };
    }
    const value = args[++i];
    if (value === undefined || EVERY_OPTION.has(value)) return { problem: `${word} has no value` };
    if (word === "--arg") {
      line.pairs.push(value);
      continue;
    }
    if (value === "") return { problem: `${word} is empty` };
    if (line.values.has(word)) return { problem: `${word} was given twice` };
    line.values.set(word, value);
  }
  return line;
}

/** Aborting it ends every request this CLI has made (see `fetchImpl`). */
const cutOff = new AbortController();

/** A signal that aborts when either of two does, with that one's reason. */
function either(a: AbortSignal | undefined, b: AbortSignal): AbortSignal {
  if (!a) return b;
  const both = new AbortController();
  for (const signal of [a, b]) {
    if (signal.aborted) {
      both.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => both.abort(signal.reason), { once: true });
  }
  return both.signal;
}

/**
 * Global fetch, with each request also ended by `cutOff`: a request still in
 * flight holds the process open.
 */
const fetchImpl: FetchLike | undefined =
  typeof globalThis.fetch === "function"
    ? (url, init) =>
        (globalThis.fetch as unknown as FetchLike)(url, {
          ...init,
          signal: either(init.signal, cutOff.signal),
        })
    : undefined;

function env(name: string): string {
  return (process.env[name] || "").trim();
}

/** A file this package ships beside `dist/`: `package.json`, `SKILL.md`. */
function shipped(name: string): string {
  return fileURLToPath(new URL(`../${name}`, import.meta.url));
}

/** The code of a file-system error (`ENOENT`), which names no path. */
function errorCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "Error";
}

/**
 * A text file as written by any editor or shell: UTF-8, with or without a
 * byte order mark, or the UTF-16 that `>` writes in Windows PowerShell 5.1.
 */
function readText(path: string): string {
  const bytes = readFileSync(path);
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString("utf16le");
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return bytes.subarray(3).toString("utf8");
  return bytes.toString("utf8");
}

/**
 * The tool call `decide` was given, one of three ways: `--arg` pairs, which
 * need no JSON quoting; `--payload`, a JSON text; or `--payload-file`, the
 * same read from a file. A `problem` is a command line that names no one
 * tool call to ask about, and the call is blocked unasked.
 */
function toolCallFrom(
  line: CommandLine,
): { params?: Record<string, string>; payload?: string; problem?: string } {
  const payload = line.values.get("--payload");
  const file = line.values.get("--payload-file");
  if (line.pairs.length > 0) {
    if (payload !== undefined || file !== undefined) {
      return { problem: "give the arguments as --arg pairs or as a payload, not both" };
    }
    const params = new Map<string, string>();
    for (const pair of line.pairs) {
      const at = pair.indexOf("=");
      if (at < 1) return { problem: "each --arg is <name>=<value>" };
      const name = pair.slice(0, at);
      if (params.has(name)) return { problem: "an --arg name was given twice" };
      params.set(name, pair.slice(at + 1));
    }
    return { params: Object.fromEntries(params) };
  }
  if (file !== undefined) {
    if (payload !== undefined) return { problem: "give --payload or --payload-file, not both" };
    let text: string;
    try {
      text = readText(file);
    } catch (err) {
      return { problem: `--payload-file could not be read (${errorCode(err)})` };
    }
    // An empty payload would be asked about as a call with no arguments.
    if (!text.trim()) return { problem: "the --payload-file is empty" };
    return { payload: text };
  }
  return { payload };
}

function isJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

function configFrom(line: CommandLine): SkillConfig {
  const skills = env("GROKBOT_ANNOUNCE_SKILLS");
  const agents = env("GROKBOT_ANNOUNCE_AGENTS");
  const option = (name: string) => line.values.get(name) ?? "";
  return {
    apiKey: option("--api-key") || env("COGNEXUS_API_KEY"),
    // Unset without the flag: the gate reads COGNEXUS_API_BASE_URL itself and
    // names it, not the flag, when a request fails.
    baseUrl: option("--base-url") || undefined,
    baseUrlSource: "--base-url",
    agentDid: option("--agent-did") || env("GROKBOT_AGENT_ID") || env("COGNEXUS_AGENT_DID"),
    instance: option("--instance") || env("GROKBOT_INSTANCE"),
    announce: line.switches.has("--announce") || env("GROKBOT_ANNOUNCE") === "true",
    enroll: !(line.switches.has("--no-enroll") || env("GROKBOT_ENROLL") === "false"),
    enrollToken: option("--enroll-token") || env("GROKBOT_ENROLL_TOKEN") || undefined,
    announceAgents: agents ? agents.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    announceSkills: skills ? skills.split(",").map((s) => s.trim()).filter(Boolean) : ["artzain"],
  };
}

const NO_INSTANCE =
  "artzain announce skipped: set GROKBOT_INSTANCE (or pass --instance) to a stable name for this host";

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0] || "decide";
  const args = argv.slice(1);
  const log = (msg: string) => {
    try {
      console.error(msg);
    } catch {
      /* ignore */
    }
  };
  const print = (msg: string) => {
    try {
      console.log(msg);
    } catch {
      /* ignore */
    }
  };

  // These three exit 0 without a decision, so each is read only when it is
  // the whole command line. With anything after one of them the line is an
  // unknown command, exit 2.
  const alone = args.length === 0;
  if (alone && (cmd === "--help" || cmd === "-h" || cmd === "help")) {
    print(USAGE.trimEnd());
    return 0;
  }
  if (alone && (cmd === "--version" || cmd === "-v" || cmd === "version")) {
    try {
      print(String((JSON.parse(readFileSync(shipped("package.json"), "utf8")) as { version?: unknown }).version));
      return 0;
    } catch (err) {
      log(`grokbot-artzain: its package.json could not be read (${errorCode(err)})`);
      return 2;
    }
  }
  if (alone && cmd === "skill") {
    const path = shipped("SKILL.md");
    try {
      readFileSync(path);
    } catch (err) {
      log(`grokbot-artzain: its SKILL.md could not be read (${errorCode(err)})`);
      return 2;
    }
    print(path);
    return 0;
  }

  if (!Object.hasOwn(OPTIONS, cmd)) {
    log(USAGE.trimEnd());
    return 2;
  }
  const line = readOptions(cmd, args);

  if (cmd === "decide") {
    // Everything `decide` prints on stdout is a verdict, so what it cannot
    // read is one too: a deny the engine was never asked for.
    const refuse = (problem: string): number => {
      print(JSON.stringify({ outcome: "deny", error: `no decision asked for (${problem}) — failing closed` }));
      return 2;
    };
    if ("problem" in line) return refuse(line.problem);
    const action = line.values.get("--action");
    if (!action) return refuse("--action is required");
    const call = toolCallFrom(line);
    if (call.problem) return refuse(call.problem);
    if (call.payload !== undefined && !isJson(call.payload)) {
      // Sent as it is: the engine refuses a tool call that is not JSON, and
      // that refusal is the decision. This line is why it will.
      log(
        line.values.has("--payload-file")
          ? "grokbot-artzain: the --payload-file does not hold valid JSON, which the engine refuses."
          : "grokbot-artzain: --payload is not valid JSON, which the engine refuses. cmd.exe and " +
              "Windows PowerShell take the double quotes out of an argument: give the arguments " +
              "as --arg <name>=<value>, or the JSON in a file with --payload-file.",
      );
    }
    const cfg = configFrom(line);
    if (cfg.announce && !cfg.instance) {
      log(NO_INSTANCE);
      cfg.announce = false;
    }
    const result = await gateToolCall(
      { ...cfg, enrollToken: undefined },
      {
        toolName: action,
        target: line.values.get("--target"),
        params: call.params,
        payload: call.payload,
        toolCallId: line.values.get("--request-id"),
        agentDid: cfg.agentDid,
      },
      fetchImpl,
    );
    if (result.allow) {
      print(JSON.stringify({ outcome: "allow", decision_id: result.decision.decision_id }));
      return 0;
    }
    print(JSON.stringify({ outcome: result.outcome || "deny", error: result.blockReason }));
    return 2;
  }

  if ("problem" in line) {
    log(`grokbot-artzain ${cmd}: ${line.problem}`);
    return 2;
  }
  const cfg = configFrom(line);

  if (cmd === "announce") {
    if (!cfg.instance) {
      log(NO_INSTANCE);
      return 2;
    }
    const out = await announceInstance({ ...cfg, announce: true }, fetchImpl, log, cfg.agentDid);
    return out.ok ? 0 : 2;
  }

  // enroll
  const out = await enrollInstance({ ...cfg, enroll: true }, fetchImpl, log, cfg.agentDid);
  if (out.ok) {
    print(JSON.stringify({
      adapter: out.adapter,
      decision: out.decision,
      envelope: out.envelope ?? null,
    }));
    return 0;
  }
  return 2;
}

// Not process.exit(): on Windows, ending the process that way just after an
// enroll or announce that ran beside the decision has finished can abort
// Node (a libuv assertion, exit code 3221226505) instead of exiting with
// this code. The process ends by itself once nothing is in flight. Idle
// keep-alive connections do not hold it, and whatever still runs is cut off
// after TELEMETRY_GRACE_MS. The timer is unref'd and holds nothing open.
process.exitCode = await main(process.argv.slice(2));
setTimeout(
  () => cutOff.abort(new DOMException("the CLI is exiting", "AbortError")),
  TELEMETRY_GRACE_MS,
).unref();
