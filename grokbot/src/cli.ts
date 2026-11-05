#!/usr/bin/env node
/**
 * Cooperative CLI for a Grok Bot skill.
 *
 *   grokbot-artzain decide --action send_email --target mailbox --arg "to=ops@example.com"
 *   grokbot-artzain decide --queue --action send_email --arg "to=ops@example.com"
 *   grokbot-artzain queue list
 *   grokbot-artzain queue retry
 *   grokbot-artzain decide --action send_email --payload '{"tool":"send_email"}'
 *   grokbot-artzain announce
 *   grokbot-artzain enroll
 *   grokbot-artzain doctor
 *   grokbot-artzain upgrade
 *   grokbot-artzain review-status <decision id>
 *   grokbot-artzain evidence <decision id>
 *   grokbot-artzain mcp
 *   grokbot-artzain skill
 *   grokbot-artzain skill --check <path>
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

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { announceInstance } from "./announce.js";
import {
  defaultGatewayLog,
  defaultJournal,
  defaultShimLog,
  postCoverageReport,
  runCoverage,
} from "./coverage.js";
import {
  DecisionError,
  decisionContext,
  dimensionId,
  failureKind,
  getReviewStatus,
  lookupAuditDecision,
  resolveApiKey,
  resolveBaseUrlSetting,
  type FetchLike,
} from "./client.js";
import { formatDoctorText, runDoctor } from "./doctor.js";
import { enrollInstance } from "./enroll.js";
import { decisionPayload, gateToolCall, type SkillConfig } from "./gate.js";
import { serveMcpHttp, serveMcpStdio } from "./mcp/server.js";
import { readProfile, writeProfile, type BotProfile } from "./profile.js";
import { resolveSandRoot, selectAnnounceAgents } from "./profiles.js";
import { decisionWasUnreachable, enqueueDecision, listQueue, retryQueue } from "./queue.js";
import { runShims } from "./shims/command.js";
import {
  announceIsFresh,
  announceStateKey,
  currentCliVersion,
  readEnrollState,
  recordAnnounces,
} from "./state.js";
import { classifyTool } from "./taxonomy.js";
import { runUpgrade } from "./upgrade.js";

/**
 * How long an announce or enroll still in flight once `decide` has its
 * verdict may run on before it is cut off. They are telemetry: the exit,
 * which carries the verdict, must not wait out their own 10-second timeout.
 */
const TELEMETRY_GRACE_MS = 2_000;

const USAGE = `usage: grokbot-artzain <command> [options]

  decide     ask before a side-effect: exit 0 = allow, any other exit = do not act
               --action <name>          taxonomy action; wins over --tool
               --tool <connector name>  map a connector tool to an action and a target
               --target <resource>
               --arg <name>=<value>     one per argument of the tool call
               --payload '<json>'       the whole tool call, in place of --arg
               --payload-file <path>    the same, from a file, or - for standard input
               --request-id <id>
               --cites-review <id>      cite an approved review; decided again
               --model <id>             model_id on the request
               --workload <id>          workload_id on the request
               --session <id>           sent in context
               --parent <decision id>   sent in context
               --on-behalf-of <principal>  sent in context
               --announce               also announce (see announce)
               --no-enroll              skip the enroll that goes beside the decision
               --queue                  when the engine cannot be reached, store the request; still exit 2
  queue      a decide the engine could not be asked
               list                     print the stored requests
               retry                    replay each with its original request id
  review-status  print pending, approved, or rejected; it cannot change a review
               <decision id>            required
  evidence   print how to check one sealed decision; it does not verify the bundle
               <decision id>            required
  mcp        answer MCP calls on stdin; it does not run the tool
               --http                   listen for HTTP instead of stdin
               --port <n>               with --http, on 127.0.0.1
  announce   list this Bot in the Agent Catalog (needs --instance or GROKBOT_INSTANCE)
               --all-profiles           every profile on this host
               --force                  announce again within 24 hours
  enroll     print the adapter this Bot should use; a way to check the key and URL
               --enroll-token <token>   redeem a one-time token for an envelope key
  doctor     check this install: exit 0 when no check failed, exit 1 when one did
               --json                   print the checks as JSON
               --offline                skip the comparison with the latest version on npm
  upgrade    print the command that installs the latest version; --yes runs it
               --yes                    run that command
               --skill <path>           with --yes, copy the packaged SKILL.md onto this file
               --force                  allow --skill outside the directory this install expects
  skill      print the path of the SKILL.md to add to the Bot
               --check <path>           compare an installed copy: current, or behind
  init       save a Bot profile (agent id, instance, base URL, key env name)
               --bot <name>             required
               --key-env <NAME>         the variable that holds the key, never the key
  shims      install or remove command wrappers for one profile
               install                  log-only, unless --enforce
               uninstall                remove the files that install wrote
               --enforce                with install, block any outcome other than allow
               --profile <name>         the profile that opts in; else GROKBOT_BOT
  coverage   list actions since a time that have no decision id
               --since <ISO time>       required, with a timezone
               --shim-log <path>        the shim log; default shim.jsonl
               --gateway-log <path>     the gateway log
               --journal <path>         the action journal
  --version  print the version
  --help     print this text

  decide, announce, enroll, doctor, queue, review-status, evidence, coverage and mcp: --api-key <key>  --base-url <url>  --agent-did <id>  --instance <name>  --profile <name>
  environment: COGNEXUS_API_KEY  COGNEXUS_API_BASE_URL  GROKBOT_AGENT_ID  COGNEXUS_AGENT_DID
               GROKBOT_INSTANCE  GROKBOT_BOT  GROKBOT_REQUIRE_IDENTITY
               GROKBOT_ANNOUNCE  GROKBOT_ENROLL  GROKBOT_ENROLL_TOKEN  GROKBOT_ENROLL_TTL_HOURS
               GROKBOT_ANNOUNCE_AGENTS  GROKBOT_ANNOUNCE_SKILLS
               GROKBOT_ACTION_JOURNAL
`;

/** Options every command that calls the engine takes. Each has a value. */
const SHARED = ["--api-key", "--base-url", "--agent-did", "--instance", "--profile"];

/** The options of each command: those followed by a value, and switches. */
const OPTIONS: Record<string, { valued: string[]; switches: string[] }> = {
  decide: {
    valued: [
      ...SHARED,
      "--action",
      "--tool",
      "--target",
      "--arg",
      "--payload",
      "--payload-file",
      "--request-id",
      "--cites-review",
      "--model",
      "--workload",
      "--session",
      "--parent",
      "--on-behalf-of",
    ],
    switches: ["--announce", "--no-enroll", "--queue"],
  },
  queue: { valued: SHARED, switches: [] },
  "review-status": { valued: SHARED, switches: [] },
  evidence: { valued: SHARED, switches: [] },
  mcp: { valued: [...SHARED, "--port"], switches: ["--http"] },
  announce: { valued: SHARED, switches: ["--all-profiles", "--force"] },
  enroll: { valued: [...SHARED, "--enroll-token"], switches: [] },
  doctor: { valued: SHARED, switches: ["--json", "--offline"] },
  upgrade: { valued: ["--skill"], switches: ["--yes", "--force"] },
  skill: { valued: ["--check"], switches: [] },
  init: {
    valued: ["--bot", "--agent-did", "--instance", "--base-url", "--key-env"],
    switches: [],
  },
  shims: { valued: ["--profile"], switches: ["--enforce"] },
  coverage: {
    valued: [...SHARED, "--since", "--shim-log", "--gateway-log", "--journal"],
    switches: [],
  },
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

/**
 * `review-status` and `evidence` take one decision id, and the shared
 * options. The id is not an option, so it is lifted out before the strict
 * reader sees the line.
 */
function decisionIdArgs(
  command: string,
  args: string[],
): { id: string; flags: string[] } | { problem: string } {
  const valued = new Set(OPTIONS[command]?.valued ?? []);
  const flags: string[] = [];
  let id = "";
  for (let i = 0; i < args.length; i++) {
    const word = args[i] ?? "";
    if (valued.has(word)) {
      flags.push(word);
      const value = args[i + 1];
      if (value !== undefined) {
        flags.push(value);
        i++;
      }
      continue;
    }
    if (word.startsWith("-")) {
      flags.push(word);
      continue;
    }
    if (id) return { problem: `${command} takes one decision id` };
    id = word;
  }
  if (!id) return { problem: `${command} needs a decision id` };
  return { id, flags };
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
 * Text as written by any editor or shell: UTF-8, with or without a byte
 * order mark, or the UTF-16 that `>` writes in Windows PowerShell 5.1.
 * A here-string piped by that shell arrives as UTF-8 with a byte order mark.
 */
function decodeText(bytes: Buffer): string {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString("utf16le");
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return bytes.subarray(3).toString("utf8");
  return bytes.toString("utf8");
}

function readText(path: string): string {
  return decodeText(readFileSync(path));
}

/** `--payload-file -`. A terminal is not a payload, so it is not read. */
function readStdin(): Promise<string> {
  if (process.stdin.isTTY) {
    return Promise.reject(Object.assign(new Error("stdin is a terminal"), { code: "ENOTTY" }));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const onData = (chunk: Buffer | string) => {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    };
    const finish = (err?: Error) => {
      process.stdin.off("data", onData);
      process.stdin.off("end", onEnd);
      process.stdin.off("error", onError);
      if (err) reject(err);
      else resolve(decodeText(Buffer.concat(chunks)));
    };
    const onEnd = () => finish();
    const onError = (err: Error) => finish(err);
    process.stdin.on("data", onData);
    process.stdin.on("end", onEnd);
    process.stdin.on("error", onError);
  });
}

/**
 * The last `Skill text for grokbot-artzain <version>` line in a saved skill.
 * The body is what a save keeps, so the line is read wherever it sits.
 */
function savedSkillVersion(text: string): string | undefined {
  let found: string | undefined;
  for (const match of text.matchAll(/^skill text for grokbot-artzain (\d+\.\d+\.\d+)\s*$/gim)) {
    found = match[1];
  }
  return found;
}

function packagedVersion(): string {
  const parsed = JSON.parse(readText(shipped("package.json"))) as { version?: unknown };
  if (typeof parsed.version !== "string" || !/^\d+\.\d+\.\d+$/.test(parsed.version)) {
    throw new Error("version");
  }
  return parsed.version;
}

/** Negative when `left` is an older dotted version than `right`. */
function compareDotted(left: string, right: string): number {
  const a = left.split(".");
  const b = right.split(".");
  const width = Math.max(a.length, b.length);
  for (let i = 0; i < width; i++) {
    const da = Number(a[i] ?? "0");
    const db = Number(b[i] ?? "0");
    if (da !== db) return da < db ? -1 : 1;
  }
  return 0;
}

/**
 * `skill --check <path>`: the installed copy against the version in
 * package.json. The same version is current (exit 0). An older one is
 * behind (exit 1). A missing file or a copy with no footer exits 2.
 */
function checkInstalledSkill(
  path: string | undefined,
  log: (msg: string) => void,
  print: (msg: string) => void,
): number {
  if (!path) {
    log("grokbot-artzain skill: --check needs the path of the installed skill");
    return 2;
  }
  let text: string;
  try {
    text = readText(path);
  } catch (err) {
    log(`grokbot-artzain skill: the installed skill could not be read (${errorCode(err)})`);
    return 2;
  }
  const installed = savedSkillVersion(text);
  if (!installed) {
    log("grokbot-artzain skill: the installed skill has no 'Skill text for grokbot-artzain' line");
    return 2;
  }
  let packaged: string;
  try {
    packaged = packagedVersion();
  } catch (err) {
    log(`grokbot-artzain skill: its package.json could not be read (${errorCode(err)})`);
    return 2;
  }
  const order = compareDotted(installed, packaged);
  if (order === 0) {
    print(`current: skill text for grokbot-artzain ${installed}`);
    return 0;
  }
  if (order < 0) {
    print(`behind: skill text for grokbot-artzain ${installed}, this package is ${packaged}`);
    return 1;
  }
  print(`the installed skill text is ${installed}, and this package is ${packaged}`);
  return 1;
}

/**
 * The tool call `decide` was given, one of three ways: `--arg` pairs, which
 * need no JSON quoting; `--payload`, a JSON text; or `--payload-file`, the
 * same read from a file, or from standard input when the path is `-`.
 * A `problem` is a command line that names no one tool call to ask about,
 * and the call is blocked unasked.
 */
async function toolCallFrom(
  line: CommandLine,
): Promise<{ params?: Record<string, string>; payload?: string; problem?: string }> {
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
      text = file === "-" ? await readStdin() : readText(file);
    } catch (err) {
      return { problem: `--payload-file could not be read (${errorCode(err)})` };
    }
    // An empty payload would be asked about as a call with no arguments.
    if (!text.trim()) return { problem: "the --payload-file is empty" };
    return { payload: text };
  }
  return { payload };
}

/** String arguments from a JSON tool call, for filling a target template. */
function argsInPayload(payload: string | undefined): Record<string, string> {
  if (!payload) return {};
  try {
    const parsed = JSON.parse(payload) as { arguments?: unknown; args?: unknown; params?: unknown; input?: unknown };
    const bag = parsed?.arguments ?? parsed?.args ?? parsed?.params ?? parsed?.input;
    if (!bag || typeof bag !== "object" || Array.isArray(bag)) return {};
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(bag)) {
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        out[key] = String(value);
      }
    }
    return out;
  } catch {
    return {};
  }
}

/** The payload with its tool field set to the action the rules will read. */
function payloadForAction(payload: string, action: string): string {
  try {
    const parsed = JSON.parse(payload) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return payload;
    parsed.tool = action;
    return JSON.stringify(parsed);
  } catch {
    return payload;
  }
}

function isJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Flag, then environment, then the selected profile, then the default.
 * `--profile` selects the profile, and `GROKBOT_BOT` selects it when the
 * flag is absent. A missing profile is a problem: the engine is not asked
 * about some other Bot. `fellBack` is a decide with no agent id, which
 * the gate records as grokbot-agent.
 */
async function loadConfig(
  line: CommandLine,
): Promise<{ config: SkillConfig; fellBack: boolean } | { problem: string }> {
  const skills = env("GROKBOT_ANNOUNCE_SKILLS");
  const agents = env("GROKBOT_ANNOUNCE_AGENTS");
  const option = (name: string) => line.values.get(name) ?? "";
  const selected = option("--profile") || env("GROKBOT_BOT");
  let profile: BotProfile | undefined;
  if (selected) {
    try {
      profile = await readProfile(selected);
    } catch (err) {
      const code = errorCode(err);
      return {
        problem: code === "EINVAL"
          ? "a profile name is letters, digits, and . _ -"
          : `the profile could not be read (${code})`,
      };
    }
  }
  const agentFlag = option("--agent-did");
  const agentEnv = env("GROKBOT_AGENT_ID") || env("COGNEXUS_AGENT_DID");
  const agentProfile = profile?.agent_id ?? "";
  const agentDid = agentFlag || agentEnv || agentProfile;
  const keyFlag = option("--api-key");
  const keyEnv = env("COGNEXUS_API_KEY");
  const keyFromProfile = !keyFlag && !keyEnv && profile?.key_env ? env(profile.key_env) : "";
  const baseFlag = option("--base-url");
  const baseEnv = env("COGNEXUS_API_BASE_URL");
  // Unset here, the gate reads COGNEXUS_API_BASE_URL and then the default,
  // and names that source when a request fails.
  const baseFromProfile = !baseFlag && !baseEnv ? profile?.base_url : undefined;
  return {
    fellBack: !agentDid,
    config: {
      apiKey: keyFlag || keyEnv || keyFromProfile,
      baseUrl: baseFlag || baseFromProfile || undefined,
      baseUrlSource: baseFlag ? "--base-url" : "profile",
      agentDid,
      instance: option("--instance") || env("GROKBOT_INSTANCE") || profile?.instance || "",
      announce: line.switches.has("--announce") || env("GROKBOT_ANNOUNCE") === "true",
      enroll: !(line.switches.has("--no-enroll") || env("GROKBOT_ENROLL") === "false"),
      enrollTtlHours: env("GROKBOT_ENROLL_TTL_HOURS") || undefined,
      enrollToken: option("--enroll-token") || env("GROKBOT_ENROLL_TOKEN") || undefined,
      announceAgents: agents ? agents.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
      announceSkills: skills ? skills.split(",").map((s) => s.trim()).filter(Boolean) : ["artzain"],
    },
  };
}

const NO_INSTANCE =
  "artzain announce skipped: set GROKBOT_INSTANCE (or pass --instance) to a stable name for this host";

/**
 * The text for a `client_update` warning: the release that is current, and
 * the command that installs it. Printed on stderr and carried as `notice`
 * on the one JSON line. Absent when the engine sent no such warning.
 */
function clientUpdateNotice(
  warnings: ReadonlyArray<Record<string, unknown>> | undefined,
): string | undefined {
  const row = (warnings ?? []).find((item) => item.warning === "client_update");
  if (!row) return undefined;
  const latest = typeof row.latest === "string" ? row.latest.trim() : "";
  const command = typeof row.upgrade_command === "string" ? row.upgrade_command.trim() : "";
  if (!latest && !command) return undefined;
  const available = latest
    ? `grokbot-artzain ${latest} is available`
    : "a newer grokbot-artzain is available";
  return command ? `${available}. ${command}` : available;
}

async function runQueue(
  args: string[],
  log: (msg: string) => void,
  print: (msg: string) => void,
): Promise<number> {
  const sub = args[0];
  if (sub !== "list" && sub !== "retry") {
    log(USAGE.trimEnd());
    return 2;
  }
  const line = readOptions("queue", args.slice(1));
  if ("problem" in line) {
    log(`grokbot-artzain queue: ${line.problem}`);
    return 2;
  }
  if (sub === "list") {
    const listed = await listQueue();
    for (const note of listed.notes) log(note);
    for (const entry of listed.entries) print(`${entry.request_id} ${entry.action} ${entry.queued_at}`);
    return 0;
  }
  const loaded = await loadConfig(line);
  if ("problem" in loaded) {
    log(`grokbot-artzain queue: ${loaded.problem}`);
    return 2;
  }
  const cfg = loaded.config;
  const apiKey = resolveApiKey(cfg.apiKey);
  if (!apiKey) {
    log("grokbot-artzain queue: set COGNEXUS_API_KEY or pass --api-key");
    return 2;
  }
  const report = await retryQueue({
    apiKey,
    fetchImpl,
    baseUrl: cfg.baseUrl ? resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource).url : undefined,
  });
  for (const note of report.notes) log(note);
  for (const record of report.records) {
    print(JSON.stringify({
      recorded: record.recorded,
      request_id: record.request_id,
      ...(record.decision_id ? { decision_id: record.decision_id } : {}),
    }));
  }
  // A recorded outcome stays a record. Exit 0 is what lets an action run.
  return report.records.length > 0 || report.pending > 0 ? 2 : 0;
}

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

  // These exit 0 without a decision when each is the whole command line.
  // `skill --check` is an option of `skill` and is read with the others.
  // With anything else after one of them the line is an unknown command,
  // exit 2.
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

  if (cmd === "queue") return runQueue(args, log, print);
  if (cmd === "shims") return runShims(args, log, print);

  if (!Object.hasOwn(OPTIONS, cmd)) {
    log(USAGE.trimEnd());
    return 2;
  }
  let decisionId = "";
  let optionArgs = args;
  if (cmd === "review-status" || cmd === "evidence") {
    const split = decisionIdArgs(cmd, args);
    if ("problem" in split) {
      log(`grokbot-artzain ${cmd}: ${split.problem}`);
      return 2;
    }
    decisionId = split.id;
    optionArgs = split.flags;
  }
  const line = readOptions(cmd, optionArgs);

  if (cmd === "coverage") {
    if ("problem" in line) {
      log(`grokbot-artzain coverage: ${line.problem}`);
      return 2;
    }
    const since = line.values.get("--since");
    if (!since) {
      log("grokbot-artzain coverage: --since is required");
      return 2;
    }
    const loaded = await loadConfig(line);
    if ("problem" in loaded) {
      log(`grokbot-artzain coverage: ${loaded.problem}`);
      return 2;
    }
    const cfg = loaded.config;
    return runCoverage({
      since,
      logs: {
        shim: line.values.get("--shim-log") || defaultShimLog(),
        gateway: line.values.get("--gateway-log") || defaultGatewayLog(),
        journal: line.values.get("--journal") || env("GROKBOT_ACTION_JOURNAL") || defaultJournal(),
      },
      report: (body) => {
        const apiKey = resolveApiKey(cfg.apiKey || undefined);
        if (!apiKey) {
          return Promise.resolve({
            ok: false as const,
            message: "artzain coverage: set COGNEXUS_API_KEY or pass --api-key to report the counts",
          });
        }
        return postCoverageReport({
          apiKey,
          baseUrl: cfg.baseUrl || "",
          baseSource: cfg.baseUrlSource || "default",
          report: body,
          fetchImpl,
        });
      },
      log,
      print,
    });
  }

  if (cmd === "init") {
    if ("problem" in line) {
      log(`grokbot-artzain init: ${line.problem}`);
      return 2;
    }
    const name = line.values.get("--bot");
    if (!name) {
      log("grokbot-artzain init: --bot is required");
      return 2;
    }
    const written = await writeProfile(name, {
      agent_id: line.values.get("--agent-did") || name,
      instance: line.values.get("--instance"),
      base_url: line.values.get("--base-url"),
      key_env: line.values.get("--key-env"),
    });
    if ("problem" in written) {
      log(`grokbot-artzain init: ${written.problem}`);
      return 2;
    }
    print(written.path);
    return 0;
  }

  if (cmd === "mcp") {
    if ("problem" in line) {
      log(`grokbot-artzain mcp: ${line.problem}`);
      return 2;
    }
    const http = line.switches.has("--http");
    const portText = line.values.get("--port");
    if (http !== (portText !== undefined)) {
      log("grokbot-artzain mcp: --http and --port go together");
      return 2;
    }
    const loaded = await loadConfig(line);
    if ("problem" in loaded) {
      log(`grokbot-artzain mcp: ${loaded.problem}`);
      return 2;
    }
    const cfg = loaded.config;
    const mcp = {
      config: {
        apiKey: cfg.apiKey,
        baseUrl: cfg.baseUrl,
        baseUrlSource: cfg.baseUrlSource,
        agentDid: cfg.agentDid,
        instance: cfg.instance,
      },
      fetchImpl,
      log,
    };
    try {
      if (http) {
        if (!portText || !/^\d+$/.test(portText)) {
          log("grokbot-artzain mcp: --port must be a whole number from 1 to 65535");
          return 2;
        }
        const port = Number(portText);
        if (port < 1 || port > 65535) {
          log("grokbot-artzain mcp: --port must be a whole number from 1 to 65535");
          return 2;
        }
        await serveMcpHttp({ ...mcp, port });
        return 0;
      }
      await serveMcpStdio(mcp);
      return 0;
    } catch (err) {
      log(`grokbot-artzain mcp: ${failureKind(err)}`);
      return 2;
    }
  }

  if (cmd === "decide") {
    // Everything `decide` prints on stdout is a verdict, so what it cannot
    // read is one too: a deny the engine was never asked for.
    const refuse = (problem: string): number => {
      print(JSON.stringify({
        outcome: "deny",
        error: `no decision asked for (${problem}) — failing closed`,
        next_step: "do not run",
      }));
      return 2;
    };
    if ("problem" in line) return refuse(line.problem);
    const explicitAction = line.values.get("--action");
    const connector = line.values.get("--tool");
    if (!explicitAction && !connector) return refuse("--action or --tool is required");
    const call = await toolCallFrom(line);
    if (call.problem) return refuse(call.problem);
    const callArgs = call.params ?? argsInPayload(call.payload);
    const mapped = connector ? classifyTool(connector, callArgs) : undefined;
    const action = explicitAction || mapped?.action;
    if (!action) return refuse("--action or --tool is required");
    const target = line.values.get("--target") || mapped?.target;
    const payload = call.payload === undefined ? undefined : payloadForAction(call.payload, action);
    if (payload !== undefined && !isJson(payload)) {
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
    const loaded = await loadConfig(line);
    if ("problem" in loaded) return refuse(loaded.problem);
    if (loaded.fellBack && env("GROKBOT_REQUIRE_IDENTITY") === "1") {
      return refuse("GROKBOT_REQUIRE_IDENTITY is set and no agent id was given");
    }
    if (loaded.fellBack) {
      log("grokbot-artzain: no agent id was given, so this decide uses grokbot-agent");
    }
    const cfg = loaded.config;
    if (cfg.announce && !cfg.instance) {
      log(NO_INSTANCE);
      cfg.announce = false;
    }
    const queued = line.switches.has("--queue");
    const requestId =
      (line.values.get("--request-id") ?? "").trim().slice(0, 64) || (queued ? randomUUID() : undefined);
    const result = await gateToolCall(
      { ...cfg, enrollToken: undefined },
      {
        toolName: action,
        target,
        params: call.params,
        payload,
        toolCallId: requestId,
        agentDid: cfg.agentDid,
        citesReview: line.values.get("--cites-review"),
        modelId: line.values.get("--model"),
        workloadId: line.values.get("--workload"),
        session: line.values.get("--session"),
        parent: line.values.get("--parent"),
        onBehalfOf: line.values.get("--on-behalf-of"),
      },
      fetchImpl,
    );
    const notice = clientUpdateNotice(result.allow ? result.decision.warnings : result.warnings);
    if (notice) log(notice);
    if (result.allow) {
      print(JSON.stringify({
        outcome: "allow",
        decision_id: result.decision.decision_id,
        next_step: "run",
        ...(notice ? { notice } : {}),
      }));
      return 0;
    }
    if (queued && decisionWasUnreachable(result.blockReason)) {
      try {
        const context = decisionContext({
          session: line.values.get("--session"),
          parent: line.values.get("--parent"),
          onBehalfOf: line.values.get("--on-behalf-of"),
          citesReview: line.values.get("--cites-review"),
        });
        const modelId = dimensionId(line.values.get("--model"));
        const workloadId = dimensionId(line.values.get("--workload"));
        const stored = await enqueueDecision({
          base_url: resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource).url,
          agent_did: cfg.agentDid || "grokbot-agent",
          action,
          target: target || `grokbot:tool:${action}`,
          payload: decisionPayload(action, call.params, payload),
          request_id: requestId ?? randomUUID(),
          product: `grokbot-artzain@${currentCliVersion()}`,
          ...(modelId ? { model_id: modelId } : {}),
          ...(workloadId ? { workload_id: workloadId } : {}),
          ...(Object.keys(context).length > 0 ? { context } : {}),
        });
        log(`queued ${stored.request_id}`);
      } catch (err) {
        log(`grokbot-artzain: the decision could not be queued (${errorCode(err)})`);
      }
    }
    const outcome = result.outcome || "deny";
    print(JSON.stringify({
      outcome,
      ...(result.decisionId ? { decision_id: result.decisionId } : {}),
      error: result.blockReason,
      next_step: outcome === "review" ? "wait for review" : "do not run",
      ...(notice ? { notice } : {}),
    }));
    return 2;
  }

  if ("problem" in line) {
    log(`grokbot-artzain ${cmd}: ${line.problem}`);
    return 2;
  }

  if (cmd === "review-status") {
    const loaded = await loadConfig(line);
    if ("problem" in loaded) {
      print(JSON.stringify({ outcome: "deny", error: `review status unavailable (${loaded.problem}). Failing closed.` }));
      return 2;
    }
    const cfg = loaded.config;
    const apiKey = resolveApiKey(cfg.apiKey);
    const refuse = (error: string): number => {
      print(JSON.stringify({ outcome: "deny", error }));
      return 2;
    };
    if (!apiKey) {
      return refuse("review status unavailable (No API key configured). Failing closed.");
    }
    try {
      const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
      const status = await getReviewStatus({
        apiKey,
        baseUrl: base.url,
        baseSource: base.source,
        decisionId,
        fetchImpl,
      });
      print(JSON.stringify({ decision_id: status.decision_id, status: status.status }));
      return 0;
    } catch (err) {
      const detail = err instanceof DecisionError ? err.message : "review status unavailable";
      return refuse(`${detail}. Failing closed.`);
    }
  }

  if (cmd === "evidence") {
    // A decision id is 26 letters and digits. Anything else is not sent: a
    // value pasted in its place can be the key, and a refusal must not print it.
    if (!/^[0-9A-Za-z]{26}$/.test(decisionId)) {
      log("grokbot-artzain evidence: a decision id is 26 letters and digits");
      return 2;
    }
    const loaded = await loadConfig(line);
    if ("problem" in loaded) {
      log(`grokbot-artzain evidence: audit log unavailable (${loaded.problem}). Failing closed.`);
      return 2;
    }
    const cfg = loaded.config;
    const apiKey = resolveApiKey(cfg.apiKey);
    if (!apiKey) {
      log("grokbot-artzain evidence: audit log unavailable (No API key configured). Failing closed.");
      return 2;
    }
    try {
      const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
      const lookup = await lookupAuditDecision({
        apiKey,
        baseUrl: base.url,
        baseSource: base.source,
        decisionId,
        fetchImpl,
      });
      if (!lookup.found) {
        log("grokbot-artzain evidence: no sealed decision with that id for this account");
        return 2;
      }
      // The verifier, not this command, reports the anchoring state. While
      // the Evidence Root is unpublished that state is SELF-ATTESTED.
      print("artzain audit export");
      print("artzain audit verify");
      print("Receipts verify as SELF-ATTESTED until the Evidence Root is published.");
      return 0;
    } catch (err) {
      const detail = err instanceof DecisionError ? err.message : "audit log unavailable";
      log(`grokbot-artzain evidence: ${detail}. Failing closed.`);
      return 2;
    }
  }

  if (cmd === "upgrade") {
    const result = await runUpgrade({
      yes: line.switches.has("--yes"),
      force: line.switches.has("--force"),
      skillPath: line.values.get("--skill"),
      env: process.env,
      fetchImpl,
    });
    if (result.stdout) print(result.stdout);
    if (result.stderr) log(result.stderr);
    return result.code;
  }

  const loaded = await loadConfig(line);
  if ("problem" in loaded) {
    log(`grokbot-artzain ${cmd}: ${loaded.problem}`);
    return 2;
  }
  const cfg = loaded.config;

  if (cmd === "announce") {
    if (!cfg.instance) {
      log(NO_INSTANCE);
      return 2;
    }
    const instance = cfg.instance;
    const selected = selectAnnounceAgents({
      allProfiles: line.switches.has("--all-profiles"),
      announceAgents: cfg.announceAgents,
      configuredAgent: cfg.agentDid,
      sandRoot: resolveSandRoot(process.env),
    });
    if (selected.problem) {
      log(selected.problem);
      return 2;
    }
    let due = selected.agents;
    if (!line.switches.has("--force")) {
      const apiKey = resolveApiKey(cfg.apiKey || undefined);
      if (apiKey) {
        try {
          const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
          const state = await readEnrollState();
          const now = Date.now();
          const skipped: string[] = [];
          due = [];
          for (const agent of selected.agents) {
            const fresh = announceIsFresh(
              state?.announces[announceStateKey(base.url, apiKey, instance, agent)],
              now,
            );
            if (fresh) skipped.push(agent);
            else due.push(agent);
          }
          for (const agent of skipped) {
            log(`artzain announce skipped: ${agent} was announced within 24 hours`);
          }
        } catch {
          due = selected.agents;
        }
      }
    }
    if (due.length === 0) return 0;
    const out = await announceInstance(
      { ...cfg, announce: true, announceAgents: due },
      fetchImpl,
      log,
      cfg.agentDid,
    );
    if (out.agentsSent && out.agentsSent.length > 0) {
      try {
        const apiKey = resolveApiKey(cfg.apiKey || undefined);
        if (apiKey) {
          const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
          await recordAnnounces(
            out.agentsSent.map((agent) => announceStateKey(base.url, apiKey, instance, agent)),
            new Date(),
          );
        }
      } catch (err) {
        log(`artzain announce could not record the time (${errorCode(err)})`);
      }
    }
    return out.ok ? 0 : 2;
  }

  if (cmd === "doctor") {
    const report = await runDoctor({
      env: process.env,
      fetchImpl,
      offline: line.switches.has("--offline"),
      apiKey: cfg.apiKey,
      baseUrl: cfg.baseUrl,
      agentId: cfg.agentDid,
      agentIdFromEnv: Boolean(env("GROKBOT_AGENT_ID") || env("COGNEXUS_AGENT_DID")),
      enrollEnabled: env("GROKBOT_ENROLL") !== "false",
      enrollTtlHours: env("GROKBOT_ENROLL_TTL_HOURS") || undefined,
      instance: cfg.instance,
      announceAgents: cfg.announceAgents,
      announceSkills: cfg.announceSkills,
    });
    print(line.switches.has("--json") ? JSON.stringify(report, null, 2) : formatDoctorText(report.checks));
    return report.ok ? 0 : 1;
  }

  if (cmd === "skill") return checkInstalledSkill(line.values.get("--check"), log, print);

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
