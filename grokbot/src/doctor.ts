/**
 * `grokbot-artzain doctor` checks this install before a Bot relies on it.
 *
 * Text output follows `artzain local doctor`: one `[ok ]`, `[WARN]` or
 * `[FAIL]` line per check, and `->` plus a one-line fix under each that is
 * not ok. Exit 0 when no check failed. A warning keeps that exit code.
 *
 * The key check is the enroll request `grokbot-artzain enroll` makes. It
 * counts against the enroll limit. This file sends no decision request.
 * An enroll token is not redeemed: that token is single use.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { failureKind, DEFAULT_BASE_URL, resolveApiKey, type FetchLike } from "./client.js";
import { enrollInstance } from "./enroll.js";
import {
  currentCliVersion,
  enrollIsFresh,
  enrollStateKey,
  enrollTtlMs,
  keyFingerprint,
  readEnrollState,
  recordEnroll as writeEnrollRecord,
  type EnrollRecord,
  type EnrollState,
} from "./state.js";

export type DoctorStatus = "ok" | "warn" | "fail";

export interface DoctorCheck {
  name: string;
  status: DoctorStatus;
  summary: string;
  fix?: string;
}

export interface DoctorReport {
  /** True when no check failed. A warning leaves this true. */
  ok: boolean;
  checks: DoctorCheck[];
}

export interface DoctorInput {
  env?: Record<string, string | undefined>;
  fetchImpl?: FetchLike;
  offline?: boolean;
  platform?: NodeJS.Platform;
  /** `process.version`, such as `v20.11.0`. */
  nodeVersion?: string;
  /** `engines.node` from package.json, such as `>=18`. */
  engines?: string;
  /** The PATH value to search. */
  path?: string;
  exists?: (file: string) => boolean;
  /**
   * Effective PowerShell execution policy. When set, doctor does not ask
   * PowerShell. On Windows, omit it and the effective policy is read.
   */
  executionPolicy?: string;
  /** Tests substitute a reader that must not run when `executionPolicy` is set. */
  readExecutionPolicy?: () => string;
  nowMs?: number;
  cliVersion?: string;
  packageVersion?: string;
  /** Installed skill text. `null` means the file could not be read. */
  skillText?: string | null;
  readState?: () => Promise<EnrollState | null>;
  recordEnroll?: (key: string, version: string, at: Date) => Promise<void>;
  apiKey?: string;
  baseUrl?: string;
  /** Agent id `decide` would record under, including `--agent-did`. */
  agentId?: string;
  /**
   * Whether `GROKBOT_AGENT_ID` is set. A missing variable is a warning:
   * a Bot may pass `--agent-did` on each call. Omit to read `env`.
   */
  agentIdFromEnv?: boolean;
  /** When false, `decide` does not consult the enroll record. */
  enrollEnabled?: boolean;
  enrollTtlHours?: string;
  instance?: string;
  announceAgents?: string[];
  announceSkills?: string[];
}

const NPM_LATEST = "https://registry.npmjs.org/@cognexuslabs/grokbot-artzain/latest";
const PROBE_MS = 10_000;
const POLICY_OK = new Set(["remotesigned", "unrestricted", "bypass"]);

const KEY_FIX = "Set COGNEXUS_API_KEY to a Decision API key (it starts with cnx_).";
const PATH_FIX =
  "Install with npm install -g @cognexuslabs/grokbot-artzain. If it is still not found, " +
  "npm config get prefix prints the folder: the command is in its bin directory on Linux and macOS, " +
  "and in the folder itself on Windows. On the Bot's computer, link the command into a folder already on PATH.";
const CMD_FIX =
  "Reinstall with npm install -g @cognexuslabs/grokbot-artzain so grokbot-artzain.cmd is on PATH, " +
  "or run grokbot-artzain.cmd.";
const POLICY_FIX =
  "PowerShell is refusing npm's .ps1 launcher. Run grokbot-artzain.cmd, or allow local scripts with " +
  "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned.";
const CACHE_FIX =
  "Run grokbot-artzain enroll to refresh the record. It counts against the enroll limit, " +
  "and the next decide enrolls again until then.";
const REDIRECT_FIX =
  "Set COGNEXUS_API_BASE_URL to the address the API answers on. A redirect is not followed.";

function trimBase(url: string): string {
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 47) end--;
  return url.slice(0, end);
}

function envOf(input: DoctorInput): Record<string, string | undefined> {
  return input.env ?? process.env;
}

function apiKeyOf(input: DoctorInput): string {
  return resolveApiKey(input.apiKey, envOf(input)) ?? "";
}

function baseOf(input: DoctorInput): { url: string; source: string } | { problem: string } {
  const explicit = (input.baseUrl ?? "").trim();
  const fromEnv = (envOf(input).COGNEXUS_API_BASE_URL ?? "").trim();
  const raw = trimBase(explicit || fromEnv || DEFAULT_BASE_URL);
  const source = explicit ? "--base-url" : fromEnv ? "COGNEXUS_API_BASE_URL" : "default";
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { problem: "The base URL is not a URL. Set COGNEXUS_API_BASE_URL to an https address." };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { problem: "Set COGNEXUS_API_BASE_URL to an http or https address." };
  }
  if (parsed.username || parsed.password) {
    return { problem: "The base URL includes credentials. Set COGNEXUS_API_BASE_URL to the origin alone." };
  }
  return { url: raw, source };
}

function agentFromEnv(input: DoctorInput): boolean {
  if (input.agentIdFromEnv !== undefined) return input.agentIdFromEnv;
  const env = envOf(input);
  return Boolean((env.GROKBOT_AGENT_ID || env.COGNEXUS_AGENT_DID || "").trim());
}

function enrollOn(input: DoctorInput): boolean {
  if (input.enrollEnabled !== undefined) return input.enrollEnabled;
  return (envOf(input).GROKBOT_ENROLL ?? "").trim() !== "false";
}

interface Packaged {
  version: string;
  engines: string;
}

function packaged(): Packaged {
  try {
    const path = fileURLToPath(new URL("../package.json", import.meta.url));
    const parsed = JSON.parse(readFileSync(path, "utf8")) as {
      version?: unknown;
      engines?: { node?: unknown };
    };
    return {
      version: typeof parsed.version === "string" && parsed.version ? parsed.version : currentCliVersion(),
      engines: typeof parsed.engines?.node === "string" ? parsed.engines.node : "",
    };
  } catch {
    return { version: currentCliVersion(), engines: "" };
  }
}

function skillFile(): string {
  return fileURLToPath(new URL("../SKILL.md", import.meta.url));
}

/** The `Skill text version:` line in an installed SKILL.md. */
export function skillTextVersion(text: string): string | undefined {
  return /^skill text version:\s*(\d+\.\d+\.\d+)\s*$/im.exec(text)?.[1];
}

function nodeMeets(version: string, range: string): boolean | null {
  const got = version.trim().replace(/^v/i, "").split(".");
  const match = /^>=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*$/.exec(range.trim());
  if (!match) return null;
  const need = [match[1], match[2] ?? "0", match[3] ?? "0"];
  for (let i = 0; i < 3; i++) {
    const left = Number(got[i] ?? "0");
    const right = Number(need[i]);
    if (!Number.isInteger(left) || !Number.isInteger(right)) return null;
    if (left > right) return true;
    if (left < right) return false;
  }
  return true;
}

function compareDot(left: string, right: string): number | null {
  const a = left.split(".");
  const b = right.split(".");
  if (a.some((part) => !/^\d+$/.test(part)) || b.some((part) => !/^\d+$/.test(part))) return null;
  const width = Math.max(a.length, b.length);
  for (let i = 0; i < width; i++) {
    const da = Number(a[i] ?? "0");
    const db = Number(b[i] ?? "0");
    if (da !== db) return da < db ? -1 : 1;
  }
  return 0;
}

function pathList(value: string, platform: string): string[] {
  const sep = platform === "win32" ? ";" : ":";
  return value.split(sep).map((dir) => dir.trim()).filter(Boolean);
}

function childPath(dir: string, name: string, platform: string): string {
  const sep = platform === "win32" ? "\\" : "/";
  return `${dir.replace(/[\\/]+$/, "")}${sep}${name}`;
}

function defaultExecutionPolicy(): string {
  try {
    return execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
      { encoding: "utf8", timeout: 5_000, windowsHide: true },
    ).trim();
  } catch {
    return "";
  }
}

function policyText(input: DoctorInput): string {
  if (input.executionPolicy !== undefined) return input.executionPolicy.trim();
  try {
    return (input.readExecutionPolicy ?? defaultExecutionPolicy)().trim();
  } catch {
    return "";
  }
}

interface Probe {
  status?: number;
  body?: unknown;
  error?: string;
}

async function probe(
  impl: FetchLike,
  url: string,
  headers: Record<string, string>,
  readBody: boolean,
): Promise<Probe> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_MS);
  timer.unref?.();
  try {
    const resp = await impl(url, {
      method: "GET",
      headers,
      redirect: "manual",
      signal: controller.signal,
    });
    const status = resp.status;
    if (readBody && status >= 200 && status < 300) {
      try {
        return { status, body: await resp.json() };
      } catch {
        return { status };
      }
    }
    controller.abort();
    return { status };
  } catch (err) {
    return { error: failureKind(err, controller.signal) };
  } finally {
    clearTimeout(timer);
  }
}

function isRedirect(status: number | undefined): boolean {
  return status === 0 || (typeof status === "number" && status >= 300 && status < 400);
}

function checkNode(version: string, engines: string): DoctorCheck {
  const name = "node";
  if (!engines) {
    return {
      name,
      status: "fail",
      summary: "package engines could not be read",
      fix: "Reinstall @cognexuslabs/grokbot-artzain.",
    };
  }
  const meets = nodeMeets(version, engines);
  if (meets === null) {
    return {
      name,
      status: "fail",
      summary: `node ${version} could not be compared with engines ${engines}`,
      fix: `Install a Node.js that meets ${engines} and run this command with it.`,
    };
  }
  if (!meets) {
    return {
      name,
      status: "fail",
      summary: `node ${version} is below engines ${engines}`,
      fix: `Install a Node.js that meets ${engines} and run this command with it.`,
    };
  }
  return { name, status: "ok", summary: `node ${version} meets engines ${engines}` };
}

function checkCommand(input: DoctorInput, platform: string): DoctorCheck {
  const name = "command";
  const exists = input.exists ?? existsSync;
  const dirs = pathList(input.path ?? envOf(input).PATH ?? process.env.PATH ?? "", platform);
  const names = platform === "win32"
    ? ["grokbot-artzain", "grokbot-artzain.cmd", "grokbot-artzain.ps1", "grokbot-artzain.exe"]
    : ["grokbot-artzain"];
  const found = new Set<string>();
  for (const dir of dirs) {
    for (const file of names) {
      if (exists(childPath(dir, file, platform))) found.add(file);
    }
  }
  if (found.size === 0) {
    return { name, status: "fail", summary: "grokbot-artzain is not on PATH", fix: PATH_FIX };
  }
  if (platform === "win32" && !found.has("grokbot-artzain.cmd")) {
    return { name, status: "fail", summary: "grokbot-artzain.cmd is not on PATH", fix: CMD_FIX };
  }
  if (platform === "win32") {
    const policy = policyText(input);
    if (!POLICY_OK.has(policy.toLowerCase())) {
      const summary = policy
        ? `PowerShell execution policy is ${policy}`
        : "PowerShell execution policy could not be read";
      return { name, status: "warn", summary, fix: POLICY_FIX };
    }
    return {
      name,
      status: "ok",
      summary: `grokbot-artzain.cmd is on PATH and PowerShell execution policy is ${policy}`,
    };
  }
  return { name, status: "ok", summary: "grokbot-artzain is on PATH" };
}

async function checkCli(input: DoctorInput, version: string, impl: FetchLike | undefined): Promise<DoctorCheck> {
  const name = "cli";
  if (input.offline) {
    return { name, status: "ok", summary: "cli version check skipped (--offline)" };
  }
  if (!impl) {
    return {
      name,
      status: "warn",
      summary: "the npm registry was not asked",
      fix: "Re-run grokbot-artzain doctor when a fetch implementation is available, or pass --offline.",
    };
  }
  const answer = await probe(impl, NPM_LATEST, {}, true);
  const latest = (answer.body as { version?: unknown } | undefined)?.version;
  if (answer.error || answer.status !== 200 || typeof latest !== "string" || !latest.trim()) {
    return {
      name,
      status: "warn",
      summary: "the latest version on npm could not be read",
      fix: "Re-run grokbot-artzain doctor when registry.npmjs.org answers, or pass --offline to skip this check.",
    };
  }
  const cmp = compareDot(version, latest.trim());
  if (cmp === null) {
    return {
      name,
      status: "warn",
      summary: `cli ${version} could not be compared with npm ${latest.trim()}`,
      fix: "Re-run grokbot-artzain doctor, or pass --offline to skip this check.",
    };
  }
  if (cmp < 0) {
    return {
      name,
      status: "warn",
      summary: `cli ${version}, latest on npm is ${latest.trim()}`,
      fix: "Run npm install -g @cognexuslabs/grokbot-artzain to install the latest version.",
    };
  }
  const summary = cmp === 0
    ? `cli ${version} matches the latest on npm`
    : `cli ${version} is newer than ${latest.trim()} on npm`;
  return { name, status: "ok", summary };
}

function checkSkill(text: string | null, packageVersion: string): DoctorCheck {
  const name = "skill";
  if (text === null) {
    return {
      name,
      status: "warn",
      summary: "the installed SKILL.md could not be read",
      fix: "Reinstall @cognexuslabs/grokbot-artzain.",
    };
  }
  const installed = skillTextVersion(text);
  if (!installed) {
    return {
      name,
      status: "warn",
      summary: "the installed skill text has no version",
      fix: "Reinstall @cognexuslabs/grokbot-artzain and save its SKILL.md to the Bot again. " +
        "grokbot-artzain skill prints the file's path.",
    };
  }
  if (installed !== packageVersion) {
    return {
      name,
      status: "warn",
      summary: `installed skill text ${installed}, package ${packageVersion}`,
      fix: `The installed skill text is ${installed} and this package is ${packageVersion}. ` +
        "Reinstall @cognexuslabs/grokbot-artzain and save its SKILL.md to the Bot again, unchanged. " +
        "grokbot-artzain skill prints the file's path.",
    };
  }
  return { name, status: "ok", summary: `skill text ${installed} matches this package` };
}

function checkKey(apiKey: string): DoctorCheck {
  if (!apiKey) {
    return { name: "key", status: "fail", summary: "key is missing", fix: KEY_FIX };
  }
  return { name: "key", status: "ok", summary: `key sha256:${keyFingerprint(apiKey).slice(0, 8)}` };
}

async function checkBase(impl: FetchLike | undefined, base: { url: string } | { problem: string }): Promise<DoctorCheck> {
  const name = "base_url";
  if ("problem" in base) return { name, status: "fail", summary: "base URL could not be used", fix: base.problem };
  if (!impl) {
    return {
      name,
      status: "fail",
      summary: "base URL was not asked",
      fix: "Run this command on Node.js 18 or later, which provides fetch.",
    };
  }
  const answer = await probe(impl, `${base.url}/health`, {}, false);
  if (answer.error) {
    return {
      name,
      status: "fail",
      summary: `base URL could not be reached (${answer.error})`,
      fix: "Set COGNEXUS_API_BASE_URL to the address of your ArtzAIn deployment, or check this computer's network.",
    };
  }
  if (isRedirect(answer.status)) {
    return {
      name,
      status: "fail",
      summary: `base URL answered with HTTP ${answer.status}, a redirect`,
      fix: REDIRECT_FIX,
    };
  }
  return { name, status: "ok", summary: `base URL answers with HTTP ${answer.status}` };
}

async function checkKeyAccepted(
  input: DoctorInput,
  impl: FetchLike | undefined,
  apiKey: string,
  base: { url: string; source: string } | { problem: string },
  agentId: string,
): Promise<{ check: DoctorCheck; accepted: boolean }> {
  const name = "key_accepted";
  if (!apiKey) {
    return { check: { name, status: "fail", summary: "key was not checked", fix: KEY_FIX }, accepted: false };
  }
  if ("problem" in base) {
    return { check: { name, status: "fail", summary: "key was not sent", fix: base.problem }, accepted: false };
  }
  if (!impl) {
    return {
      check: {
        name,
        status: "fail",
        summary: "key was not sent",
        fix: "Run this command on Node.js 18 or later, which provides fetch.",
      },
      accepted: false,
    };
  }
  const result = await enrollInstance(
    {
      apiKey,
      baseUrl: base.url,
      baseUrlSource: base.source,
      enroll: true,
      instance: input.instance,
      announceAgents: input.announceAgents,
      announceSkills: input.announceSkills,
      agentDid: agentId,
    },
    impl,
    () => {},
    agentId,
  );
  if (result.ok) return { check: { name, status: "ok", summary: "key accepted" }, accepted: true };
  if (typeof result.status === "number" && isRedirect(result.status)) {
    return {
      check: {
        name,
        status: "fail",
        summary: `key check refused (HTTP ${result.status})`,
        fix: REDIRECT_FIX,
      },
      accepted: false,
    };
  }
  if (result.status === 401 || result.status === 403) {
    return {
      check: {
        name,
        status: "fail",
        summary: `key refused (HTTP ${result.status})`,
        fix: "The key was refused. Use a Decision API key from the ArtzAIn dashboard. " +
          "A sign-in token and an envelope key do not work here.",
      },
      accepted: false,
    };
  }
  if (result.status === 429) {
    return {
      check: {
        name,
        status: "fail",
        summary: "key check refused (HTTP 429)",
        fix: "Enroll refused with HTTP 429. This check counts against the enroll limit. Wait and run grokbot-artzain doctor again.",
      },
      accepted: false,
    };
  }
  if (typeof result.status === "number") {
    return {
      check: {
        name,
        status: "fail",
        summary: `key check refused (HTTP ${result.status})`,
        fix: `Enroll refused with HTTP ${result.status}. Run grokbot-artzain doctor again once the engine accepts the key.`,
      },
      accepted: false,
    };
  }
  return {
    check: {
      name,
      status: "fail",
      summary: `key check failed (${result.reason ?? "Error"})`,
      fix: "The address could not be reached from this computer. Set COGNEXUS_API_BASE_URL when the engine is elsewhere.",
    },
    accepted: false,
  };
}

function checkAgent(input: DoctorInput, agentId: string): DoctorCheck {
  const name = "agent_id";
  if (!agentFromEnv(input)) {
    return {
      name,
      status: "warn",
      summary: "GROKBOT_AGENT_ID is not set",
      fix: "Set GROKBOT_AGENT_ID to a stable name for this Bot. A Bot may pass --agent-did on each call.",
    };
  }
  if (agentId === "grokbot-agent") {
    return {
      name,
      status: "warn",
      summary: "GROKBOT_AGENT_ID is grokbot-agent",
      fix: "Set GROKBOT_AGENT_ID to a stable name for this Bot other than grokbot-agent.",
    };
  }
  return { name, status: "ok", summary: `agent id ${agentId}` };
}

function checkCache(
  input: DoctorInput,
  entry: EnrollRecord | undefined,
  version: string,
  nowMs: number,
  refreshed: boolean,
  apiKey: string,
): DoctorCheck {
  const name = "enroll_cache";
  if (!enrollOn(input)) {
    return { name, status: "ok", summary: "enroll is off, so decide does not consult the record" };
  }
  if (!apiKey) {
    return {
      name,
      status: "warn",
      summary: "no enroll record can be read until a key is set",
      fix: "Set COGNEXUS_API_KEY, then run grokbot-artzain doctor again.",
    };
  }
  if (refreshed) return { name, status: "ok", summary: "enroll record refreshed by this key check" };
  const ttl = enrollTtlMs(input.enrollTtlHours ?? envOf(input).GROKBOT_ENROLL_TTL_HOURS);
  if (enrollIsFresh(entry, version, nowMs, ttl)) {
    return { name, status: "ok", summary: "enroll record is fresh" };
  }
  const summary = !entry
    ? "no enroll record yet"
    : entry.cli_version !== version
      ? `enroll record is from CLI ${entry.cli_version}`
      : "enroll record is older than the enroll TTL";
  return { name, status: "warn", summary, fix: CACHE_FIX };
}

async function guard(name: string, body: () => Promise<DoctorCheck> | DoctorCheck): Promise<DoctorCheck> {
  try {
    return await body();
  } catch (err) {
    return {
      name,
      status: "fail",
      summary: `${name} check failed (${failureKind(err)})`,
      fix: "Re-run grokbot-artzain doctor.",
    };
  }
}

export function formatDoctorText(checks: readonly DoctorCheck[]): string {
  const lines: string[] = [];
  for (const check of checks) {
    const mark = check.status === "ok" ? "ok " : check.status === "warn" ? "WARN" : "FAIL";
    lines.push(`  [${mark}] ${check.summary}`);
    if (check.status !== "ok" && check.fix) lines.push(`        -> ${check.fix}`);
  }
  return lines.join("\n");
}

export async function runDoctor(input: DoctorInput = {}): Promise<DoctorReport> {
  const ship = packaged();
  const cliVersion = (input.cliVersion ?? ship.version).trim() || "0.0.0";
  const packageVersion = (input.packageVersion ?? ship.version).trim() || cliVersion;
  const engines = input.engines ?? ship.engines;
  const nodeVersion = input.nodeVersion ?? process.version;
  const platform = input.platform ?? process.platform;
  const impl = input.fetchImpl ?? (typeof globalThis.fetch === "function"
    ? (globalThis.fetch as unknown as FetchLike)
    : undefined);
  const apiKey = apiKeyOf(input);
  const base = baseOf(input);
  const agentId = (input.agentId ?? "").trim() || "grokbot-agent";
  const nowMs = input.nowMs ?? Date.now();
  let skillText: string | null;
  if (input.skillText === null) skillText = null;
  else if (input.skillText !== undefined) skillText = input.skillText;
  else {
    try {
      skillText = readFileSync(skillFile(), "utf8");
    } catch {
      skillText = null;
    }
  }

  const checks: DoctorCheck[] = [];
  checks.push(await guard("node", () => checkNode(nodeVersion, engines)));
  checks.push(await guard("command", () => checkCommand(input, platform)));
  checks.push(await guard("cli", () => checkCli(input, cliVersion, impl)));
  checks.push(await guard("skill", () => checkSkill(skillText, packageVersion)));
  checks.push(await guard("key", () => checkKey(apiKey)));
  checks.push(await guard("base_url", () => checkBase(impl, base)));

  let keyWasAccepted = false;
  checks.push(await (async () => {
    try {
      const out = await checkKeyAccepted(input, impl, apiKey, base, agentId);
      keyWasAccepted = out.accepted;
      return out.check;
    } catch (err) {
      return {
        name: "key_accepted",
        status: "fail" as const,
        summary: `key_accepted check failed (${failureKind(err)})`,
        fix: "Re-run grokbot-artzain doctor.",
      };
    }
  })());

  checks.push(await guard("agent_id", () => checkAgent(input, agentId)));

  let entry: EnrollRecord | undefined;
  let refreshed = false;
  const slot = apiKey && "url" in base ? enrollStateKey(base.url, apiKey, agentId) : "";
  if (slot) {
    try {
      const saved = await (input.readState ?? readEnrollState)();
      entry = saved?.entries[slot];
    } catch {
      entry = undefined;
    }
    if (keyWasAccepted && enrollOn(input)) {
      try {
        await (input.recordEnroll ?? writeEnrollRecord)(slot, cliVersion, new Date(nowMs));
        refreshed = true;
      } catch {
        refreshed = false;
      }
    }
  }
  checks.push(await guard("enroll_cache", () => checkCache(input, entry, cliVersion, nowMs, refreshed, apiKey)));

  return { ok: checks.every((item) => item.status !== "fail"), checks };
}
