/**
 * `grokbot-artzain upgrade` prints the command that installs the latest
 * version of this package, and runs it only when asked. The install method
 * comes from the real path of the binary: npm's global prefix, a user
 * prefix such as ~/.local, or an npx cache.
 *
 * The command does not read or change the process environment, and it does
 * not read the API key. A child process is given a copy of the environment
 * with the key variables removed.
 */

import { spawn, spawnSync } from "node:child_process";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { FetchLike } from "./client.js";
import { stateDirectory } from "./state.js";

const PACKAGE = "@cognexuslabs/grokbot-artzain";
const NPM_LATEST = `https://registry.npmjs.org/${PACKAGE}/latest`;
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const SHELL_ARG_RE = /^[\w@/\\.:+=-]+$/;
const SECRET_ENV = ["COGNEXUS_API_KEY", "MYAPP_API_KEY", "GROKBOT_ENROLL_TOKEN"];
const REOPEN = "Open a new shell so it finds the updated command.";
const PROBE_MS = 10_000;

export type InstallMethod = "global" | "prefix" | "npx" | "unknown";

export interface SpawnCall {
  command: string;
  args: string[];
  shell: boolean;
  env: NodeJS.ProcessEnv;
}

export interface UpgradeInput {
  binPath?: string;
  platform?: NodeJS.Platform;
  globalPrefix?: string;
  home?: string;
  latest?: string;
  packageVersion?: string;
  packagedSkill?: string;
  skillsDir?: string;
  yes?: boolean;
  force?: boolean;
  skillPath?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: FetchLike;
  spawn?: (call: SpawnCall) => Promise<{ status: number | null }>;
  readFile?: (path: string) => string;
  writeFile?: (path: string, text: string) => void;
  resolvePath?: (path: string) => string;
  /** Receives each line as it is decided, before a skill file is written. */
  note?: (line: string) => void;
}

export interface UpgradeResult {
  code: number;
  stdout: string;
  stderr: string;
  method: InstallMethod;
}

interface Plan {
  method: InstallMethod;
  command: string;
  args: string[];
  /** The user prefix, when `method` is `prefix`. */
  prefix?: string;
}

export function expectedSkillsDir(): string {
  return join(stateDirectory(), "skills");
}

export async function runUpgrade(input: UpgradeInput = {}): Promise<UpgradeResult> {
  const platform = input.platform ?? process.platform;
  const env = input.env ?? process.env;
  const lines: string[] = [];
  const say = (line: string) => {
    lines.push(line);
    input.note?.(line);
  };
  const finish = (code: number, stderr = "", method: InstallMethod = "unknown"): UpgradeResult => ({
    code,
    stdout: lines.join("\n"),
    stderr,
    method,
  });

  if (input.skillPath) {
    const allowed = skillTarget(input, platform);
    if (!allowed.ok) {
      return finish(2, "That path is outside the directory this install expects. Pass --force to copy there anyway.");
    }
  }

  const latest = await latestVersion(input);
  if (!latest.ok) {
    return finish(1, "The latest version on npm could not be read, so no install command was run.");
  }

  const current = input.packageVersion ?? readPackageVersion();
  const plan = classify(
    input.binPath ?? defaultBinPath(),
    input.globalPrefix ?? defaultGlobalPrefix(platform, env),
    input.home ?? homedir(),
    platform,
  );
  const cmp = current ? compareVersions(current, latest.version) : null;

  if (plan.method === "unknown") {
    return finish(1, "This copy's path does not show how it was installed, so no install command was run.", "unknown");
  }
  if (cmp === null) {
    return finish(1, "The version on npm could not be compared with this copy, so no install command was run.", plan.method);
  }

  const shell = platform === "win32";
  const spec = `${PACKAGE}@${latest.version}`;
  const command = toolName(plan.method, platform);
  const args = plan.method === "npx"
    ? ["--yes", spec]
    : plan.method === "prefix"
      ? ["install", "-g", "--prefix", plan.prefix ?? "", spec]
      : ["install", "-g", spec];

  if (cmp > 0) {
    say(`This copy is ${current}, newer than ${latest.version} on npm.`);
  } else if (cmp === 0) {
    say(`Already ${current}, the latest on npm.`);
  } else {
    say([command, ...args].join(" "));
    if (shell && plan.method !== "npx") say(REOPEN);
    if (input.yes) {
      if (shell && args.some((arg) => !SHELL_ARG_RE.test(arg))) {
        return finish(1, "An argument is not safe to pass to the shell, so the command was not run.", plan.method);
      }
      const childEnv = withoutSecrets(env);
      const status = await (input.spawn ?? defaultSpawn)({ command, args, shell, env: childEnv });
      if (status.status !== 0) {
        return finish(status.status && status.status > 0 ? status.status : 1, "The install command failed.", plan.method);
      }
    }
  }

  if (input.skillPath) {
    const target = skillTarget(input, platform);
    if (!target.ok) {
      return finish(2, "That path is outside the directory this install expects. Pass --force to copy there anyway.", plan.method);
    }
    const packaged = input.packagedSkill ?? readPackagedSkill();
    if (packaged === undefined) {
      return finish(1, "The packaged SKILL.md could not be read.", plan.method);
    }
    const read = input.readFile ?? ((path: string) => readFileSync(path, "utf8"));
    let currentText = "";
    try {
      currentText = read(target.path);
    } catch (err) {
      const code = (err as { code?: unknown }).code;
      if (code !== "ENOENT") return finish(1, "The skill file could not be read.", plan.method);
    }
    const summary = skillSummary(currentText, packaged);
    say(summary);
    if (input.yes && summary !== "SKILL.md: already matches the packaged file") {
      try {
        (input.writeFile ?? ((path: string, text: string) => writeFileSync(path, text, "utf8")))(target.path, packaged);
      } catch {
        return finish(1, "The skill file could not be written.", plan.method);
      }
    }
  }

  return finish(0, "", plan.method);
}

function toolName(method: InstallMethod, platform: NodeJS.Platform): string {
  const windows = platform === "win32";
  if (method === "npx") return windows ? "npx.cmd" : "npx";
  return windows ? "npm.cmd" : "npm";
}

function classify(binPath: string, globalPrefix: string, home: string, platform: NodeJS.Platform): Plan {
  const parts = segments(binPath, platform);
  if (parts.includes("_npx")) return { method: "npx", command: "", args: [] };
  if (globalPrefix && isUnder(binPath, globalPrefix, platform)) {
    return { method: "global", command: "", args: [] };
  }
  const prefix = prefixFrom(binPath, platform);
  if (prefix) return { method: "prefix", command: "", args: [], prefix };
  const local = `${home.replace(/[\\/]+$/, "")}${platform === "win32" ? "\\.local" : "/.local"}`;
  if (isUnder(binPath, local, platform)) return { method: "prefix", command: "", args: [], prefix: local };
  return { method: "unknown", command: "", args: [] };
}

function prefixFrom(binPath: string, platform: NodeJS.Platform): string | undefined {
  const raw = binPath.replace(/[\\/]+/g, "/").replace(/\/$/, "").split("/").filter(Boolean);
  const parts = platform === "win32" ? raw.map((part) => part.toLowerCase()) : raw;
  for (let i = 0; i < parts.length - 2; i++) {
    if (parts[i] !== "node_modules") continue;
    if (parts[i + 1] !== "@cognexuslabs" || parts[i + 2] !== "grokbot-artzain") continue;
    const cut = parts[i - 1] === "lib" ? i - 1 : i;
    if (cut <= 0) return undefined;
    return joinSegments(raw.slice(0, cut), platform);
  }
  return undefined;
}

function segments(value: string, platform: NodeJS.Platform): string[] {
  const parts = value.replace(/[\\/]+/g, "/").replace(/\/$/, "").split("/").filter(Boolean);
  return platform === "win32" ? parts.map((part) => part.toLowerCase()) : parts;
}

function joinSegments(parts: string[], platform: NodeJS.Platform): string {
  if (platform === "win32") return parts.join("\\");
  return `/${parts.join("/")}`;
}

function isUnder(child: string, parent: string, platform: NodeJS.Platform): boolean {
  const c = segments(child, platform);
  const p = segments(parent, platform);
  if (p.length === 0 || c.length <= p.length) return false;
  return p.every((part, i) => part === c[i]);
}

function skillTarget(
  input: UpgradeInput,
  platform: NodeJS.Platform,
): { ok: true; path: string } | { ok: false } {
  const raw = input.skillPath ?? "";
  let resolved: string;
  try {
    resolved = (input.resolvePath ?? ((path: string) => path))(raw);
  } catch {
    return { ok: false };
  }
  if (!resolved) return { ok: false };
  if (input.force) return { ok: true, path: resolved };
  const root = input.skillsDir ?? expectedSkillsDir();
  return isUnder(resolved, root, platform) ? { ok: true, path: resolved } : { ok: false };
}

function skillSummary(before: string, after: string): string {
  const { added, removed } = lineDiff(before, after);
  if (added === 0 && removed === 0) return "SKILL.md: already matches the packaged file";
  return `SKILL.md: ${count(added, "line")} added, ${count(removed, "line")} removed`;
}

function count(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function lineDiff(before: string, after: string): { added: number; removed: number } {
  const tally = (text: string) => {
    const map = new Map<string, number>();
    for (const line of textLines(text)) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const from = tally(before);
  const to = tally(after);
  let added = 0;
  let removed = 0;
  for (const key of new Set([...from.keys(), ...to.keys()])) {
    const delta = (to.get(key) ?? 0) - (from.get(key) ?? 0);
    if (delta > 0) added += delta;
    else removed += -delta;
  }
  return { added, removed };
}

function textLines(text: string): string[] {
  const parts = text.split(/\r?\n/);
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

async function latestVersion(input: UpgradeInput): Promise<{ ok: true; version: string } | { ok: false }> {
  if (input.latest !== undefined) {
    return VERSION_RE.test(input.latest) ? { ok: true, version: input.latest } : { ok: false };
  }
  const impl = input.fetchImpl ?? (typeof globalThis.fetch === "function" ? (globalThis.fetch as unknown as FetchLike) : undefined);
  if (!impl) return { ok: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_MS);
  timer.unref?.();
  try {
    const resp = await impl(NPM_LATEST, {
      method: "GET",
      headers: {},
      redirect: "manual",
      signal: controller.signal,
    });
    if (resp.status < 200 || resp.status >= 300) {
      controller.abort();
      return { ok: false };
    }
    const body = await resp.json() as { version?: unknown };
    const version = typeof body.version === "string" ? body.version.trim() : "";
    return VERSION_RE.test(version) ? { ok: true, version } : { ok: false };
  } catch {
    return { ok: false };
  } finally {
    clearTimeout(timer);
  }
}

function compareVersions(left: string, right: string): number | null {
  const a = numeric(left);
  const b = numeric(right);
  if (!a || !b) return null;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return (a[i] ?? 0) < (b[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

function numeric(version: string): [number, number, number] | undefined {
  const match = VERSION_RE.exec(version);
  if (!match) return undefined;
  const parts = version.split(".").map((part) => Number(part));
  if (parts.length !== 3 || parts.some((part) => !Number.isSafeInteger(part))) return undefined;
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function withoutSecrets(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const copy: NodeJS.ProcessEnv = { ...env };
  for (const name of SECRET_ENV) delete copy[name];
  return copy;
}

function defaultBinPath(): string {
  const bin = process.argv[1];
  if (!bin) return fileURLToPath(import.meta.url);
  try {
    return realpathSync(bin);
  } catch {
    return bin;
  }
}

function defaultGlobalPrefix(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  const command = platform === "win32" ? "npm.cmd" : "npm";
  try {
    const out = spawnSync(command, ["prefix", "-g"], {
      encoding: "utf8",
      shell: platform === "win32",
      env: withoutSecrets(env),
      windowsHide: true,
    });
    if (out.status !== 0) return "";
    return (out.stdout || "").trim();
  } catch {
    return "";
  }
}

function readPackageVersion(): string | undefined {
  try {
    const text = readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8");
    const version = (JSON.parse(text) as { version?: unknown }).version;
    return typeof version === "string" ? version : undefined;
  } catch {
    return undefined;
  }
}

function readPackagedSkill(): string | undefined {
  try {
    return readFileSync(fileURLToPath(new URL("../SKILL.md", import.meta.url)), "utf8");
  } catch {
    return undefined;
  }
}

function defaultSpawn(call: SpawnCall): Promise<{ status: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(call.command, call.args, {
      shell: call.shell,
      env: call.env,
      stdio: "inherit",
      windowsHide: true,
    });
    child.on("error", () => resolve({ status: 1 }));
    child.on("close", (status) => resolve({ status }));
  });
}
