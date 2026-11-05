/**
 * Where a `decide` records that it enrolled, and where `announce` records
 * that it listed an agent, so the next process can skip a fresh one.
 *
 * The file is `state.json` under `~/.config/grokbot-artzain`, or under
 * `%APPDATA%\grokbot-artzain` on Windows. An enroll entry is keyed by the
 * base URL, a SHA-256 fingerprint of the API key, and the agent id. An
 * announce entry adds the instance. Each stores the time. The key itself
 * is not stored.
 *
 * A missing, corrupt or unreadable file is "enroll and rewrite". It is
 * never an error the gate reports.
 */

import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
/** Windows refuses a rename while another program has the old file open. */
const REPLACE_RETRY_MS = process.platform === "win32" ? 5_000 : 0;
const REPLACE_RETRY_INTERVAL_MS = 2;

let renameOverride: ((from: string, to: string) => Promise<void>) | undefined;
let retryMsOverride: number | undefined;

/** Tests substitute a rename that refuses, and how long a refusal is tried. */
export function setReplaceForTests(
  fn: ((from: string, to: string) => Promise<void>) | undefined,
  retryMs?: number,
): void {
  renameOverride = fn;
  retryMsOverride = retryMs;
}

export interface EnrollRecord {
  last_enroll_at: string;
  cli_version: string;
}

export interface AnnounceRecord {
  last_announce_at: string;
}

export interface EnrollState {
  entries: Record<string, EnrollRecord>;
  announces: Record<string, AnnounceRecord>;
}

/** An announce of the same agent, instance, base URL and key is skipped inside this window. */
export const ANNOUNCE_TTL_MS = 24 * 60 * 60 * 1000;

let directoryForTests: string | undefined;

/** Tests point this at a temporary folder. Unset uses the real location. */
export function setStateDirectoryForTests(dir: string | undefined): void {
  directoryForTests = dir;
}

export function stateDirectory(): string {
  if (directoryForTests) return directoryForTests;
  if (process.platform === "win32") {
    const base = process.env.APPDATA || join(homedir(), "AppData", "Roaming");
    return join(base, "grokbot-artzain");
  }
  return join(homedir(), ".config", "grokbot-artzain");
}

export function stateFilePath(): string {
  return join(stateDirectory(), "state.json");
}

/** SHA-256 hex of the key. The entry name is built from this, and the file never stores the key. */
export function keyFingerprint(apiKey: string): string {
  return createHash("sha256").update(apiKey, "utf8").digest("hex");
}

/**
 * The entry name: base URL, the key's fingerprint, and the agent id.
 * Hashed so the file does not have to quote the URL.
 */
export function enrollStateKey(baseUrl: string, apiKey: string, agentId: string): string {
  return createHash("sha256")
    .update(`${baseUrl}\0${keyFingerprint(apiKey)}\0${agentId}`, "utf8")
    .digest("hex");
}

/**
 * The announce entry name: base URL, the key's fingerprint, the instance
 * and the agent id. Hashed so the file does not store the key.
 */
export function announceStateKey(
  baseUrl: string,
  apiKey: string,
  instance: string,
  agentId: string,
): string {
  return createHash("sha256")
    .update(`${baseUrl}\0${keyFingerprint(apiKey)}\0${instance}\0${agentId}`, "utf8")
    .digest("hex");
}

let versionCache: string | undefined;

export function currentCliVersion(): string {
  if (versionCache !== undefined) return versionCache;
  try {
    const path = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown };
    versionCache = typeof parsed.version === "string" && parsed.version ? parsed.version : "0.0.0";
  } catch {
    versionCache = "0.0.0";
  }
  return versionCache;
}

/** Hours before the same base URL, key and Bot enroll again. Default 24. */
export function enrollTtlMs(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return 24 * 60 * 60 * 1000;
  const hours = Number(raw);
  if (!Number.isFinite(hours) || hours < 0) return 24 * 60 * 60 * 1000;
  return hours * 60 * 60 * 1000;
}

function asRecord(value: unknown): EnrollRecord | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as { last_enroll_at?: unknown; cli_version?: unknown };
  if (typeof row.last_enroll_at !== "string" || typeof row.cli_version !== "string") return undefined;
  return { last_enroll_at: row.last_enroll_at, cli_version: row.cli_version };
}

function asAnnounce(value: unknown): AnnounceRecord | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as { last_announce_at?: unknown };
  if (typeof row.last_announce_at !== "string") return undefined;
  return { last_announce_at: row.last_announce_at };
}

function readMap<T>(
  value: unknown,
  parse: (row: unknown) => T | undefined,
): Record<string, T> {
  const out: Record<string, T> = {};
  if (!value || typeof value !== "object") return out;
  for (const [name, row] of Object.entries(value as Record<string, unknown>)) {
    const parsed = parse(row);
    if (parsed) out[name] = parsed;
  }
  return out;
}

/**
 * The saved state, or `null` when there is nothing usable. A missing file,
 * a read error and JSON that is not the shape above are all `null`.
 */
export async function readEnrollState(): Promise<EnrollState | null> {
  let text: string;
  try {
    text = await readFile(stateFilePath(), "utf8");
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(text) as { entries?: unknown; announces?: unknown };
    if (!parsed || typeof parsed !== "object") return null;
    const hasEntries = Boolean(parsed.entries) && typeof parsed.entries === "object";
    const hasAnnounces = Boolean(parsed.announces) && typeof parsed.announces === "object";
    if (!hasEntries && !hasAnnounces) return null;
    return {
      entries: readMap(parsed.entries, asRecord),
      announces: readMap(parsed.announces, asAnnounce),
    };
  } catch {
    return null;
  }
}

export function enrollIsFresh(
  entry: EnrollRecord | undefined,
  version: string,
  nowMs: number,
  ttlMs: number,
): boolean {
  if (!entry || entry.cli_version !== version) return false;
  const at = Date.parse(entry.last_enroll_at);
  if (!Number.isFinite(at)) return false;
  return nowMs - at < ttlMs;
}

/** True while `nowMs` is strictly inside 24 hours of the recorded announce. */
export function announceIsFresh(
  entry: AnnounceRecord | undefined,
  nowMs: number,
  ttlMs: number = ANNOUNCE_TTL_MS,
): boolean {
  if (!entry) return false;
  const at = Date.parse(entry.last_announce_at);
  if (!Number.isFinite(at)) return false;
  return nowMs - at < ttlMs;
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    // A retry must not keep the process up after the verdict. The CLI cuts
    // telemetry off; this wait ends with it.
    timer.unref?.();
  });
}

function errno(err: unknown): string {
  return err && typeof err === "object" && "code" in err ? String((err as { code?: unknown }).code) : "";
}

/**
 * Move `from` over `to`. On Windows a refusal is tried again for a few
 * seconds. Whatever fails, `from` is removed and `to` is as it was.
 */
export async function replaceFile(from: string, to: string): Promise<void> {
  const deadline = Date.now() + (retryMsOverride ?? REPLACE_RETRY_MS);
  const move = renameOverride ?? rename;
  try {
    for (;;) {
      try {
        await move(from, to);
        return;
      } catch (err) {
        const code = errno(err);
        const refused = code === "EPERM" || code === "EACCES" || code === "EBUSY";
        if (!refused || Date.now() >= deadline) throw err;
        await pause(REPLACE_RETRY_INTERVAL_MS);
      }
    }
  } catch (err) {
    try {
      await unlink(from);
    } catch {
      /* the temp file is already gone */
    }
    throw err;
  }
}

async function writePrivate(path: string, data: string): Promise<void> {
  const handle = await open(path, "w", FILE_MODE);
  try {
    await handle.writeFile(data, "utf8");
    if (process.platform !== "win32") await handle.chmod(FILE_MODE);
  } finally {
    await handle.close();
  }
  if (process.platform !== "win32") {
    try {
      await chmod(path, FILE_MODE);
    } catch {
      /* the descriptor already carries the mode */
    }
  }
}

async function withStateLock<T>(dir: string, body: () => Promise<T>): Promise<T> {
  const lock = join(dir, ".state.lock");
  const deadline = Date.now() + 2_000;
  for (;;) {
    try {
      const handle = await open(lock, "wx", FILE_MODE);
      await handle.close();
      break;
    } catch (err) {
      if (errno(err) !== "EEXIST" || Date.now() >= deadline) throw err;
      try {
        const info = await stat(lock);
        if (Date.now() - info.mtimeMs > 2_000) await unlink(lock);
      } catch {
        /* the holder removed it, or another waiter did */
      }
      await pause(5);
    }
  }
  try {
    return await body();
  } finally {
    try {
      await unlink(lock);
    } catch {
      /* already released */
    }
  }
}

async function ensureStateDir(): Promise<string> {
  const dir = stateDirectory();
  await mkdir(dir, { recursive: true, mode: DIR_MODE });
  if (process.platform !== "win32") {
    try {
      await chmod(dir, DIR_MODE);
    } catch {
      /* a directory that already has the mode */
    }
  }
  return dir;
}

/**
 * Merge one edit into the file. A lock keeps two writers from each saving
 * a copy that lacks the other. Throws when the file cannot be written.
 */
async function updateState(edit: (state: EnrollState) => void): Promise<void> {
  const dir = await ensureStateDir();
  await withStateLock(dir, async () => {
    const current = await readEnrollState();
    const state: EnrollState = {
      entries: { ...(current?.entries ?? {}) },
      announces: { ...(current?.announces ?? {}) },
    };
    edit(state);
    const temp = join(dir, `.state.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    await writePrivate(
      temp,
      `${JSON.stringify({ entries: state.entries, announces: state.announces }, null, 2)}\n`,
    );
    await replaceFile(temp, stateFilePath());
  });
}

/**
 * Record one enroll, merged with the entries already in the file.
 * Throws when the file cannot be written; the gate swallows that.
 */
export async function recordEnroll(key: string, version: string, at: Date): Promise<void> {
  const stamp = at.toISOString();
  await updateState((state) => {
    state.entries[key] = { last_enroll_at: stamp, cli_version: version };
  });
}

/** Record the agents a call stored. An enroll record already in the file stays. */
export async function recordAnnounces(keys: string[], at: Date): Promise<void> {
  const stamp = at.toISOString();
  await updateState((state) => {
    for (const key of keys) state.announces[key] = { last_announce_at: stamp };
  });
}
