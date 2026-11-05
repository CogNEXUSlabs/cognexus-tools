/**
 * A decide the engine could not be asked.
 *
 * The files live in `queue/` under `~/.config/grokbot-artzain`, or under
 * `%APPDATA%\grokbot-artzain` on Windows. Each file is mode 0600 and holds
 * the request the engine decides on, payload included. The API key stays
 * out of the file. A replay sends that request with its original
 * request id. The outcome is recorded, and the action stays for a later
 * decide that exits 0.
 *
 * An entry older than 48 hours is dropped. That is the Decision API's
 * idempotency window: past it, the same request id is a new decision.
 */

import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";

import { DecisionError, postDecision, type FetchLike } from "./client.js";
import { replaceFile, stateDirectory } from "./state.js";

/** Past this age a stored request is no longer the same decision. */
export const QUEUE_TTL_MS = 48 * 60 * 60 * 1000;

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface QueuedRequest {
  queued_at: string;
  base_url: string;
  agent_did: string;
  action: string;
  target: string;
  /** The tool-call payload, the text the engine decides on. */
  payload: string;
  request_id: string;
  product: string;
  /** `model_id`, when the decide named one. */
  model_id?: string;
  /** `workload_id`, when the decide named one. */
  workload_id?: string;
  /** Advisory context, unknown keys included. Absent when the decide sent none. */
  context?: Record<string, unknown>;
}

interface StoredRequest extends QueuedRequest {
  path: string;
}

export interface ReplayRecord {
  request_id: string;
  /** The outcome the engine returned. Recording it does not run the action. */
  recorded: string;
  decision_id?: string;
  acted: false;
}

export interface RetryReport {
  /** A replay never lets the action run. */
  acted: false;
  records: ReplayRecord[];
  notes: string[];
  /** Stored requests still on disk after this pass. */
  pending: number;
}

const FIELDS = [
  "queued_at",
  "base_url",
  "agent_did",
  "action",
  "target",
  "payload",
  "request_id",
  "product",
] as const;

export function queueDirectory(): string {
  return join(stateDirectory(), "queue");
}

/** The engine answered nothing: a transport failure, including a timeout. */
export function decisionWasUnreachable(blockReason: string): boolean {
  return blockReason.includes("Decision API unreachable:");
}

export function expiredNote(requestId: string): string {
  return `dropped ${requestId}: older than 48 hours`;
}

function errno(err: unknown): string {
  return err && typeof err === "object" && "code" in err ? String((err as { code?: unknown }).code) : "";
}

/** A stored id, or `null` when the field is present and not a string. */
function optionalText(row: Record<string, unknown>, name: string): string | undefined | null {
  if (!Object.hasOwn(row, name) || row[name] === undefined || row[name] === "") return undefined;
  return typeof row[name] === "string" ? row[name] : null;
}

/** Stored context, or `null` when the field is present and not an object. */
function optionalContext(row: Record<string, unknown>): Record<string, unknown> | undefined | null {
  if (!Object.hasOwn(row, "context") || row.context === undefined) return undefined;
  const value = row.context;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return { ...(value as Record<string, unknown>) };
}

function asQueued(value: unknown): QueuedRequest | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as Record<string, unknown>;
  const entry = {} as QueuedRequest;
  for (const name of FIELDS) {
    const field = row[name];
    if (typeof field !== "string" || field === "") return undefined;
    entry[name] = field;
  }
  const model = optionalText(row, "model_id");
  const workload = optionalText(row, "workload_id");
  const context = optionalContext(row);
  if (model === null || workload === null || context === null) return undefined;
  if (model) entry.model_id = model;
  if (workload) entry.workload_id = workload;
  if (context && Object.keys(context).length > 0) entry.context = context;
  return entry;
}

async function ensureQueueDir(): Promise<string> {
  const dir = queueDirectory();
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

/** Store one request. Returns the entry that was written. */
export async function enqueueDecision(
  request: Omit<QueuedRequest, "queued_at">,
  at: Date = new Date(),
): Promise<QueuedRequest> {
  const entry: QueuedRequest = { ...request, queued_at: at.toISOString() };
  if (!asQueued(entry)) throw new Error("incomplete");
  const dir = await ensureQueueDir();
  const name = `${randomBytes(16).toString("hex")}.json`;
  const dest = join(dir, name);
  const temp = join(dir, `.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  await writePrivate(temp, `${JSON.stringify(entry, null, 2)}\n`);
  await replaceFile(temp, dest);
  return entry;
}

async function load(now: number): Promise<{ live: StoredRequest[]; notes: string[] }> {
  let names: string[];
  try {
    names = await readdir(queueDirectory());
  } catch (err) {
    if (errno(err) === "ENOENT") return { live: [], notes: [] };
    throw err;
  }
  const live: StoredRequest[] = [];
  const notes: string[] = [];
  for (const name of names) {
    if (!name.endsWith(".json") || name.startsWith(".")) continue;
    const path = join(queueDirectory(), name);
    let entry: QueuedRequest | undefined;
    try {
      entry = asQueued(JSON.parse(await readFile(path, "utf8")) as unknown);
    } catch {
      entry = undefined;
    }
    if (!entry) {
      notes.push(`dropped ${name}: the queued request could not be read`);
      await unlink(path).catch(() => undefined);
      continue;
    }
    const stamped = Date.parse(entry.queued_at);
    if (!Number.isFinite(stamped) || now - stamped > QUEUE_TTL_MS) {
      notes.push(
        Number.isFinite(stamped)
          ? expiredNote(entry.request_id)
          : `dropped ${entry.request_id}: the queued request could not be read`,
      );
      await unlink(path).catch(() => undefined);
      continue;
    }
    live.push({ ...entry, path });
  }
  live.sort((a, b) => a.queued_at.localeCompare(b.queued_at) || a.request_id.localeCompare(b.request_id));
  return { live, notes };
}

/** Drop expired entries, then return what is still waiting. */
export async function listQueue(now = Date.now()): Promise<{ entries: QueuedRequest[]; notes: string[] }> {
  const { live, notes } = await load(now);
  return {
    entries: live.map(({ path: _path, ...entry }) => entry),
    notes,
  };
}

function oneLine(text: string, apiKey: string): string {
  const cleaned = apiKey ? text.split(apiKey).join("the API key") : text;
  return cleaned.replace(/\s+/g, " ").trim();
}

/**
 * Replay each live entry with the request id it was stored with.
 * `acted` is false: the outcome is recorded, and the action waits for a
 * decide that exits 0.
 */
export async function retryQueue(options: {
  apiKey: string;
  fetchImpl?: FetchLike;
  /** Replaces the stored base URL when the flag was passed. */
  baseUrl?: string;
  now?: number;
}): Promise<RetryReport> {
  const { live, notes } = await load(options.now ?? Date.now());
  const records: ReplayRecord[] = [];
  let pending = 0;
  for (const entry of live) {
    try {
      const decision = await postDecision({
        apiKey: options.apiKey,
        baseUrl: options.baseUrl || entry.base_url,
        baseSource: "the queued request",
        action: entry.action,
        target: entry.target,
        payload: entry.payload,
        agentDid: entry.agent_did,
        requestId: entry.request_id,
        product: entry.product,
        modelId: entry.model_id,
        workloadId: entry.workload_id,
        context: entry.context,
        fetchImpl: options.fetchImpl,
      });
      await unlink(entry.path).catch(() => undefined);
      records.push({
        request_id: entry.request_id,
        recorded: decision.outcome,
        decision_id: decision.decision_id,
        acted: false,
      });
    } catch (err) {
      pending += 1;
      const detail = err instanceof DecisionError ? err.message : err instanceof Error ? err.message : String(err);
      notes.push(`still queued ${entry.request_id}: ${oneLine(detail, options.apiKey)}`);
    }
  }
  return { acted: false, records, notes, pending };
}
