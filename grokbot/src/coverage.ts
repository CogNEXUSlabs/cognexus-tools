/**
 * `grokbot-artzain coverage --since <ISO time>` lists actions that have no
 * decision id.
 *
 * It reads three JSONL files. The shim log is what a command shim appends
 * when it runs a command. The gateway log is the MCP gateway's action log.
 * The action journal is the file SKILL.md asks the Bot to append to. A
 * missing file is an empty source. A line is one action. `decision_id` is
 * what matches it to a decision. The key is never written or sent.
 *
 * The counts posted to the engine are per agent, after lines that share a
 * decision id have been counted once.
 */

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { failureKind, resolveBaseUrlSetting, type FetchLike } from "./client.js";
import { stateDirectory } from "./state.js";

const SINCE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export type ActionSource = "shim" | "gateway" | "journal";

export interface ActionRecord {
  at: string;
  source: ActionSource;
  agent: string;
  action: string;
  target: string;
  decisionId: string;
}

export interface CoverageReport {
  since: string;
  agents: { agent_id: string; action_count: number }[];
}

export function parseSince(text: string): Date | undefined {
  const value = text.trim();
  if (!SINCE.test(value)) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

export function defaultShimLog(): string {
  return join(stateDirectory(), "shim.jsonl");
}

export function defaultJournal(env: NodeJS.ProcessEnv = process.env): string {
  const named = env.GROKBOT_ACTION_JOURNAL?.trim();
  if (named) return named;
  return join(stateDirectory(), "actions.jsonl");
}

export function defaultGatewayLog(env: NodeJS.ProcessEnv = process.env): string {
  const named = env.ARTZAIN_GATEWAY_LOG?.trim();
  if (named) return named;
  if (process.platform === "win32") {
    const base = env.APPDATA || join(homedir(), "AppData", "Roaming");
    return join(base, "artzain-mcp-gateway", "gateway.jsonl");
  }
  const home = env.HOME || homedir();
  return join(home, ".config", "artzain-mcp-gateway", "gateway.jsonl");
}

/** One JSON line. The caller chooses the file. A failure is the caller's to report. */
export async function appendActionLine(
  file: string,
  row: { at: string; agent: string; action: string; target: string; decision_id: string },
): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify(row)}\n`, "utf8");
}

function textField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Actions in `text` at or after `since`. A line that is not one action is
 * counted in `skipped` and left out.
 */
export function readActionLog(
  text: string,
  source: ActionSource,
  since: Date,
): { actions: ActionRecord[]; skipped: number } {
  const actions: ActionRecord[] = [];
  let skipped = 0;
  const start = since.getTime();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      skipped += 1;
      continue;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      skipped += 1;
      continue;
    }
    const row = parsed as Record<string, unknown>;
    const at = textField(row.at);
    const when = parseSince(at);
    const action = textField(row.action);
    if (!when || when.getTime() < start || !action) {
      if (!when || !action) skipped += 1;
      continue;
    }
    actions.push({
      at,
      source,
      agent: textField(row.agent),
      action,
      target: textField(row.target),
      decisionId: textField(row.decision_id),
    });
  }
  return { actions, skipped };
}

export function unmatchedActions(actions: ActionRecord[]): ActionRecord[] {
  return actions
    .filter((row) => row.decisionId === "")
    .sort((a, b) => a.at.localeCompare(b.at) || a.source.localeCompare(b.source) || a.action.localeCompare(b.action));
}

/** Per-agent counts. Lines that share a decision id count once. A blank agent is left out. */
export function actionCounts(actions: ActionRecord[]): { agent_id: string; action_count: number }[] {
  const seen = new Set<string>();
  const counts = new Map<string, number>();
  for (const row of actions) {
    if (row.decisionId) {
      const key = `id:${row.decisionId}`;
      if (seen.has(key)) continue;
      seen.add(key);
    }
    const agent = row.agent.trim();
    if (!agent) continue;
    counts.set(agent, (counts.get(agent) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([agent_id, action_count]) => ({ agent_id, action_count }));
}

export function buildReport(since: string, actions: ActionRecord[]): CoverageReport {
  return { since, agents: actionCounts(actions) };
}

export function unmatchedLine(row: ActionRecord): string {
  return JSON.stringify({
    at: row.at,
    source: row.source,
    agent: row.agent,
    action: row.action,
    target: row.target,
  });
}

type ReadResult = { text: string } | { missing: true } | { error: true };

async function readLog(file: string): Promise<ReadResult> {
  try {
    return { text: await readFile(file, "utf8") };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { missing: true };
    return { error: true };
  }
}

export async function postCoverageReport(options: {
  apiKey: string;
  baseUrl: string;
  baseSource: string;
  report: CoverageReport;
  fetchImpl?: FetchLike;
}): Promise<{ ok: true; evaluated: boolean } | { ok: false; message: string }> {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const base = resolveBaseUrlSetting(options.baseUrl, options.baseSource);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const resp = await fetchImpl(`${base.url}/api/v1/registry/coverage`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Api-Key": options.apiKey },
      body: JSON.stringify(options.report),
      signal: controller.signal,
      redirect: "manual",
    });
    if (resp.status >= 300 && resp.status < 400) {
      return { ok: false, message: "artzain coverage: the report was redirected and was not followed" };
    }
    if (!resp.ok) {
      return { ok: false, message: `artzain coverage: the report was not accepted (HTTP ${resp.status})` };
    }
    let evaluated = false;
    try {
      const body = (await resp.json()) as { evaluated?: unknown };
      evaluated = body.evaluated === true;
    } catch {
      evaluated = false;
    }
    return { ok: true, evaluated };
  } catch (err) {
    return {
      ok: false,
      message: `artzain coverage: the report was not sent (${failureKind(err)})`,
    };
  } finally {
    clearTimeout(timer);
  }
}

const SOURCES: { source: ActionSource; label: string }[] = [
  { source: "shim", label: "shim log" },
  { source: "gateway", label: "gateway log" },
  { source: "journal", label: "action journal" },
];

/**
 * Print each action with no decision id, then post the per-agent counts.
 * Exit 1 when any action has no decision. Exit 2 when the window cannot be
 * read, a log that exists cannot be read, or the counts were not accepted
 * and every action had a decision. A missing log is an empty source.
 */
export async function runCoverage(options: {
  since: string;
  logs: Record<ActionSource, string>;
  report: (body: CoverageReport) => Promise<{ ok: true; evaluated: boolean } | { ok: false; message: string }>;
  log: (line: string) => void;
  print: (line: string) => void;
}): Promise<number> {
  const since = parseSince(options.since);
  if (!since) {
    options.log("artzain coverage: --since needs an ISO-8601 time with a timezone");
    return 2;
  }
  const actions: ActionRecord[] = [];
  let skipped = 0;
  for (const item of SOURCES) {
    const read = await readLog(options.logs[item.source]);
    if ("error" in read) {
      options.log(`artzain coverage: the ${item.label} could not be read`);
      return 2;
    }
    if ("missing" in read) continue;
    const parsed = readActionLog(read.text, item.source, since);
    actions.push(...parsed.actions);
    skipped += parsed.skipped;
  }
  if (skipped > 0) {
    options.log(`artzain coverage: skipped ${skipped} lines that are not an action with a time`);
  }
  const unmatched = unmatchedActions(actions);
  for (const row of unmatched) options.print(unmatchedLine(row));
  const posted = await options.report(buildReport(options.since.trim(), actions));
  if (!posted.ok) {
    options.log(posted.message);
    return unmatched.length > 0 ? 1 : 2;
  }
  if (unmatched.length > 0) {
    const noun = unmatched.length === 1 ? "action" : "actions";
    options.log(`artzain coverage: ${unmatched.length} ${noun} with no decision`);
    return 1;
  }
  options.log("artzain coverage: every action had a decision");
  return 0;
}
