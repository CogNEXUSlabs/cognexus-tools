/**
 * Pull-enroll (FR-12 estate automation, wave 4).
 *
 * On the first gated call the skill POSTs identity (announce shape, names
 * only) to `POST /api/v1/registry/enroll` with `source: "grokbot"` and the
 * same Decision API key the gate already holds. The default reply names
 * the adapter to install and never returns a `cnxe_`. A one-time
 * `enrollToken` from Govern / the snippet pack is the only path that
 * returns the envelope key (`grokbot-artzain enroll --enroll-token …`).
 *
 * Enroll is on unless `enroll: false`. It is telemetry, not a gate: it
 * never blocks the Decision call, and failures are logged and swallowed.
 * Transient failures (network, 5xx, 429) retry on a later gated call; a
 * refusal (4xx) is a config problem and is not retried until the process
 * restarts.
 */

import { resolveApiKey, resolveBaseUrl, type FetchLike } from "./client.js";

export const ENROLL_TIMEOUT_MS = 10_000;
const MAX_AGENTS = 50;
const MAX_SKILLS = 100;
const MAX_NAME_LEN = 200;
const MAX_INSTANCE_LEN = 120;

export interface EnrollConfig {
  apiKey?: string;
  baseUrl?: string;
  /** Opt-out: enroll fires unless this is exactly false. */
  enroll?: boolean;
  /** One-shot operator token from Govern / the snippet pack. */
  enrollToken?: string;
  instance?: string;
  announceAgents?: string[];
  announceSkills?: string[];
  agentDid?: string;
}

export interface EnrollResult {
  ok: boolean;
  status?: number;
  reason?: string;
  retryable?: boolean;
  adapter?: Record<string, unknown>;
  decision?: Record<string, unknown>;
  envelope?: Record<string, unknown> | null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function boundName(value: string, maxLen: number): string {
  return Array.from(value.trim()).slice(0, maxLen).join("");
}

function cleanNames(values: unknown, cap: number): string[] {
  if (!Array.isArray(values)) return [];
  const out: string[] = [];
  for (const v of values) {
    if (typeof v !== "string") continue;
    const name = boundName(v, MAX_NAME_LEN);
    if (!name || out.includes(name)) continue;
    out.push(name);
    if (out.length >= cap) break;
  }
  return out;
}

/** Fire one enroll. Never throws — the caller is a Decision gate. */
export async function enrollInstance(
  cfg: EnrollConfig,
  fetchImpl?: FetchLike,
  log: (msg: string) => void = () => {},
  fallbackAgentId?: string,
): Promise<EnrollResult> {
  if (cfg.enroll === false) {
    return { ok: false, reason: "enroll disabled" };
  }
  const apiKey = resolveApiKey(asString(cfg.apiKey) || undefined);
  if (!apiKey) {
    log("artzain enroll skipped: no API key configured");
    return { ok: false, reason: "no api key" };
  }
  const instance = boundName(asString(cfg.instance), MAX_INSTANCE_LEN);
  const agents = cleanNames(cfg.announceAgents, MAX_AGENTS);
  if (agents.length === 0) {
    const fallback = boundName(
      asString(fallbackAgentId).trim() ||
        asString(cfg.agentDid).trim() ||
        "grokbot-agent",
      MAX_NAME_LEN,
    );
    agents.push(fallback);
  }
  const skills = cleanNames(cfg.announceSkills, MAX_SKILLS);
  const enrollToken = asString(cfg.enrollToken).trim();

  const impl: FetchLike | undefined =
    fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (!impl) {
    log("artzain enroll skipped: no fetch implementation (Node >= 18 required)");
    return { ok: false, reason: "no fetch" };
  }

  const body: Record<string, unknown> = {
    source: "grokbot",
    agents,
    skills,
  };
  if (instance) body.instance = instance;
  if (enrollToken) body.enroll_token = enrollToken;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ENROLL_TIMEOUT_MS);
  try {
    const resp = await impl(
      `${resolveBaseUrl(cfg.baseUrl)}/api/v1/registry/enroll`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": apiKey,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      },
    );
    if (!resp.ok) {
      const retryable = resp.status >= 500 || resp.status === 429;
      log(`artzain enroll refused: HTTP ${resp.status}` +
        (retryable ? " (will retry on a later gated call)" : ""));
      return { ok: false, status: resp.status, reason: `http ${resp.status}`, retryable };
    }
    let adapterPrimary = "unknown";
    let extra = "";
    let adapter: Record<string, unknown> | undefined;
    let decision: Record<string, unknown> | undefined;
    let envelope: Record<string, unknown> | null | undefined;
    try {
      const data = (await resp.json()) as Record<string, unknown>;
      if (data.adapter && typeof data.adapter === "object") {
        adapter = data.adapter as Record<string, unknown>;
        if (typeof adapter.primary === "string") adapterPrimary = adapter.primary;
      }
      if (data.decision && typeof data.decision === "object") {
        decision = data.decision as Record<string, unknown>;
      }
      if (data.envelope === null) {
        envelope = null;
      } else if (data.envelope && typeof data.envelope === "object") {
        envelope = data.envelope as Record<string, unknown>;
        if (typeof envelope.envelope_key === "string" && envelope.envelope_key) {
          extra = "; envelope material received (key not logged)";
        }
      }
    } catch {
      extra = "; response unreadable";
    }
    log(`artzain enroll ok: adapter ${adapterPrimary}${extra}`);
    return { ok: true, status: resp.status, adapter, decision, envelope };
  } catch (err) {
    log(`artzain enroll failed: ${(err as Error).message} ` +
      "(will retry on a later gated call)");
    return { ok: false, reason: (err as Error).message, retryable: true };
  } finally {
    clearTimeout(timer);
  }
}
