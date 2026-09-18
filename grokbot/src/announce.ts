/**
 * Opt-in instance announce (FR-12 v6 slice 3).
 *
 * With `announce: true`, the skill POSTs the instance's identity — agent
 * ids and skill slugs, NAMES ONLY, never content or `gateway.json` — to
 * `POST /api/v1/registry/announce` with `source: "grokbot"` and the same
 * Decision API key the gate already holds. This is how laptop/home-lab
 * hosts no scanner can reach enter the estate: rows land as source
 * `grokbot` behind the standard sealed registration gate, in the
 * `grokbot-announce:` namespace (cannot forge a gateway-probed
 * `{url}#agent:{id}`).
 *
 * Announce is telemetry, not a gate: it never blocks a Decision call,
 * and failures are logged and swallowed. Transient failures (network,
 * 5xx, 429) retry on a later gated call; a refusal (4xx) is a config
 * problem and is not retried until the process restarts.
 */

import { resolveApiKey, resolveBaseUrl, type FetchLike } from "./client.js";

export const ANNOUNCE_TIMEOUT_MS = 10_000;
const MAX_AGENTS = 50;
const MAX_SKILLS = 100;
const MAX_NAME_LEN = 200;
const MAX_INSTANCE_LEN = 120;

export interface AnnounceConfig {
  apiKey?: string;
  baseUrl?: string;
  /** Opt-in: nothing is announced unless this is exactly true. */
  announce?: boolean;
  /** Stable instance name — the identity namespace for announced rows.
   * Rows re-namespace if it changes, so pick one and keep it. */
  instance?: string;
  /** Agent ids to announce (names only). Defaults to [agentDid]. */
  announceAgents?: string[];
  /** Skill slugs to announce (names only). */
  announceSkills?: string[];
  agentDid?: string;
  /** Pull-enroll. Default ON (`enroll !== false`). Set false to skip. */
  enroll?: boolean;
  /** One-shot operator token from Govern / the snippet pack. */
  enrollToken?: string;
}

export interface AnnounceResult {
  ok: boolean;
  status?: number;
  reason?: string;
  /** Transient (network / 5xx / 429): a later gated call may retry.
   * False for successes and for 4xx config refusals. */
  retryable?: boolean;
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

/** Fire one announce. Never throws — the caller is a Decision gate.
 * `fallbackAgentId` should be the Bot id when available: the announced
 * identity must match the did stamped on decision leaves. */
export async function announceInstance(
  cfg: AnnounceConfig,
  fetchImpl?: FetchLike,
  log: (msg: string) => void = () => {},
  fallbackAgentId?: string,
): Promise<AnnounceResult> {
  if (cfg.announce !== true) {
    return { ok: false, reason: "announce not enabled" };
  }
  const apiKey = resolveApiKey(asString(cfg.apiKey) || undefined);
  if (!apiKey) {
    log("artzain announce skipped: no API key configured");
    return { ok: false, reason: "no api key" };
  }
  const instance = boundName(asString(cfg.instance), MAX_INSTANCE_LEN);
  if (!instance) {
    log("artzain announce skipped: set `instance` to a stable name");
    return { ok: false, reason: "no instance name" };
  }
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

  const impl: FetchLike | undefined =
    fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (!impl) {
    log("artzain announce skipped: no fetch implementation (Node >= 18 required)");
    return { ok: false, reason: "no fetch" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ANNOUNCE_TIMEOUT_MS);
  try {
    const resp = await impl(
      `${resolveBaseUrl(cfg.baseUrl)}/api/v1/registry/announce`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": apiKey,
        },
        body: JSON.stringify({ source: "grokbot", instance, agents, skills }),
        signal: controller.signal,
      },
    );
    if (!resp.ok) {
      const retryable = resp.status >= 500 || resp.status === 429;
      log(`artzain announce refused: HTTP ${resp.status}` +
        (retryable ? " (will retry on a later gated call)" : ""));
      return { ok: false, status: resp.status, reason: `http ${resp.status}`, retryable };
    }
    let counts = "";
    try {
      const data = (await resp.json()) as Record<string, unknown>;
      const n = (k: string) => (typeof data[k] === "number" ? (data[k] as number) : 0);
      counts = `registered ${n("registered")}, seen ${n("seen")}, ` +
        `blocked ${n("blocked")}, deferred ${n("deferred")}, ` +
        `failed ${n("failed")}`;
      if (n("deferred") > 0) {
        counts += " — deferred rows are not retried until a re-announce (restart)";
      }
      if (n("failed") > 0) {
        counts += " — failed rows hit a server-side write error and were NOT " +
          "stored; a re-announce (restart) retries them";
      }
    } catch {
      counts = "response unreadable";
    }
    log(`artzain announce ok: instance '${instance}', ${agents.length} agent(s); ${counts}`);
    return { ok: true, status: resp.status };
  } catch (err) {
    log(`artzain announce failed: ${(err as Error).message} ` +
      "(will retry on a later gated call)");
    return { ok: false, reason: (err as Error).message, retryable: true };
  } finally {
    clearTimeout(timer);
  }
}
