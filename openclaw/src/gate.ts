import {
  DecisionError,
  DECIDE_TIMEOUT_MS,
  postDecision,
  resolveApiKey,
  resolveBaseUrlSetting,
  type DecisionResponse,
  type FetchLike,
} from "./client.js";
import { announceInstance, type AnnounceConfig } from "./announce.js";
import { enrollInstance } from "./enroll.js";

export const HOOK_TIMEOUT_MS = 14_000;

export interface PluginConfig extends AnnounceConfig {
  apiKey?: string;
  baseUrl?: string;
  agentDid?: string;
}

/** Announce fires from the first gated call — the register hook never
 * sees plugin config, the tool path does. It is fire-and-forget: gating
 * NEVER waits on it, and its failure never blocks. Delivery is
 * attempt-once per process for successes and config refusals (3xx, 4xx);
 * TRANSIENT failures (network, 5xx, 429) re-arm so a later gated call
 * retries — a laptop whose first tool call happens offline still
 * announces once the network is back. Enroll is the same contract and
 * default ON (`enroll !== false`). */
let announceStarted = false;
let enrollStarted = false;

export function resetAnnounceForTests(): void {
  announceStarted = false;
  enrollStarted = false;
}

export function resetEnrollForTests(): void {
  enrollStarted = false;
}

function maybeAnnounceOnce(
  cfg: PluginConfig,
  fetchImpl?: FetchLike,
  ctxAgentId?: string,
): void {
  if (announceStarted || cfg.announce !== true) return;
  announceStarted = true;
  void announceInstance(
    cfg,
    fetchImpl,
    (msg) => {
      try {
        console.error(msg);
      } catch {
        /* logging must never break gating */
      }
    },
    ctxAgentId,
  )
    .then((result) => {
      if (!result.ok && result.retryable) {
        announceStarted = false; // transient — try again on a later call
      }
    })
    .catch(() => {
      /* announceInstance resolves rather than rejecting; belt-and-braces */
    });
}

function maybeEnrollOnce(
  cfg: PluginConfig,
  fetchImpl?: FetchLike,
  ctxAgentId?: string,
): void {
  if (enrollStarted || cfg.enroll === false) return;
  enrollStarted = true;
  void enrollInstance(
    cfg,
    fetchImpl,
    (msg) => {
      try {
        console.error(msg);
      } catch {
        /* logging must never break gating */
      }
    },
    ctxAgentId,
  )
    .then((result) => {
      if (!result.ok && result.retryable) {
        enrollStarted = false;
      }
    })
    .catch(() => {
      /* enrollInstance resolves rather than rejecting */
    });
}

export interface ToolCallEvent {
  toolName: string;
  params?: Record<string, unknown>;
  toolCallId?: string;
  runId?: string;
  context?: { pluginConfig?: PluginConfig };
}

export interface ToolCallCtx {
  agentId?: string;
  pluginConfig?: PluginConfig;
}

export type BlockResult = { block: true; blockReason: string };

function payloadFor(toolName: string, params: unknown): string {
  try {
    return JSON.stringify({ tool: toolName, arguments: params ?? {} });
  } catch {
    return JSON.stringify({ tool: toolName, arguments: { _unserializable: true } });
  }
}

function block(reason: string): BlockResult {
  return { block: true, blockReason: reason };
}

export function pluginConfigOf(
  event: ToolCallEvent,
  ctx: ToolCallCtx,
): PluginConfig {
  return event.context?.pluginConfig || ctx.pluginConfig || {};
}

export async function handleBeforeToolCall(
  event: ToolCallEvent,
  ctx: ToolCallCtx,
  fetchImpl?: FetchLike,
): Promise<BlockResult | undefined> {
  const cfg = pluginConfigOf(event, ctx);
  // ctx.agentId first: the announced default identity must match the did
  // the gate stamps on decision leaves, or reconciliation flags this very
  // instance's traffic as an unregistered agent.
  maybeAnnounceOnce(cfg, fetchImpl, ctx.agentId);
  maybeEnrollOnce(cfg, fetchImpl, ctx.agentId);
  const apiKey = resolveApiKey(cfg.apiKey);
  if (!apiKey) {
    return block(
      "decision unavailable (No API key configured — set COGNEXUS_API_KEY or plugin apiKey) — failing closed",
    );
  }

  const toolName = event.toolName || "unknown_tool";
  const requestId = (event.toolCallId || event.runId || "").slice(0, 64);
  const agentDid = ctx.agentId || cfg.agentDid || "openclaw-gateway";

  try {
    const base = resolveBaseUrlSetting(cfg.baseUrl);
    const decision: DecisionResponse = await postDecision({
      apiKey,
      baseUrl: base.url,
      baseSource: base.source,
      action: toolName,
      target: `openclaw:tool:${toolName}`,
      payload: payloadFor(toolName, event.params),
      agentDid,
      requestId: requestId || undefined,
      timeoutMs: DECIDE_TIMEOUT_MS,
      fetchImpl,
    });

    if (decision.outcome === "allow") {
      return;
    }

    const reasons = (decision.reasons || []).join("; ") || decision.outcome;
    if (decision.outcome === "review") {
      return block(
        `QUEUED FOR REVIEW: ${reasons} (decision ${decision.decision_id})`,
      );
    }
    return block(`REFUSED: ${reasons} (decision ${decision.decision_id})`);
  } catch (err) {
    const detail =
      err instanceof DecisionError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return block(`decision unavailable (${detail}) — failing closed`);
  }
}
