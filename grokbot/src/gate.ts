/**
 * Cooperative Decision gate for a Grok Bot skill (pattern C).
 *
 * There is no documented host `before_tool_call` intercept. The operator
 * installs this skill and the Bot description tells it to call
 * `gateToolCall` (or the `grokbot-artzain decide` CLI) before a
 * side-effect. Fail-closed only when the skill actually runs; a Bot that
 * never calls it is ungoverned — which is what the catalog + Marshal
 * already surface.
 */

import {
  DecisionError,
  DECIDE_TIMEOUT_MS,
  postDecision,
  resolveApiKey,
  resolveBaseUrl,
  type DecisionResponse,
  type FetchLike,
} from "./client.js";
import { announceInstance, type AnnounceConfig } from "./announce.js";
import { enrollInstance } from "./enroll.js";

export interface SkillConfig extends AnnounceConfig {
  apiKey?: string;
  baseUrl?: string;
  agentDid?: string;
}

export interface GateInput {
  toolName: string;
  params?: Record<string, unknown>;
  payload?: string;
  target?: string;
  toolCallId?: string;
  agentDid?: string;
}

export type GateResult =
  | { allow: true; decision: DecisionResponse }
  | { allow: false; blockReason: string; outcome?: string };

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
  cfg: SkillConfig,
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
        announceStarted = false;
      }
    })
    .catch(() => {
      /* announceInstance resolves rather than rejecting */
    });
}

function maybeEnrollOnce(
  cfg: SkillConfig,
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

function payloadFor(toolName: string, params: unknown): string {
  try {
    return JSON.stringify({ tool: toolName, arguments: params ?? {} });
  } catch {
    return JSON.stringify({ tool: toolName, arguments: { _unserializable: true } });
  }
}

export async function gateToolCall(
  cfg: SkillConfig,
  input: GateInput,
  fetchImpl?: FetchLike,
): Promise<GateResult> {
  maybeAnnounceOnce(cfg, fetchImpl, input.agentDid);
  maybeEnrollOnce(cfg, fetchImpl, input.agentDid);
  const apiKey = resolveApiKey(cfg.apiKey);
  if (!apiKey) {
    return {
      allow: false,
      blockReason:
        "decision unavailable (No API key configured — set COGNEXUS_API_KEY) — failing closed",
    };
  }

  const toolName = input.toolName || "unknown_tool";
  const requestId = (input.toolCallId || "").slice(0, 64);
  const agentDid = input.agentDid || cfg.agentDid || "grokbot-agent";

  try {
    const decision: DecisionResponse = await postDecision({
      apiKey,
      baseUrl: resolveBaseUrl(cfg.baseUrl),
      action: toolName,
      target: input.target || `grokbot:tool:${toolName}`,
      payload: input.payload || payloadFor(toolName, input.params),
      agentDid,
      requestId: requestId || undefined,
      timeoutMs: DECIDE_TIMEOUT_MS,
      fetchImpl,
    });

    if (decision.outcome === "allow") {
      return { allow: true, decision };
    }

    const reasons = (decision.reasons || []).join("; ") || decision.outcome;
    if (decision.outcome === "review") {
      return {
        allow: false,
        outcome: "review",
        blockReason: `QUEUED FOR REVIEW: ${reasons} (decision ${decision.decision_id})`,
      };
    }
    return {
      allow: false,
      outcome: decision.outcome,
      blockReason: `REFUSED: ${reasons} (decision ${decision.decision_id})`,
    };
  } catch (err) {
    const detail =
      err instanceof DecisionError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return {
      allow: false,
      blockReason: `decision unavailable (${detail}) — failing closed`,
    };
  }
}
