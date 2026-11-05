/**
 * Cooperative Decision gate for a Grok Bot skill (pattern C).
 *
 * There is no documented host `before_tool_call` intercept. The operator
 * installs this skill and the Bot description tells it to call
 * `gateToolCall` (or the `grokbot-artzain decide` CLI) before a
 * side-effect. Fail-closed only when the skill actually runs; a Bot that
 * never calls it is ungoverned — which is what the catalog + Marshal
 * already surface.
 *
 * `handleBeforeToolCall` is that same gate in the shape a host
 * `before_tool_call` hook calls. This package does not register the hook.
 */

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
import {
  currentCliVersion,
  enrollIsFresh,
  enrollStateKey,
  enrollTtlMs,
  readEnrollState,
  recordEnroll,
} from "./state.js";

export interface SkillConfig extends AnnounceConfig {
  apiKey?: string;
  baseUrl?: string;
  agentDid?: string;
  /** Hours before the same base URL, key and Bot enroll again. The CLI sets this from `GROKBOT_ENROLL_TTL_HOURS`. */
  enrollTtlHours?: string;
}

export interface GateInput {
  toolName: string;
  params?: Record<string, unknown>;
  payload?: string;
  target?: string;
  toolCallId?: string;
  agentDid?: string;
  /** Decision id of an approved review this call cites. */
  citesReview?: string;
  modelId?: string;
  workloadId?: string;
  /** Advisory context. Unknown keys are sent with the decision. */
  context?: Record<string, unknown>;
  session?: string;
  parent?: string;
  onBehalfOf?: string;
}

export type GateResult =
  | { allow: true; decision: DecisionResponse }
  | {
      allow: false;
      blockReason: string;
      outcome?: string;
      /** Present when the engine answered. A client_update warning lives here. */
      warnings?: DecisionResponse["warnings"];
      /** The engine's decision, when this answer is one. */
      decisionId?: string;
    };

let announceStarted = false;
/** An enroll this process has started, keyed like the state file. */
const enrollPending = new Map<string, Promise<void>>();
/** A refusal (not a transient failure) is not tried again until the process ends. */
const enrollRefused = new Set<string>();

export function resetAnnounceForTests(): void {
  announceStarted = false;
  enrollPending.clear();
  enrollRefused.clear();
}

export function resetEnrollForTests(): void {
  enrollPending.clear();
  enrollRefused.clear();
}

/** Tests wait until the enroll that ran beside a decision has settled. */
export function settleEnrollForTests(): Promise<void> {
  return Promise.all([...enrollPending.values()]).then(() => undefined);
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
  // Exactly false, including GROKBOT_ENROLL=false and --no-enroll. Any
  // other value, and an omitted one, enrolls.
  if (cfg.enroll === false) return;
  const apiKey = resolveApiKey(cfg.apiKey);
  const agentId = ctxAgentId || cfg.agentDid || "grokbot-agent";
  const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
  const slot = apiKey ? enrollStateKey(base.url, apiKey, agentId) : "";
  if (enrollRefused.has(slot) || enrollPending.has(slot)) return;

  const job = (async () => {
    const version = currentCliVersion();
    if (slot) {
      const saved = await readEnrollState();
      const ttl = enrollTtlMs(cfg.enrollTtlHours ?? process.env.GROKBOT_ENROLL_TTL_HOURS);
      if (enrollIsFresh(saved?.entries[slot], version, Date.now(), ttl)) return;
    }
    const result = await enrollInstance(
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
    );
    if (!slot) return;
    if (result.ok) {
      try {
        await recordEnroll(slot, version, new Date());
      } catch {
        /* the next decide enrolls again when the record did not land */
      }
    } else if (!result.retryable) {
      enrollRefused.add(slot);
    }
  })();
  enrollPending.set(slot, job);
  void job.finally(() => {
    if (enrollPending.get(slot) === job) enrollPending.delete(slot);
  });
}

const CLIENT_TOO_OLD =
  "REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.";

function isClientTooOld(err: unknown): boolean {
  if (!(err instanceof DecisionError) || err.status !== 422) return false;
  const detail = err.detail;
  if (!detail || typeof detail !== "object") return false;
  return (detail as { code?: unknown }).code === "client_too_old";
}

/** The tool-call payload a decide sends. A queued copy stores this text. */
export function decisionPayload(toolName: string, params: unknown, given?: string): string {
  if (given !== undefined) return given;
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
    const base = resolveBaseUrlSetting(cfg.baseUrl, cfg.baseUrlSource);
    const decision: DecisionResponse = await postDecision({
      apiKey,
      baseUrl: base.url,
      baseSource: base.source,
      action: toolName,
      target: input.target || `grokbot:tool:${toolName}`,
      payload: decisionPayload(toolName, input.params, input.payload),
      agentDid,
      requestId: requestId || undefined,
      citesReview: input.citesReview,
      modelId: input.modelId,
      workloadId: input.workloadId,
      context: input.context,
      session: input.session,
      parent: input.parent,
      onBehalfOf: input.onBehalfOf,
      timeoutMs: DECIDE_TIMEOUT_MS,
      fetchImpl,
    });

    if (decision.outcome === "allow") {
      return { allow: true, decision };
    }

    const reasons = (decision.reasons || []).join("; ") || decision.outcome;
    const decisionId = decision.decision_id || undefined;
    if (decision.outcome === "review") {
      return {
        allow: false,
        outcome: "review",
        decisionId,
        blockReason: `QUEUED FOR REVIEW: ${reasons} (decision ${decision.decision_id})`,
        warnings: decision.warnings,
      };
    }
    return {
      allow: false,
      outcome: decision.outcome,
      decisionId,
      blockReason: `REFUSED: ${reasons} (decision ${decision.decision_id})`,
      warnings: decision.warnings,
    };
  } catch (err) {
    if (isClientTooOld(err)) {
      return { allow: false, outcome: "deny", blockReason: CLIENT_TOO_OLD };
    }
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

/** A host `before_tool_call` event. `context.pluginConfig` is this package's skill config. */
export interface ToolCallEvent {
  toolName: string;
  params?: Record<string, unknown>;
  toolCallId?: string;
  runId?: string;
  context?: { pluginConfig?: SkillConfig };
}

/** The context a host passes beside the event. */
export interface ToolCallCtx {
  agentId?: string;
  pluginConfig?: SkillConfig;
}

/** What a host hook returns when the tool must not run. An allow returns nothing. */
export type BlockResult = { block: true; blockReason: string };

function pluginConfigOf(event: ToolCallEvent, ctx: ToolCallCtx): SkillConfig {
  return event.context?.pluginConfig || ctx.pluginConfig || {};
}

/**
 * The host-hook form of `gateToolCall`. An allow returns nothing. Any other
 * outcome returns `{ block: true, blockReason }`. This package does not
 * register the hook.
 */
export async function handleBeforeToolCall(
  event: ToolCallEvent,
  ctx: ToolCallCtx,
  fetchImpl?: FetchLike,
): Promise<BlockResult | undefined> {
  const result = await gateToolCall(
    pluginConfigOf(event, ctx),
    {
      toolName: event.toolName,
      params: event.params,
      toolCallId: event.toolCallId || event.runId,
      agentDid: ctx.agentId,
    },
    fetchImpl,
  );
  if (result.allow) return;
  return { block: true, blockReason: result.blockReason };
}
