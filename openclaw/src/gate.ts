import {
  DecisionError,
  DECIDE_TIMEOUT_MS,
  postDecision,
  resolveApiKey,
  resolveBaseUrl,
  type DecisionResponse,
  type FetchLike,
} from "./client.js";

export const HOOK_TIMEOUT_MS = 14_000;

export interface PluginConfig {
  apiKey?: string;
  baseUrl?: string;
  agentDid?: string;
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
    const decision: DecisionResponse = await postDecision({
      apiKey,
      baseUrl: resolveBaseUrl(cfg.baseUrl),
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
