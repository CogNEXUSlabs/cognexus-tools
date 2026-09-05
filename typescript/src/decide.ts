/**
 * `decide()` — gate a proposed agent action through the CogNEXUS Decision
 * API (`POST /api/v1/decisions`). Remote-only: unlike the Python SDK there
 * is no offline local-guard fallback — a missing API key throws a clear
 * `DecisionError` instead (documented divergence).
 */

import { effectiveApiKey, effectiveBaseUrl } from "./config.js";
import { DecisionError } from "./errors.js";

export type PayloadKind =
  | "user_input"
  | "external_content"
  | "tabular"
  | "model_output"
  | "tool_call";

export type DecisionOutcome = "allow" | "deny" | "review";

export interface AgentVote {
  agent: string;
  verdict: string;
  score?: number | null;
  reason?: string | null;
}

export interface DecisionResponse {
  outcome: DecisionOutcome;
  decision_id: string;
  audit_block_id: string;
  contributing_agents: AgentVote[];
  policy_bundle_version: string;
  resolution_policy: string;
  latency_ms: number;
  reasons: string[];
}

export type FetchLike = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export interface DecideOptions {
  /** The proposed action verb, e.g. `"send_email"`. */
  action: string;
  /** What the action touches, e.g. `"crm:contact:123"`. */
  target: string;
  /** The content to screen (≤ 256 KiB). */
  payload: string;
  /** How the payload should be screened. Default `"user_input"`. */
  kind?: PayloadKind;
  /** Acting agent identity. Default `"cognexus-sdk-ts"`. */
  agentDid?: string;
  /** Calling surface recorded in the leaf. Default `"sdk"`. */
  surface?: string;
  /** Idempotency key — replays return the original sealed decision. */
  requestId?: string;
  /** FR-11 product identifier (`name@version`). */
  product?: string;
  /** Advisory context recorded alongside the decision. */
  context?: Record<string, unknown>;
  /** Request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  /** Test seam / custom transport. Defaults to global `fetch`. */
  fetchImpl?: FetchLike;
}

export async function decide(options: DecideOptions): Promise<DecisionResponse> {
  const apiKey = effectiveApiKey();
  if (!apiKey) {
    throw new DecisionError(
      "No API key configured — decisions will not be sealed. " +
        "Set COGNEXUS_API_KEY, call configure({ apiKey }), or run `artzain login` (~15s; " +
        "its ~/.artzain/credentials.toml profile is read on Node 20.16+ / 22.3+). " +
        "(The TypeScript SDK is remote-only; there is no offline guard fallback.)",
    );
  }
  const fetchImpl: FetchLike =
    options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) {
    throw new DecisionError("No fetch implementation available (Node >= 18 required).");
  }

  const body = {
    agent_did: options.agentDid ?? "cognexus-sdk-ts",
    action: options.action,
    target: options.target,
    payload: options.payload,
    payload_kind: options.kind ?? "user_input",
    surface: options.surface ?? "sdk",
    request_id: options.requestId ?? null,
    product: options.product ?? null,
    context: options.context ?? {},
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  let resp: Awaited<ReturnType<FetchLike>>;
  try {
    resp = await fetchImpl(`${effectiveBaseUrl()}/api/v1/decisions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": apiKey,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    throw new DecisionError(`Decision API unreachable: ${(err as Error).message}`);
  } finally {
    clearTimeout(timer);
  }

  if (!resp.ok) {
    let detail: unknown;
    try {
      detail = ((await resp.json()) as { detail?: unknown })?.detail;
    } catch {
      detail = undefined;
    }
    // Typed engine refusals (fail-closed): kill_switch_active / audit_unavailable.
    const detailText =
      typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : "";
    throw new DecisionError(
      `Decision API returned HTTP ${resp.status}${detailText ? `: ${detailText}` : ""}`,
      { status: resp.status, detail },
    );
  }
  return (await resp.json()) as DecisionResponse;
}
