/**
 * Decision API client used by the OpenClaw plugin.
 *
 * Keep the request shape in lockstep with ``sdk/typescript/src/decide.ts``
 * (POST /api/v1/decisions, X-Api-Key, payload_kind=tool_call). Missing key
 * and HTTP 503 throw DecisionError — callers fail closed.
 *
 * The plugin has no runtime dependency on ``@cognexuslabs/artzain`` on
 * purpose: it is installed from a git checkout (``openclaw plugins install
 * ./sdk/openclaw``) and loaded from ``src/index.ts`` with no install step,
 * ships zero runtime dependencies, and is released from its own tag on the
 * mirror with no ordering against the SDK's. So the shared pieces are copied
 * verbatim from ``sdk/typescript/src/{errors,decide}.ts`` between the
 * ``lockstep:begin`` / ``lockstep:end`` markers, and ``lockstep.test.ts``
 * fails when a copy drifts from its source.
 */

export const DEFAULT_BASE_URL = "https://app.cognexuslabs.ai";
export const DECIDE_TIMEOUT_MS = 12_000;

// lockstep:begin DecisionError
/** Raised when the Decision API cannot return a decision. */
export class DecisionError extends Error {
  /** HTTP status when the server answered; undefined on transport failure. */
  readonly status?: number;
  /** Parsed `detail` from the server's error body, when present. */
  readonly detail?: unknown;

  constructor(message: string, options?: { status?: number; detail?: unknown }) {
    super(message);
    this.name = "DecisionError";
    this.status = options?.status;
    this.detail = options?.detail;
  }
}
// lockstep:end DecisionError

// lockstep:begin decision-types
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
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;
// lockstep:end decision-types

export interface PostDecisionOptions {
  apiKey: string;
  baseUrl: string;
  action: string;
  target: string;
  payload: string;
  agentDid: string;
  requestId?: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

function trimBase(url: string): string {
  // Scanned rather than trimmed with /\/+$/, which backtracks quadratically
  // on a value made up mostly of slashes (same loop as the SDK's config.ts).
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 47) end--;
  return url.slice(0, end);
}

export function resolveApiKey(pluginKey?: string): string | undefined {
  const explicit = (pluginKey || "").trim();
  if (explicit) return explicit;
  const env =
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
      ?.env;
  return (env?.COGNEXUS_API_KEY || env?.MYAPP_API_KEY || "").trim() || undefined;
}

export function resolveBaseUrl(pluginBase?: string): string {
  const explicit = (pluginBase || "").trim();
  if (explicit) return trimBase(explicit);
  const env =
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
      ?.env;
  const fromEnv = (env?.COGNEXUS_API_BASE_URL || "").trim();
  return trimBase(fromEnv || DEFAULT_BASE_URL);
}

export async function postDecision(
  options: PostDecisionOptions,
): Promise<DecisionResponse> {
  const fetchImpl: FetchLike =
    options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) {
    throw new DecisionError("No fetch implementation available (Node >= 18 required).");
  }

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? DECIDE_TIMEOUT_MS,
  );
  let resp: Awaited<ReturnType<FetchLike>>;
  try {
    resp = await fetchImpl(`${trimBase(options.baseUrl)}/api/v1/decisions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": options.apiKey,
      },
      body: JSON.stringify({
        agent_did: options.agentDid,
        action: options.action,
        target: options.target,
        payload: options.payload,
        payload_kind: "tool_call",
        surface: "openclaw",
        request_id: options.requestId ?? null,
        context: {},
      }),
      signal: controller.signal,
    });
  } catch (err) {
    throw new DecisionError(
      `Decision API unreachable: ${(err as Error).message}`,
    );
  } finally {
    clearTimeout(timer);
  }

  // lockstep:begin decision-response
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
  let parsed: unknown;
  try {
    parsed = await resp.json();
  } catch (err) {
    // A 2xx that is not JSON (a proxy or captive portal answering HTML)
    // surfaced as a bare SyntaxError, outside the DecisionError contract.
    throw new DecisionError(
      `Decision API returned HTTP ${resp.status} with a non-JSON body: ${(err as Error).message}`,
      { status: resp.status },
    );
  }
  return parsed as DecisionResponse;
  // lockstep:end decision-response
}
