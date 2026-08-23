/**
 * Decision API client used by the OpenClaw plugin.
 *
 * Keep the request shape in lockstep with ``sdk/typescript/src/decide.ts``
 * (POST /api/v1/decisions, X-Api-Key, payload_kind=tool_call). Missing key
 * and HTTP 503 throw DecisionError — callers fail closed.
 */

export const DEFAULT_BASE_URL = "https://app.cognexuslabs.ai";
export const DECIDE_TIMEOUT_MS = 12_000;

export class DecisionError extends Error {
  readonly status?: number;
  readonly detail?: unknown;

  constructor(message: string, options?: { status?: number; detail?: unknown }) {
    super(message);
    this.name = "DecisionError";
    this.status = options?.status;
    this.detail = options?.detail;
  }
}

export type DecisionOutcome = "allow" | "deny" | "review";

export interface DecisionResponse {
  outcome: DecisionOutcome;
  decision_id: string;
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
}>;

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
  return url.replace(/\/+$/, "");
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

  if (!resp.ok) {
    let detail: unknown;
    try {
      detail = ((await resp.json()) as { detail?: unknown })?.detail;
    } catch {
      detail = undefined;
    }
    const detailText =
      typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : "";
    throw new DecisionError(
      `Decision API returned HTTP ${resp.status}${detailText ? `: ${detailText}` : ""}`,
      { status: resp.status, detail },
    );
  }
  return (await resp.json()) as DecisionResponse;
}
