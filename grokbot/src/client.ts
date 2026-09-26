/**
 * Decision API client used by the Grok Bot cooperative skill.
 *
 * Keep the request shape in lockstep with ``sdk/typescript/src/decide.ts``
 * (POST /api/v1/decisions, X-Api-Key, payload_kind=tool_call). Missing key
 * and HTTP 503 throw DecisionError — callers fail closed.
 *
 * The skill has no runtime dependency on ``@cognexuslabs/artzain`` on
 * purpose: it is installed from a git checkout, ships zero runtime
 * dependencies, and is released from its own tag on the mirror with no
 * ordering against the SDK's. So the shared pieces are copied verbatim
 * from ``sdk/typescript/src/{errors,decide}.ts`` between the
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

/** One enforcer's vote. The Decision API sends every field on every vote. */
export interface AgentVote {
  /** The enforcer, e.g. `"tool-call-contract"`. */
  name: string;
  /**
   * The enforcer's own verdict. A policy bundle's `resolution` can raise the
   * outcome above it, and the vote still reads what its enforcer said.
   */
  verdict: DecisionOutcome;
  /** On the engine's scale: `"none"`, `"low"`, `"medium"`, `"high"`, `"critical"`. */
  severity: string;
  /** Normalised 0–1 risk score; `null` when the enforcer does not score. */
  score: number | null;
  findings: string[];
  /** Set when the enforcer could not vote: its exception, or a code such as `registry_unavailable`. */
  error: string | null;
}

export interface DecisionResponse {
  outcome: DecisionOutcome;
  decision_id: string;
  audit_block_id: string;
  contributing_agents: AgentVote[];
  policy_bundle_version: string;
  resolution_policy: string;
  latency_ms: number;
  /**
   * Summary lines for a non-`allow` outcome, empty on `allow`. A line quotes
   * at most one finding per vote; the votes carry all of them.
   */
  reasons: string[];
  /**
   * Non-fatal advisories, e.g. `{ warning: "idempotent_replay", ... }`. They
   * never change the outcome. Engines older than the field omit it.
   */
  warnings?: Record<string, unknown>[];
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

  // One deadline for the request and for reading the response: the timer is
  // cleared only once the body has been read, so a server that sends its
  // headers and then stalls cannot hang the call.
  const controller = new AbortController();
  const timer = setTimeout(
    () =>
      controller.abort(
        new DOMException("The operation was aborted due to timeout", "TimeoutError"),
      ),
    options.timeoutMs ?? DECIDE_TIMEOUT_MS,
  );
  try {
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
          surface: "grokbot",
          request_id: options.requestId ?? null,
          context: {},
        }),
        signal: controller.signal,
      });
    } catch (err) {
      throw new DecisionError(
        `Decision API unreachable: ${(err as Error).message}`,
      );
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
      // A body that could not be read at all (the timeout passed while it
      // was arriving, the connection dropped) is not a JSON problem.
      const problem =
        (err as Error)?.name === "SyntaxError"
          ? "with a non-JSON body"
          : "but its body could not be read";
      throw new DecisionError(
        `Decision API returned HTTP ${resp.status} ${problem}: ${(err as Error).message}`,
        { status: resp.status },
      );
    }
    return parsed as DecisionResponse;
    // lockstep:end decision-response
  } finally {
    clearTimeout(timer);
  }
}
