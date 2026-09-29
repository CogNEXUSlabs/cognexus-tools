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

// lockstep:begin failure-kind
/**
 * The kind of error a request failed with, for a message: its name, and its
 * code when it has one (`TypeError`, `Error [ECONNREFUSED]`). A TypeError
 * with a cause, such as fetch's "fetch failed", is named by its cause. The
 * error's text is left out, and so is a name or code that is not an
 * identifier: fetch quotes a header value it refuses, an API key among them,
 * and a certificate issued for another name puts the host in the text.
 *
 * Once `deadline`, the call's own timeout signal, has fired, the failure is
 * that timeout, whatever the transport rejected with.
 */
export function failureKind(err: unknown, deadline?: AbortSignal): string {
  if (deadline?.aborted) return "TimeoutError, aborted when the timeout passed";
  try {
    let failure = err as { name?: unknown; code?: unknown; cause?: unknown } | null | undefined;
    if (failure?.name === "TypeError" && typeof failure.cause === "object" && failure.cause) {
      failure = failure.cause as typeof failure;
    }
    const name = failure?.name;
    const code = failure?.code;
    const kind = typeof name === "string" && /^[A-Z][A-Za-z0-9_]{0,63}$/.test(name) ? name : "Error";
    return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? `${kind} [${code}]` : kind;
  } catch {
    // A property that throws when read (a proxy, a getter) names nothing.
    return "Error";
  }
}
// lockstep:end failure-kind

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
    /**
     * Always `"manual"`. The request carries the API key, and following a
     * redirect sends it again to wherever `Location` points, which may be
     * another host. `fetch` hands back the 3xx instead, and the call treats
     * it as the error status it is. A custom transport must not follow
     * redirects either.
     */
    redirect: "manual";
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
  /**
   * Where `baseUrl` came from, named when the request fails: a label such as
   * `COGNEXUS_API_BASE_URL`, never the value. Default `"the baseUrl option"`.
   */
  baseSource?: string;
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
  return resolveBaseUrlSetting(pluginBase).url;
}

/**
 * The base URL `resolveBaseUrl` picks and where it came from: plugin config,
 * then `COGNEXUS_API_BASE_URL`, then the default. The source is a label for
 * messages, never the value.
 */
export function resolveBaseUrlSetting(pluginBase?: string): { url: string; source: string } {
  const explicit = (pluginBase || "").trim();
  if (explicit) return { url: trimBase(explicit), source: "plugin config baseUrl" };
  const env =
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
      ?.env;
  const fromEnv = (env?.COGNEXUS_API_BASE_URL || "").trim();
  if (fromEnv) return { url: trimBase(fromEnv), source: "COGNEXUS_API_BASE_URL" };
  return { url: DEFAULT_BASE_URL, source: "default" };
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
          surface: "openclaw",
          request_id: options.requestId ?? null,
          context: {},
        }),
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (err) {
      // The error's text can quote the API key or name the host (see
      // failureKind), so the message names its kind and where the base URL
      // came from, and the error is not kept as a cause, which loggers print.
      throw new DecisionError(
        `Decision API unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${options.baseSource ?? "the baseUrl option"})`,
      );
    }

    // lockstep:begin decision-response
    if (resp.status >= 300 && resp.status < 400) {
      // A redirect is not followed (see FetchLike), so the 3xx itself lands
      // here. Its body is the redirecting server's, not an engine refusal,
      // and is left unread: ending the request releases the connection,
      // which a large unread body would hold until garbage collection.
      controller.abort();
      throw new DecisionError(
        `Decision API returned HTTP ${resp.status}, a redirect, which is not followed: ` +
          "check the base URL",
        { status: resp.status },
      );
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
    let parsed: unknown;
    try {
      parsed = await resp.json();
    } catch (err) {
      // A 2xx that is not JSON (a proxy or captive portal answering HTML)
      // surfaced as a bare SyntaxError, outside the DecisionError contract.
      // A body that could not be read at all (the timeout passed while it
      // was arriving, the connection dropped) is not a JSON problem. Neither
      // message quotes the error: a SyntaxError quotes the body, which can
      // echo the request's headers.
      const kind = failureKind(err, controller.signal);
      throw new DecisionError(
        kind === "SyntaxError"
          ? `Decision API returned HTTP ${resp.status} with a non-JSON body`
          : `Decision API returned HTTP ${resp.status} but its body could not be read: ${kind}`,
        { status: resp.status },
      );
    }
    return parsed as DecisionResponse;
    // lockstep:end decision-response
  } finally {
    clearTimeout(timer);
  }
}
