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

import { randomInt, randomUUID } from "node:crypto";

import { currentCliVersion } from "./state.js";

export const DEFAULT_BASE_URL = "https://app.cognexuslabs.ai";
export const DECIDE_TIMEOUT_MS = 12_000;

/** How many times one decide asks, including the first. */
const DECIDE_ATTEMPTS = 3;
/** Full-jitter cap for the wait after attempt 1, then double, held to this. */
const RETRY_BACKOFF_BASE_MS = 200;
const RETRY_BACKOFF_CAP_MS = 1_000;

/** A 429's `Retry-After`, in milliseconds, when the response carried one. */
const retryAfterWait = new WeakMap<DecisionError, number>();

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
  /**
   * The `product` field. A queued replay sends the value it stored, so the
   * engine sees the same inputs. Omitted, this command's version is used.
   */
  product?: string;
  /** An approved review this call cites. Sent as `context.cites_review`. */
  citesReview?: string;
  /** `model_id`. Empty when the caller does not name one. */
  modelId?: string;
  /** `workload_id`. Empty when the caller does not name one. */
  workloadId?: string;
  /**
   * Advisory context. Keys this command does not know are sent as given.
   * `session`, `parent`, `onBehalfOf` and `citesReview` are merged in and
   * do not drop the rest.
   */
  context?: Record<string, unknown>;
  /** `context.session`. */
  session?: string;
  /** `context.parent`, a decision id. */
  parent?: string;
  /** `context.on_behalf_of`. */
  onBehalfOf?: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

/**
 * A workload or model id, as the Decision API accepts it: trimmed, at most
 * 80 characters, and with no control character. Empty is allowed.
 */
export function dimensionId(value: string | undefined): string {
  const text = (value ?? "").trim();
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) < 32) {
      throw new DecisionError(
        "Decision request not sent: workload_id and model_id cannot include control characters.",
      );
    }
  }
  return text.slice(0, 80);
}

/**
 * The `context` object on a decision. Every key the caller set is kept.
 * `session`, `parent`, `on_behalf_of` and `cites_review` are written when
 * the command was given them. The Decision API does not put this object in
 * the signed leaf.
 */
export function decisionContext(options: {
  context?: Record<string, unknown>;
  session?: string;
  parent?: string;
  onBehalfOf?: string;
  citesReview?: string;
}): Record<string, unknown> {
  const context: Record<string, unknown> = { ...(options.context ?? {}) };
  const session = (options.session ?? "").trim();
  const parent = (options.parent ?? "").trim();
  const behalf = (options.onBehalfOf ?? "").trim();
  const cited = (options.citesReview ?? "").trim();
  if (session) context.session = session;
  if (parent) context.parent = parent;
  if (behalf) context.on_behalf_of = behalf;
  if (cited) context.cites_review = cited;
  return context;
}

/** The Decision API body for one decide, including a queued replay. */
export function decisionRequestBody(options: {
  agentDid: string;
  action: string;
  target: string;
  payload: string;
  requestId: string | null;
  product?: string;
  citesReview?: string;
  modelId?: string;
  workloadId?: string;
  context?: Record<string, unknown>;
  session?: string;
  parent?: string;
  onBehalfOf?: string;
}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    agent_did: options.agentDid,
    action: options.action,
    target: options.target,
    payload: options.payload,
    payload_kind: "tool_call",
    surface: "grokbot",
    request_id: options.requestId,
    product: options.product ?? `grokbot-artzain@${currentCliVersion()}`,
    context: decisionContext(options),
  };
  const workload = dimensionId(options.workloadId);
  const model = dimensionId(options.modelId);
  if (workload) body.workload_id = workload;
  if (model) body.model_id = model;
  return body;
}

function trimBase(url: string): string {
  // Scanned rather than trimmed with /\/+$/, which backtracks quadratically
  // on a value made up mostly of slashes (same loop as the SDK's config.ts).
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 47) end--;
  return url.slice(0, end);
}

/** Warned at most once per process. The next release drops the warning. */
let warnedMyappOnly = false;

/**
 * `MYAPP_API_KEY` is not a key. When that name is the only source, this
 * release says so on stderr and the caller has no key.
 */
function warnMyappOnly(): void {
  if (warnedMyappOnly) return;
  warnedMyappOnly = true;
  try {
    const stderr = (globalThis as { process?: { stderr?: { write?: (chunk: string) => unknown } } })
      .process?.stderr;
    stderr?.write?.(
      "MYAPP_API_KEY is not read, so there is no key. Set COGNEXUS_API_KEY. " +
        "This release warns when MYAPP_API_KEY is the only source.\n",
    );
  } catch {
    // A warning must not change the decision.
  }
}

/**
 * The key to send. An explicit value wins, then `COGNEXUS_API_KEY`.
 * `env`, when passed, is read instead of the process environment. That is
 * how a shim uses the environment it was given.
 */
export function resolveApiKey(
  pluginKey?: string,
  env?: Record<string, string | undefined>,
): string | undefined {
  const explicit = (pluginKey || "").trim();
  if (explicit) return explicit;
  const source =
    env ??
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const fromCognexus = (source?.COGNEXUS_API_KEY || "").trim();
  if (fromCognexus) return fromCognexus;
  if ((source?.MYAPP_API_KEY || "").trim()) warnMyappOnly();
  return undefined;
}

export function resolveBaseUrl(pluginBase?: string): string {
  return resolveBaseUrlSetting(pluginBase).url;
}

/** How a `baseUrl` from the skill's config is named: `configSource` if one is given. */
export function configBaseUrlSource(configSource?: unknown): string {
  return typeof configSource === "string" && configSource.trim()
    ? configSource
    : "skill config baseUrl";
}

/**
 * The base URL `resolveBaseUrl` picks and where it came from: skill config,
 * then `COGNEXUS_API_BASE_URL`, then the default. The source is a label for
 * messages, never the value; `configSource` names the config's `baseUrl`
 * (the CLI passes `--base-url`).
 */
export function resolveBaseUrlSetting(
  pluginBase?: string,
  configSource?: string,
): { url: string; source: string } {
  const explicit = (pluginBase || "").trim();
  if (explicit) return { url: trimBase(explicit), source: configBaseUrlSource(configSource) };
  const env =
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
      ?.env;
  const fromEnv = (env?.COGNEXUS_API_BASE_URL || "").trim();
  if (fromEnv) return { url: trimBase(fromEnv), source: "COGNEXUS_API_BASE_URL" };
  return { url: DEFAULT_BASE_URL, source: "default" };
}

/**
 * One decide. A missing `requestId` becomes a new id, and `--request-id`
 * (passed in as `requestId`) replaces it. The same id goes on every attempt,
 * so a replay returns the first decision instead of sealing another.
 *
 * The loop is the whole call: at most three attempts, and every wait, share
 * one deadline of `timeoutMs` (default `DECIDE_TIMEOUT_MS`). A network
 * error, HTTP 429, and HTTP 503 `audit_unavailable` or
 * `cited_review_unavailable` are tried again. A 503 `kill_switch_active`,
 * a redirect, and HTTP 401, 403, 404 and 422 are not.
 */
export async function postDecision(
  options: PostDecisionOptions,
): Promise<DecisionResponse> {
  const requestId = (options.requestId ?? "").trim().slice(0, 64) || randomUUID();
  const budget = options.timeoutMs ?? DECIDE_TIMEOUT_MS;
  const deadline = Date.now() + budget;
  let last: DecisionError | undefined;
  for (let attempt = 1; attempt <= DECIDE_ATTEMPTS; attempt++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    try {
      return await postDecisionOnce({ ...options, requestId, timeoutMs: remaining });
    } catch (err) {
      if (!(err instanceof DecisionError)) throw err;
      last = err;
      if (attempt === DECIDE_ATTEMPTS || !shouldRetry(err)) throw err;
      const room = deadline - Date.now();
      const wait = waitBeforeRetry(err, attempt, room);
      if (wait === undefined) throw err;
      if (wait > 0) await pause(wait);
    }
  }
  throw last ?? timeoutError(options.baseSource);
}

function timeoutError(baseSource: string | undefined): DecisionError {
  return new DecisionError(
    "Decision API unreachable: TimeoutError, aborted when the timeout passed " +
      `(base URL from ${baseSource ?? "the baseUrl option"})`,
  );
}

/** Network loss, a replayable 503, or 429. A timeout has already used the deadline. */
function shouldRetry(err: DecisionError): boolean {
  if (err.message.includes("TimeoutError")) return false;
  if (err.status === 429) return true;
  if (err.status === 503) {
    return err.detail === "audit_unavailable" || err.detail === "cited_review_unavailable";
  }
  if (err.status === undefined && err.message.startsWith("Decision API unreachable:")) return true;
  // A 2xx whose body never arrived. The id makes a replay safe.
  return err.message.includes("but its body could not be read:");
}

/**
 * Milliseconds to wait, or `undefined` when the wait would run past the
 * deadline. HTTP 429 uses `Retry-After` when the response had one.
 */
function waitBeforeRetry(err: DecisionError, attempt: number, roomMs: number): number | undefined {
  const header = retryAfterWait.get(err);
  const wait = header !== undefined ? header : backoffMs(attempt);
  if (wait >= roomMs) return undefined;
  return wait;
}

/** Full jitter from 0 through the cap for this attempt. Attempt 1 caps at the base. */
function backoffMs(attempt: number): number {
  const cap = Math.min(RETRY_BACKOFF_CAP_MS, RETRY_BACKOFF_BASE_MS * 2 ** (attempt - 1));
  return cap <= 0 ? 0 : randomInt(0, cap + 1);
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** `Retry-After` as a delay. Whole seconds, or an HTTP date. Missing and unreadable are omitted. */
function retryAfterHeaderMs(resp: object): number | undefined {
  const headers = (resp as { headers?: { get?: (name: string) => string | null } }).headers;
  const raw = headers?.get?.("retry-after");
  if (raw == null) return undefined;
  const text = raw.trim();
  if (!text) return undefined;
  const seconds = Number(text);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const at = Date.parse(text);
  if (!Number.isFinite(at)) return undefined;
  return Math.max(0, at - Date.now());
}

async function postDecisionOnce(
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
        body: JSON.stringify(
          decisionRequestBody({
            agentDid: options.agentDid,
            action: options.action,
            target: options.target,
            payload: options.payload,
            requestId: options.requestId ?? null,
            product: options.product,
            citesReview: options.citesReview,
            modelId: options.modelId,
            workloadId: options.workloadId,
            context: options.context,
            session: options.session,
            parent: options.parent,
            onBehalfOf: options.onBehalfOf,
          }),
        ),
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

    const retryAfterMs = resp.status === 429 ? retryAfterHeaderMs(resp) : undefined;
    try {
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
    } catch (err) {
      if (retryAfterMs !== undefined && err instanceof DecisionError) {
        retryAfterWait.set(err, retryAfterMs);
      }
      throw err;
    }
  } finally {
    clearTimeout(timer);
  }
}

const REVIEW_STATUSES = new Set(["pending", "approved", "rejected"]);

export interface ReviewStatus {
  decision_id: string;
  status: "pending" | "approved" | "rejected";
}

/**
 * Read one review this account made. The body is pending, approved, or
 * rejected. This does not resolve the review. A missing review, another
 * account, a redirect, and a transport error all throw: none of them is an
 * approval.
 */
export async function getReviewStatus(options: {
  apiKey: string;
  baseUrl: string;
  baseSource?: string;
  decisionId: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}): Promise<ReviewStatus> {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DECIDE_TIMEOUT_MS);
  try {
    let resp: Awaited<ReturnType<FetchLike>>;
    try {
      resp = await fetchImpl(
        `${trimBase(options.baseUrl)}/api/v1/decisions/${encodeURIComponent(options.decisionId)}/review`,
        {
          method: "GET",
          headers: { "X-Api-Key": options.apiKey },
          signal: controller.signal,
          redirect: "manual",
        },
      );
    } catch (err) {
      throw new DecisionError(
        `Decision API unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${options.baseSource ?? "the baseUrl option"})`,
      );
    }
    if (resp.status >= 300 && resp.status < 400) {
      controller.abort();
      throw new DecisionError(
        `Decision API returned HTTP ${resp.status}, a redirect, which is not followed: ` +
          "check the base URL",
        { status: resp.status },
      );
    }
    if (!resp.ok) {
      controller.abort();
      throw new DecisionError(`Decision API returned HTTP ${resp.status}`, { status: resp.status });
    }
    let parsed: unknown;
    try {
      parsed = await resp.json();
    } catch (err) {
      const kind = failureKind(err, controller.signal);
      throw new DecisionError(
        kind === "SyntaxError"
          ? `Decision API returned HTTP ${resp.status} with a non-JSON body`
          : `Decision API returned HTTP ${resp.status} but its body could not be read: ${kind}`,
        { status: resp.status },
      );
    }
    const body = parsed as { decision_id?: unknown; status?: unknown };
    if (
      typeof body.decision_id !== "string" ||
      typeof body.status !== "string" ||
      !REVIEW_STATUSES.has(body.status)
    ) {
      throw new DecisionError("Decision API returned a review status this command does not read", {
        status: resp.status,
      });
    }
    return {
      decision_id: body.decision_id,
      status: body.status as ReviewStatus["status"],
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Whether this account has a leaf sealed under `decisionId`.
 *
 * `GET /api/v1/audit/decisions?decision=` returns that page. An empty page is
 * not an error: the id is well formed and this account has no such leaf.
 * A redirect, a non-JSON body, and any other status throw. None of them is
 * a found decision, and this does not check the bundle. `artzain audit verify`
 * is what reports SELF-ATTESTED.
 */
export async function lookupAuditDecision(options: {
  apiKey: string;
  baseUrl: string;
  baseSource?: string;
  decisionId: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}): Promise<{ found: boolean }> {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DECIDE_TIMEOUT_MS);
  try {
    let resp: Awaited<ReturnType<FetchLike>>;
    const query = new URLSearchParams({ decision: options.decisionId });
    try {
      resp = await fetchImpl(
        `${trimBase(options.baseUrl)}/api/v1/audit/decisions?${query.toString()}`,
        {
          method: "GET",
          headers: { "X-Api-Key": options.apiKey },
          signal: controller.signal,
          redirect: "manual",
        },
      );
    } catch (err) {
      throw new DecisionError(
        `Decision API unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${options.baseSource ?? "the baseUrl option"})`,
      );
    }
    if (resp.status >= 300 && resp.status < 400) {
      controller.abort();
      throw new DecisionError(
        `Decision API returned HTTP ${resp.status}, a redirect, which is not followed: ` +
          "check the base URL",
        { status: resp.status },
      );
    }
    if (!resp.ok) {
      controller.abort();
      throw new DecisionError(`Decision API returned HTTP ${resp.status}`, { status: resp.status });
    }
    let parsed: unknown;
    try {
      parsed = await resp.json();
    } catch (err) {
      const kind = failureKind(err, controller.signal);
      throw new DecisionError(
        kind === "SyntaxError"
          ? `Decision API returned HTTP ${resp.status} with a non-JSON body`
          : `Decision API returned HTTP ${resp.status} but its body could not be read: ${kind}`,
        { status: resp.status },
      );
    }
    const decisions = (parsed as { decisions?: unknown }).decisions;
    if (!Array.isArray(decisions)) {
      throw new DecisionError("Decision API returned an audit list this command does not read", {
        status: resp.status,
      });
    }
    const found = decisions.some(
      (row) =>
        !!row &&
        typeof row === "object" &&
        (row as { decision_id?: unknown }).decision_id === options.decisionId,
    );
    return { found };
  } finally {
    clearTimeout(timer);
  }
}
