/**
 * `decide()` — gate a proposed agent action through the CogNEXUS Decision
 * API (`POST /api/v1/decisions`). Remote-only: unlike the Python SDK there
 * is no offline local-guard fallback — a missing API key throws a clear
 * `DecisionError` instead (documented divergence).
 */

import { resolveCredentials, type ResolvedCredentials } from "./config.js";
import { DecisionError, failureKind } from "./errors.js";

export type PayloadKind =
  | "user_input"
  | "external_content"
  | "tabular"
  | "model_output"
  | "tool_call";

// The lockstep blocks below are copied verbatim into
// sdk/openclaw/src/client.ts and sdk/grokbot/src/client.ts; lockstep.test.ts
// in those packages fails when they drift.
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
  /** Request timeout in milliseconds, reading the response included. Default 10000. */
  timeoutMs?: number;
  /** Test seam / custom transport. Defaults to global `fetch`. */
  fetchImpl?: FetchLike;
}

export async function decide(options: DecideOptions): Promise<DecisionResponse> {
  // The key and the host it may go to are decided together; a host that is
  // set but did not issue the key refuses the call before anything is sent.
  let creds: ResolvedCredentials;
  try {
    creds = resolveCredentials();
  } catch (err) {
    throw new DecisionError(`Decision request not sent: ${(err as Error).message}`);
  }
  const apiKey = creds.apiKey;
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
  // Serialized before the request, so that a context that does not serialize
  // (a BigInt, a cycle) is reported as the caller's data, not as the API.
  // The text describes that data (the SDK puts no setting in the body).
  let requestBody: string;
  try {
    requestBody = JSON.stringify(body);
  } catch (err) {
    throw new DecisionError(
      `Decision request not sent: it does not serialize to JSON: ${(err as Error)?.message ?? failureKind(err)}`,
    );
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
    options.timeoutMs ?? 10_000,
  );
  try {
    let resp: Awaited<ReturnType<FetchLike>>;
    try {
      resp = await fetchImpl(`${creds.baseUrl}/api/v1/decisions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": apiKey,
        },
        body: requestBody,
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (err) {
      // The error's text can quote the API key or name the host (see
      // failureKind), so the message names its kind and where the base URL
      // came from, and the error is not kept as a cause, which loggers print.
      throw new DecisionError(
        `Decision API unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${creds.baseSource})`,
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
