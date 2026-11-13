/**
 * Fail-closed routing for the ArtzAIn Decision node.
 *
 * HTTP 200 + outcome allow/review/deny → that branch. Any other status
 * (503 audit_unavailable, 401/422 misconfig, transport-shaped bodies)
 * becomes deny. review is a stop branch — not a Wait node.
 */

import { randomUUID } from "node:crypto";

import { trimTrailingSlashes } from "./base-url.js";

export type DecisionBranch = "allow" | "review" | "deny";

/** Server-side cap on `request_id` (`application/api/decisions.py`). */
export const REQUEST_ID_MAX_LENGTH = 64;

export interface RoutedDecision {
  branch: DecisionBranch;
  json: Record<string, unknown>;
}

export interface DecisionBody {
  agent_did: string;
  action: string;
  target: string;
  payload: string;
  payload_kind: string;
  surface: string;
  request_id: string | null;
  /** The session this decision belongs to. Absent when there is none to send. */
  session_id?: string;
  context: Record<string, unknown>;
}

/** The server keeps 128 characters of a session id. */
export const SESSION_ID_MAX_LENGTH = 128;

/**
 * A session id as the Decision API takes it: trimmed and cut to the server's
 * width. One with a control character is the empty string, and the field is
 * then left out: the server answers it with a 422, and a session id is not
 * worth a refused decision.
 */
function sessionText(value: string | undefined): string {
  const text = String(value ?? "").trim();
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f]/.test(text)) return "";
  return text.slice(0, SESSION_ID_MAX_LENGTH);
}

/**
 * The session of an execution's decisions: `n8n:<instance>:<execution>`, or
 * `n8n:<execution>` on an n8n that names no instance. Execution ids count up
 * per instance, so the instance keeps two instances on one account apart.
 * Empty without an execution id (older n8n, unit tests): a random id would
 * group nothing. The instance is cut, never the execution.
 */
export function executionSessionId(
  instanceId: string | undefined,
  executionId: string | undefined,
): string {
  const execution = sessionText(executionId);
  if (!execution) return "";
  const room = SESSION_ID_MAX_LENGTH - "n8n::".length - execution.length;
  const instance = room > 0 ? sessionText(instanceId).slice(0, room) : "";
  return sessionText(instance ? `n8n:${instance}:${execution}` : `n8n:${execution}`);
}

export function decisionsUrl(baseUrl: string): string {
  return `${trimTrailingSlashes(baseUrl)}/api/v1/decisions`;
}

export function buildDecisionBody(input: {
  agentDid: string;
  action: string;
  target: string;
  payload: string;
  payloadKind: string;
  requestId: string;
  sessionId?: string;
  extra?: Record<string, unknown>;
}): DecisionBody {
  const session = sessionText(input.sessionId);
  return {
    // Sent only when there is one, so an engine older than the field sees
    // the body it always saw.
    ...(session ? { session_id: session } : {}),
    agent_did: input.agentDid,
    action: input.action,
    target: input.target,
    payload: input.payload,
    payload_kind: input.payloadKind,
    surface: "n8n",
    request_id: input.requestId.slice(0, REQUEST_ID_MAX_LENGTH) || null,
    context: input.extra ?? {},
  };
}

/**
 * Fallback `request_id` for an item whose Request ID parameter is empty.
 *
 * The server keys its idempotency ledger on `(user_id, request_id)` for
 * 48 h. A repeat with the same inputs replays the earlier decision (engines
 * built before 21 September 2026 replay it whatever the payload), so a
 * second execution would get no decision of its own: the fallback must never
 * repeat across executions. It is derived from the
 * n8n execution id plus the item index; when no execution id is available
 * (older n8n, unit tests) a random UUID stands in. Always ≤ 64 chars.
 */
export function fallbackRequestId(
  executionId: string | undefined,
  index: number,
): string {
  const scope = executionId && executionId.trim() ? executionId.trim() : randomUUID();
  return `n8n-${scope}-${index}`.slice(0, REQUEST_ID_MAX_LENGTH);
}

export function routeHttpDecision(status: number, body: unknown): RoutedDecision {
  if (status === 200 && body && typeof body === "object") {
    const rec = body as Record<string, unknown>;
    const outcome = rec.outcome;
    if (outcome === "allow") return { branch: "allow", json: rec };
    if (outcome === "review") return { branch: "review", json: rec };
    if (outcome === "deny") return { branch: "deny", json: rec };
  }
  // A redirect is not followed (fetchWithTimeout), so a 3xx lands here. Its
  // body is the redirecting server's page, not an engine refusal: the reason
  // names the status instead.
  const detail =
    status >= 300 && status < 400
      ? `HTTP ${status}, a redirect, which is not followed: check the credential's Base URL`
      : body && typeof body === "object" && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : `HTTP ${status}`;
  return {
    branch: "deny",
    json: {
      outcome: "deny",
      reasons: [`${detail} — failing closed`],
      decision_id: "",
    },
  };
}
