/**
 * Fail-closed routing for the CogNEXUS Decision node.
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
  context: Record<string, unknown>;
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
  extra?: Record<string, unknown>;
}): DecisionBody {
  return {
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
 * 48 h and replays the earlier decision without comparing the payload, so
 * the fallback must never repeat across executions. It is derived from the
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
  const detail =
    body && typeof body === "object" && "detail" in body
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
