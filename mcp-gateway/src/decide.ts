/**
 * One Decision API call. A missing key, a transport failure, a redirect, or
 * any outcome other than allow is a block. This client has no offline path:
 * it never returns a synthetic allow.
 */

import { randomUUID } from "node:crypto";

import { VERSION } from "./version.js";

const DEFAULT_BASE = "https://app.cognexuslabs.ai";
const TIMEOUT_MS = 10_000;

export interface DecisionRequest {
  agentId: string;
  action: string;
  target: string;
  payload: string;
  requestId?: string;
  /** `session_id`: the gateway run this tool call belongs to. Left out when empty. */
  sessionId?: string;
}

export interface Decision {
  outcome: string;
  decisionId: string;
  reasons: string[];
}

export class DecisionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecisionError";
  }
}

function failureKind(err: unknown): string {
  if (err && typeof err === "object") {
    const named = err as { name?: string; code?: string };
    const name = named.name && named.name !== "Error" ? named.name : "";
    const code = named.code ?? "";
    const kind = [name, code].filter(Boolean).join(" ");
    if (kind) return kind;
  }
  return "Error";
}

function reasonsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

export async function decide(request: DecisionRequest, env: NodeJS.ProcessEnv = process.env): Promise<Decision> {
  const key = env.COGNEXUS_API_KEY ?? "";
  if (key.trim() === "") {
    throw new DecisionError("No API key configured. Set COGNEXUS_API_KEY.");
  }
  const base = (env.COGNEXUS_API_BASE_URL ?? DEFAULT_BASE).replace(/\/+$/, "");
  const url = `${base}/api/v1/decisions`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
      },
      body: JSON.stringify({
        agent_did: request.agentId,
        action: request.action,
        target: request.target,
        payload: request.payload,
        payload_kind: "tool_call",
        surface: "mcp",
        request_id: request.requestId ?? randomUUID(),
        ...(request.sessionId ? { session_id: request.sessionId } : {}),
        product: `artzain-mcp-gateway@${VERSION}`,
      }),
    });
  } catch (err) {
    throw new DecisionError(`decision unavailable (${failureKind(err)}). Failing closed.`);
  } finally {
    clearTimeout(timer);
  }
  if (response.status >= 300 && response.status < 400) {
    throw new DecisionError("decision unavailable (redirect). Failing closed.");
  }
  if (!response.ok) {
    throw new DecisionError(`decision unavailable (HTTP ${response.status}). Failing closed.`);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new DecisionError("decision unavailable (bad response). Failing closed.");
  }
  if (!body || typeof body !== "object") {
    throw new DecisionError("decision unavailable (bad response). Failing closed.");
  }
  const row = body as { outcome?: unknown; decision_id?: unknown; reasons?: unknown };
  if (typeof row.outcome !== "string" || row.outcome === "") {
    throw new DecisionError("decision unavailable (no outcome). Failing closed.");
  }
  return {
    outcome: row.outcome,
    decisionId: typeof row.decision_id === "string" ? row.decision_id : "",
    reasons: reasonsOf(row.reasons),
  };
}
