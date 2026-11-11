/**
 * `postSdkEvent()` — fire-and-forget guard-event ingest
 * (`POST /api/events`). Mirrors the Python SDK: never throws — telemetry
 * must not break the caller. `postGenerationOutcome()` is the event a model
 * call's token counts travel in.
 */

import { randomUUID } from "node:crypto";

import { resolveCredentials, type ResolvedCredentials } from "./config.js";
import type { FetchLike } from "./decide.js";

export interface SdkEventOptions {
  eventType: string;
  title?: string;
  level?: "info" | "success" | "warn" | "error";
  payload?: Record<string, unknown>;
  /**
   * Which client sent the event. Left out when not given, and the server
   * then records its default.
   */
  source?: string;
  /**
   * Prompt and completion token counts for this event. They go into the
   * payload as `tokens_in` and `tokens_out`, over any the payload holds, and
   * count on the Tokens-to-Outcomes page.
   */
  tokensIn?: number;
  tokensOut?: number;
  /** Request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

/** A token count as sent: a whole number from zero up, or nothing. */
function tokenCount(value: number | undefined): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.max(0, Math.trunc(value));
}

const DECISION_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * The correlation id an event carries. A decision id (26 characters, as
 * `decide()` returns it) is sent in upper case, the form the server stores,
 * so the event's token counts land on that decision. Any other id is sent in
 * lower case, and an empty one becomes a new id.
 */
function correlationId(requestId?: string): string {
  const given = (requestId ?? "").trim();
  if (!given) return randomUUID().replace(/-/g, "");
  const upper = given.toUpperCase();
  return DECISION_ID.test(upper) ? upper : given.toLowerCase();
}

export async function postSdkEvent(options: SdkEventOptions): Promise<boolean> {
  let creds: ResolvedCredentials;
  try {
    creds = resolveCredentials();
  } catch {
    return false; // the host that is set did not issue the key: send nothing
  }
  const apiKey = creds.apiKey;
  if (!apiKey) return false;
  const fetchImpl: FetchLike =
    options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) return false;
  const payload: Record<string, unknown> = { ...(options.payload ?? {}) };
  const tokensIn = tokenCount(options.tokensIn);
  const tokensOut = tokenCount(options.tokensOut);
  if (tokensIn !== undefined) payload.tokens_in = tokensIn;
  if (tokensOut !== undefined) payload.tokens_out = tokensOut;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  try {
    const resp = await fetchImpl(`${creds.baseUrl}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Api-Key": apiKey },
      body: JSON.stringify({
        event_type: options.eventType,
        title: options.title ?? options.eventType,
        level: options.level ?? "info",
        payload,
        ...(options.source ? { source: options.source } : {}),
      }),
      signal: controller.signal,
      redirect: "manual",
    });
    // A refusal's body (a redirect's included) is not read: end the request,
    // or a large one holds the connection until garbage collection.
    if (!resp.ok) controller.abort();
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export interface GenerationOutcomeOptions {
  /** `"passed"` or `"failed"`; another value is sent as given. */
  outcome: string;
  /** Why, in a sentence: blocked by a guard, answered, timed out. */
  reason: string;
  /** Model or deployment label. */
  modelId?: string;
  /**
   * Correlation id. Pass the `decision_id` that `decide()` returned to count
   * these tokens on that decision in Tokens-to-Outcomes. A new id when omitted.
   */
  requestId?: string;
  tokensIn?: number;
  tokensOut?: number;
  /** Wall time of the model call in milliseconds. */
  latencyMs?: number;
  /** More fields for the payload. */
  extra?: Record<string, unknown>;
  /** Request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

/**
 * Report one model call: whether it passed, and what it cost in tokens.
 * Like `postSdkEvent()`, it never throws and resolves to whether the event
 * was accepted. No prompt text is sent.
 */
export async function postGenerationOutcome(options: GenerationOutcomeOptions): Promise<boolean> {
  try {
    const outcome = String(options.outcome ?? "").trim().toLowerCase();
    const payload: Record<string, unknown> = {
      outcome: outcome || options.outcome,
      reason: String(options.reason ?? "").trim().slice(0, 2000),
      request_id: correlationId(options.requestId),
      model_id: options.modelId ?? null,
    };
    if (typeof options.latencyMs === "number" && Number.isFinite(options.latencyMs)) {
      payload.latency_ms = Math.max(0, options.latencyMs);
    }
    Object.assign(payload, options.extra ?? {});
    return await postSdkEvent({
      eventType: "generation",
      title:
        outcome === "passed"
          ? "Generation · PASSED"
          : outcome === "failed"
            ? "Generation · FAILED"
            : `Generation · ${options.outcome || "event"}`,
      level: outcome === "passed" ? "success" : outcome === "failed" ? "error" : "info",
      source: "npm_sdk",
      payload,
      tokensIn: options.tokensIn,
      tokensOut: options.tokensOut,
      timeoutMs: options.timeoutMs,
      fetchImpl: options.fetchImpl,
    });
  } catch {
    return false;
  }
}
