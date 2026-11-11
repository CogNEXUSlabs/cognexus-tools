/**
 * `postDecisionResult()` — post the business result of a sealed decision
 * (`POST /api/v1/decisions/{decision_id}/result`). An allowed decision with a
 * posted result is an accountable outcome on the Tokens-to-Outcomes page.
 */

import { resolveCredentials, type ResolvedCredentials } from "./config.js";
import { DecisionError, failureKind } from "./errors.js";
import type { FetchLike } from "./decide.js";

export interface DecisionResult {
  decision_id: string;
  result_ref: string;
  /** Set by the server. A repeat of the same result returns the first time. */
  result_posted_at: string;
}

const DECISION_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * Post *resultRef* (an invoice number, a ticket id, a pull request URL; at
 * most 200 characters) as the result of *decisionId*. The server records the
 * time. Posting the same result again returns the original time; a different
 * one is refused with a 409. Only the id and the reference are sent.
 *
 * Throws `DecisionError` when the arguments would be refused, no API key is
 * configured, or the call fails.
 */
export async function postDecisionResult(
  decisionId: string,
  resultRef: string,
  options?: {
    /** Request timeout in milliseconds, reading the response included. Default 10000. */
    timeoutMs?: number;
    fetchImpl?: FetchLike;
  },
): Promise<DecisionResult> {
  const token = String(decisionId ?? "").trim().toUpperCase();
  if (!DECISION_ID.test(token)) {
    throw new DecisionError("Result not posted: decisionId must be 26 characters.");
  }
  const ref = String(resultRef ?? "").trim();
  // eslint-disable-next-line no-control-regex
  if (!ref || ref.length > 200 || /[\u0000-\u001f]/.test(ref)) {
    throw new DecisionError("Result not posted: resultRef is required.");
  }
  let creds: ResolvedCredentials;
  try {
    creds = resolveCredentials();
  } catch (err) {
    throw new DecisionError(`Result not posted: ${(err as Error).message}`);
  }
  const apiKey = creds.apiKey;
  if (!apiKey) {
    throw new DecisionError("Result not posted: no API key is configured.");
  }
  const fetchImpl: FetchLike =
    options?.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) {
    throw new DecisionError("No fetch implementation available (Node >= 18 required).");
  }
  // One deadline for the request and for reading the response, as in decide().
  const controller = new AbortController();
  const timer = setTimeout(
    () =>
      controller.abort(
        new DOMException("The operation was aborted due to timeout", "TimeoutError"),
      ),
    options?.timeoutMs ?? 10_000,
  );
  try {
    let resp: Awaited<ReturnType<FetchLike>>;
    try {
      resp = await fetchImpl(`${creds.baseUrl}/api/v1/decisions/${token}/result`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Api-Key": apiKey },
        body: JSON.stringify({ result_ref: ref }),
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (err) {
      // Named by its kind and where the base URL came from, as in decide().
      throw new DecisionError(
        `Decision API unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${creds.baseSource})`,
      );
    }
    if (resp.status >= 300 && resp.status < 400) {
      // Not followed (see FetchLike); its body is left unread.
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
      const detailText =
        typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : "";
      throw new DecisionError(
        `Decision API returned HTTP ${resp.status}${detailText ? `: ${detailText}` : ""}`,
        { status: resp.status, detail },
      );
    }
    try {
      return (await resp.json()) as DecisionResult;
    } catch (err) {
      const kind = failureKind(err, controller.signal);
      throw new DecisionError(
        kind === "SyntaxError"
          ? `Decision API returned HTTP ${resp.status} with a non-JSON body`
          : `Decision API returned HTTP ${resp.status} but its body could not be read: ${kind}`,
        { status: resp.status },
      );
    }
  } finally {
    clearTimeout(timer);
  }
}
