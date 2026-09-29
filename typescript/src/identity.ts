/** `fetchApiKeyIdentity()` — validate the configured key (`GET /api/api-keys/me`). */

import { resolveCredentials, type ResolvedCredentials } from "./config.js";
import { DecisionError, failureKind } from "./errors.js";
import type { FetchLike } from "./decide.js";

export interface ApiKeyIdentity {
  user_id: number;
  email?: string;
  key_prefix?: string;
  [extra: string]: unknown;
}

export async function fetchApiKeyIdentity(options?: {
  /** Request timeout in milliseconds, reading the response included. Default 10000. */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}): Promise<ApiKeyIdentity> {
  let creds: ResolvedCredentials;
  try {
    creds = resolveCredentials();
  } catch (err) {
    throw new DecisionError(`Key validation not sent: ${(err as Error).message}`);
  }
  const apiKey = creds.apiKey;
  if (!apiKey) {
    throw new DecisionError("No API key configured.");
  }
  const fetchImpl: FetchLike =
    options?.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
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
      resp = await fetchImpl(`${creds.baseUrl}/api/api-keys/me`, {
        method: "GET",
        headers: { "X-Api-Key": apiKey },
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (err) {
      // Named by its kind and where the base URL came from, as in decide().
      throw new DecisionError(
        `Key validation unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${creds.baseSource})`,
      );
    }
    // A redirect is not followed (see FetchLike). An http:// base URL that
    // the server redirects to https:// ends here, so the message names the
    // redirect rather than suggest the key is bad. Its body is left unread,
    // so the request is ended to release the connection.
    if (resp.status >= 300 && resp.status < 400) {
      controller.abort();
      throw new DecisionError(
        `Key validation returned HTTP ${resp.status}, a redirect, which is not followed: ` +
          "check the base URL",
        { status: resp.status },
      );
    }
    if (!resp.ok) {
      throw new DecisionError(`Key validation failed (HTTP ${resp.status}).`, {
        status: resp.status,
      });
    }
    let parsed: unknown;
    try {
      parsed = await resp.json();
    } catch (err) {
      const kind = failureKind(err, controller.signal);
      throw new DecisionError(
        kind === "SyntaxError"
          ? `Key validation returned HTTP ${resp.status} with a non-JSON body`
          : `Key validation returned HTTP ${resp.status} but its body could not be read: ${kind}`,
        { status: resp.status },
      );
    }
    return parsed as ApiKeyIdentity;
  } finally {
    clearTimeout(timer);
  }
}
