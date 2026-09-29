/** Request timeout shared by both nodes. */

import { failureKind } from "./failure.js";

export const DEFAULT_TIMEOUT_MS = 10_000;

/** What a failed request is reported as: `<what> unreachable: … (base URL from <baseSource>)`. */
export interface RequestLabel {
  /** The service, e.g. `"Decision API"`. */
  what: string;
  /** Where the base URL came from: a label, never the value. */
  baseSource: string;
}

/** Coerce the node's `timeoutMs` parameter; anything non-positive or non-numeric falls back to the default. */
export function resolveTimeoutMs(raw: unknown): number {
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

/**
 * Fetch `url` with `init` and read the whole body as text, aborting after
 * `timeoutMs`. The deadline covers the body too: a server that sends its
 * headers and then stalls mid-body fails the call instead of hanging it.
 * The body is read once, here, and the caller decides what the status and
 * the text mean. Callers handle the rejection.
 *
 * A redirect is not followed. fetch would send the request again to wherever
 * `Location` points: the Decision node's `X-Api-Key` with it, even to another
 * host, and on 307 and 308 the body too. A 3xx comes back as the status it
 * is, with its body, the redirecting server's page, left unread (`text` is
 * empty).
 *
 * A request that fails, or a body that cannot be read, is reported by the
 * failure's kind (see `failureKind`), with `label.baseSource` when no answer
 * came back, and by an error of this function's own: fetch's error can quote
 * the API key, its cause can name the host or hold the socket, and the nodes
 * attach the error they catch to the item.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  label: RequestLabel,
): Promise<{ status: number; text: string }> {
  const controller = new AbortController();
  const timer = setTimeout(
    () =>
      controller.abort(
        new DOMException("The operation was aborted due to timeout", "TimeoutError"),
      ),
    timeoutMs,
  );
  try {
    let resp: Response;
    try {
      resp = await fetch(url, { ...init, redirect: "manual", signal: controller.signal });
    } catch (err) {
      throw new Error(
        `${label.what} unreachable: ${failureKind(err, controller.signal)} ` +
          `(base URL from ${label.baseSource})`,
      );
    }
    if (resp.status >= 300 && resp.status < 400) {
      return { status: resp.status, text: "" };
    }
    try {
      return { status: resp.status, text: await resp.text() };
    } catch (err) {
      throw new Error(
        `${label.what} returned HTTP ${resp.status} but its body could not be read: ` +
          failureKind(err, controller.signal),
      );
    }
  } finally {
    clearTimeout(timer);
    // End the request whatever happened. A body left unread (a redirect's)
    // would hold the connection until garbage collection; one already read
    // is unaffected.
    controller.abort();
  }
}
