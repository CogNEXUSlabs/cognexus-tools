/** Request timeout shared by both nodes. */

export const DEFAULT_TIMEOUT_MS = 10_000;

/** Coerce the node's `timeoutMs` parameter; anything non-positive or non-numeric falls back to the default. */
export function resolveTimeoutMs(raw: unknown): number {
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

/**
 * Fetch `url` with `init` and hand the response to `read`, aborting after
 * `timeoutMs`. The deadline covers `read` too: a server that sends its
 * headers and then stalls mid-body fails the call instead of hanging it, so
 * read the body inside `read`, not after this returns. Callers handle the
 * rejection.
 */
export async function fetchWithTimeout<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  read: (resp: Response) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(
    () =>
      controller.abort(
        new DOMException("The operation was aborted due to timeout", "TimeoutError"),
      ),
    timeoutMs,
  );
  try {
    const resp = await fetch(url, { ...init, signal: controller.signal });
    return await read(resp);
  } finally {
    clearTimeout(timer);
  }
}
