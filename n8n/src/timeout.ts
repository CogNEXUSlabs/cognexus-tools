/** Request timeout shared by both nodes. */

export const DEFAULT_TIMEOUT_MS = 10_000;

/** Coerce the node's `timeoutMs` parameter; anything non-positive or non-numeric falls back to the default. */
export function resolveTimeoutMs(raw: unknown): number {
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

/** Fetch `url` with `init`, aborting after `timeoutMs`. Callers handle the rejection. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
