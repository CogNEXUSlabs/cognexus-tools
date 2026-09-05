/** `fetchApiKeyIdentity()` — validate the configured key (`GET /api/api-keys/me`). */

import { effectiveApiKey, effectiveBaseUrl } from "./config.js";
import { DecisionError } from "./errors.js";
import type { FetchLike } from "./decide.js";

export interface ApiKeyIdentity {
  user_id: number;
  email?: string;
  key_prefix?: string;
  [extra: string]: unknown;
}

export async function fetchApiKeyIdentity(options?: {
  /** Request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}): Promise<ApiKeyIdentity> {
  const apiKey = effectiveApiKey();
  if (!apiKey) {
    throw new DecisionError("No API key configured.");
  }
  const fetchImpl: FetchLike =
    options?.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options?.timeoutMs ?? 10_000);
  let resp: Awaited<ReturnType<FetchLike>>;
  try {
    resp = await fetchImpl(`${effectiveBaseUrl()}/api/api-keys/me`, {
      method: "GET",
      headers: { "X-Api-Key": apiKey },
      body: undefined as unknown as string,
      signal: controller.signal,
    });
  } catch (err) {
    throw new DecisionError(`Key validation unreachable: ${(err as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) {
    throw new DecisionError(`Key validation failed (HTTP ${resp.status}).`, {
      status: resp.status,
    });
  }
  return (await resp.json()) as ApiKeyIdentity;
}
