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
  fetchImpl?: FetchLike;
}): Promise<ApiKeyIdentity> {
  const apiKey = effectiveApiKey();
  if (!apiKey) {
    throw new DecisionError("No API key configured.");
  }
  const fetchImpl: FetchLike =
    options?.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const resp = await fetchImpl(`${effectiveBaseUrl()}/api/api-keys/me`, {
    method: "GET",
    headers: { "X-Api-Key": apiKey },
    body: undefined as unknown as string,
  });
  if (!resp.ok) {
    throw new DecisionError(`Key validation failed (HTTP ${resp.status}).`, {
      status: resp.status,
    });
  }
  return (await resp.json()) as ApiKeyIdentity;
}
