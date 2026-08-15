/**
 * `postSdkEvent()` — fire-and-forget guard-event ingest
 * (`POST /api/events`). Mirrors the Python SDK: never throws — telemetry
 * must not break the caller.
 */

import { effectiveApiKey, effectiveBaseUrl } from "./config.js";
import type { FetchLike } from "./decide.js";

export interface SdkEventOptions {
  eventType: string;
  title?: string;
  level?: "info" | "warn" | "error";
  payload?: Record<string, unknown>;
  fetchImpl?: FetchLike;
}

export async function postSdkEvent(options: SdkEventOptions): Promise<boolean> {
  const apiKey = effectiveApiKey();
  if (!apiKey) return false;
  const fetchImpl: FetchLike =
    options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) return false;
  try {
    const resp = await fetchImpl(`${effectiveBaseUrl()}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Api-Key": apiKey },
      body: JSON.stringify({
        event_type: options.eventType,
        title: options.title ?? options.eventType,
        level: options.level ?? "info",
        payload: options.payload ?? {},
      }),
    });
    return resp.ok;
  } catch {
    return false;
  }
}
