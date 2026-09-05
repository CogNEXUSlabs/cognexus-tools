/** Envelope pattern B — OpenAI-shaped chat completions via CogNEXUS. */

import { trimTrailingSlashes } from "./base-url.js";

export function envelopeCompletionsUrl(baseUrl: string): string {
  return `${trimTrailingSlashes(baseUrl)}/api/v1/envelope/v1/chat/completions`;
}

export function envelopeFailedClosed(status: number): boolean {
  return status !== 200;
}

export function envelopeAuthHeader(apiKey: string): Record<string, string> {
  return {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };
}
