import { describe, expect, it } from "vitest";

import {
  envelopeAuthHeader,
  envelopeCompletionsUrl,
  envelopeFailedClosed,
} from "./envelope.js";

describe("envelopeCompletionsUrl", () => {
  it("is the envelope chat path, not the Decision API", () => {
    expect(envelopeCompletionsUrl("https://app.cognexuslabs.ai")).toBe(
      "https://app.cognexuslabs.ai/api/v1/envelope/v1/chat/completions",
    );
    expect(envelopeCompletionsUrl("https://app.cognexuslabs.ai")).not.toContain(
      "/api/v1/decisions",
    );
  });

  it("strips every trailing slash without backtracking (§9.85)", () => {
    expect(envelopeCompletionsUrl("https://engine.example.com///")).toBe(
      "https://engine.example.com/api/v1/envelope/v1/chat/completions",
    );
    // Quadratic on the old /\/+$/ trim; linear now.
    const started = performance.now();
    expect(envelopeCompletionsUrl(`${"/".repeat(50_000)}x`)).toBe(
      `${"/".repeat(50_000)}x/api/v1/envelope/v1/chat/completions`,
    );
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe("envelopeFailedClosed", () => {
  it("treats 403 and 503 as failures", () => {
    expect(envelopeFailedClosed(200)).toBe(false);
    expect(envelopeFailedClosed(403)).toBe(true);
    expect(envelopeFailedClosed(503)).toBe(true);
  });
});

describe("envelopeAuthHeader", () => {
  it("uses a Bearer envelope key, not a JWT cookie", () => {
    const h = envelopeAuthHeader("cnxe_test");
    expect(h.Authorization).toBe("Bearer cnxe_test");
    expect(JSON.stringify(h)).not.toMatch(/eyJ/);
  });
});
