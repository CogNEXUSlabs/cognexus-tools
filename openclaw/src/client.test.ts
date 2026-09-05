import { afterEach, describe, expect, it } from "vitest";

import {
  DecisionError,
  postDecision,
  resolveApiKey,
  resolveBaseUrl,
  type FetchLike,
} from "./client.js";

const ALLOW = {
  outcome: "allow",
  decision_id: "01JZDECISIONXXXXXXXXXXXXXX",
  reasons: [],
};

function fakeFetch(
  status: number,
  body: unknown,
  capture?: { url?: string; init?: { headers: Record<string, string>; body: string } },
): FetchLike {
  return async (url, init) => {
    if (capture) {
      capture.url = url;
      capture.init = init;
    }
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

/** A 2xx whose body is not JSON — `json()` rejects the way undici's does. */
function htmlFetch(status: number): FetchLike {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => JSON.parse("<!doctype html>"),
    text: async () => "<!doctype html>",
  });
}

afterEach(() => {
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
});

describe("resolve", () => {
  it("prefers plugin config over env", () => {
    process.env.COGNEXUS_API_KEY = "env-key";
    process.env.COGNEXUS_API_BASE_URL = "https://env.example/";
    expect(resolveApiKey("plugin-key")).toBe("plugin-key");
    expect(resolveBaseUrl("https://plugin.example/")).toBe("https://plugin.example");
  });

  it("falls back to env then the hosted origin", () => {
    expect(resolveApiKey()).toBeUndefined();
    expect(resolveBaseUrl()).toBe("https://app.cognexuslabs.ai");
    process.env.COGNEXUS_API_KEY = "env-key";
    expect(resolveApiKey()).toBe("env-key");
  });

  it("strips every trailing slash without backtracking (§9.85)", () => {
    expect(resolveBaseUrl("https://engine.example.com///")).toBe("https://engine.example.com");
    process.env.COGNEXUS_API_BASE_URL = "https://env.example//";
    expect(resolveBaseUrl()).toBe("https://env.example");

    // Quadratic on the old /\/+$/ trim (sdk/typescript/src/config.ts already
    // scans); linear now.
    const started = performance.now();
    expect(resolveBaseUrl(`${"/".repeat(50_000)}x`)).toBe(`${"/".repeat(50_000)}x`);
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe("postDecision", () => {
  it("posts tool_call to the Decision API, not the envelope", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } =
      {};
    const result = await postDecision({
      apiKey: "cgnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "openclaw:tool:exec",
      payload: '{"tool":"exec","arguments":{}}',
      agentDid: "openclaw-gateway",
      requestId: "tc-1",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    expect(result.outcome).toBe("allow");
    expect(capture.url).toBe("https://engine.example.com/api/v1/decisions");
    expect(capture.url).not.toContain("envelope");
    expect(capture.init!.headers["X-Api-Key"]).toBe("cgnx_test");
    const sent = JSON.parse(capture.init!.body) as Record<string, unknown>;
    expect(sent.payload_kind).toBe("tool_call");
    expect(sent.surface).toBe("openclaw");
    expect(sent.request_id).toBe("tc-1");
    expect(JSON.stringify(sent)).not.toContain("eyJ");
  });

  it("wraps a non-JSON 2xx body in DecisionError (§9.85)", async () => {
    const err = await postDecision({
      apiKey: "cgnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "openclaw:tool:exec",
      payload: "{}",
      agentDid: "bot",
      fetchImpl: htmlFetch(200),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("non-JSON");
  });

  it("trims the base URL without backtracking (§9.85)", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } =
      {};
    const started = performance.now();
    await postDecision({
      apiKey: "cgnx_test",
      baseUrl: `${"/".repeat(50_000)}x/`,
      action: "exec",
      target: "openclaw:tool:exec",
      payload: "{}",
      agentDid: "bot",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(capture.url).toBe(`${"/".repeat(50_000)}x/api/v1/decisions`);
  });

  it("throws DecisionError on HTTP 503", async () => {
    await expect(
      postDecision({
        apiKey: "cgnx_test",
        baseUrl: "https://engine.example.com",
        action: "exec",
        target: "openclaw:tool:exec",
        payload: "{}",
        agentDid: "bot",
        fetchImpl: fakeFetch(503, { detail: "audit_unavailable" }),
      }),
    ).rejects.toBeInstanceOf(DecisionError);
  });
});
