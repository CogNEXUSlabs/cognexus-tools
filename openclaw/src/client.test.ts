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
    };
  };
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
