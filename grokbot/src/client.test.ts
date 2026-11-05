import { afterEach, describe, expect, it } from "vitest";

import {
  DecisionError,
  getReviewStatus,
  postDecision,
  resolveApiKey,
  resolveBaseUrl,
  type FetchLike,
} from "./client.js";
import { gateToolCall } from "./gate.js";
import { currentCliVersion } from "./state.js";

const ALLOW = {
  outcome: "allow",
  decision_id: "01JZDECISIONXXXXXXXXXXXXXX",
  audit_block_id: "01JZBLOCKXXXXXXXXXXXXXXXXX",
  contributing_agents: [
    { name: "prompt-injection", verdict: "allow", severity: "none", score: 0.0, findings: [], error: null },
    { name: "tool-call-contract", verdict: "allow", severity: "none", score: 0.0, findings: [], error: null },
  ],
  policy_bundle_version: "builtin:v0",
  resolution_policy: "builtin/strict-v0",
  latency_ms: 12,
  reasons: [],
  warnings: [],
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

afterEach(() => {
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
});

describe("postDecision", () => {
  it("posts tool_call to the Decision API, not the envelope", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } =
      {};
    const result = await postDecision({
      apiKey: "cnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "grokbot:tool:exec",
      payload: '{"tool":"exec","arguments":{}}',
      agentDid: "grokbot-agent",
      requestId: "tc-1",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    expect(result.outcome).toBe("allow");
    expect(capture.url).toBe("https://engine.example.com/api/v1/decisions");
    expect(capture.url).not.toContain("envelope");
    expect(capture.init!.headers["X-Api-Key"]).toBe("cnx_test");
    const sent = JSON.parse(capture.init!.body) as Record<string, unknown>;
    expect(sent.payload_kind).toBe("tool_call");
    expect(sent.surface).toBe("grokbot");
    expect(sent.product).toBe(`grokbot-artzain@${currentCliVersion()}`);
    expect(sent.context).toEqual({});
    expect(JSON.stringify(sent)).not.toContain("eyJ");
  });

  it("puts model_id, workload_id, session, parent and on_behalf_of on the request", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } = {};
    await postDecision({
      apiKey: "cnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "grokbot:tool:exec",
      payload: "{}",
      agentDid: "bot",
      requestId: "tc-flags",
      modelId: "model-a",
      workloadId: "inbox",
      session: "sess-1",
      parent: "01PARENT",
      onBehalfOf: "alice",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    const sent = JSON.parse(capture.init!.body) as Record<string, unknown>;
    expect(sent.model_id).toBe("model-a");
    expect(sent.workload_id).toBe("inbox");
    expect(sent.context).toEqual({ session: "sess-1", parent: "01PARENT", on_behalf_of: "alice" });
  });

  it("keeps unknown context keys when session, parent and on_behalf_of are set", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } = {};
    await postDecision({
      apiKey: "cnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "grokbot:tool:exec",
      payload: "{}",
      agentDid: "bot",
      context: { trace: "keep-me", n: 1, tags: ["a"] },
      session: "sess-1",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    const sent = JSON.parse(capture.init!.body) as { context: Record<string, unknown> };
    expect(sent.context).toEqual({ trace: "keep-me", n: 1, tags: ["a"], session: "sess-1" });
  });

  it("keeps unknown context keys through the gate", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } = {};
    const result = await gateToolCall(
      { apiKey: "cnx_test", baseUrl: "https://engine.example.com", enroll: false, announce: false },
      {
        toolName: "exec",
        context: { trace: "keep-me" },
        session: "sess-1",
        parent: "01PARENT",
        onBehalfOf: "alice",
        modelId: "model-a",
        workloadId: "inbox",
      },
      fakeFetch(200, ALLOW, capture),
    );
    expect(result.allow).toBe(true);
    const sent = JSON.parse(capture.init!.body) as Record<string, unknown>;
    expect(sent.model_id).toBe("model-a");
    expect(sent.workload_id).toBe("inbox");
    expect(sent.context).toEqual({
      trace: "keep-me",
      session: "sess-1",
      parent: "01PARENT",
      on_behalf_of: "alice",
    });
  });

  it("sends cites_review in context when asked", async () => {
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } = {};
    await postDecision({
      apiKey: "cnx_test",
      baseUrl: "https://engine.example.com",
      action: "exec",
      target: "grokbot:tool:exec",
      payload: "{}",
      agentDid: "grokbot-agent",
      citesReview: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    const sent = JSON.parse(capture.init!.body) as { context?: Record<string, string> };
    expect(sent.context).toEqual({ cites_review: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
  });

  it("reads a review and does not treat a failure as approved", async () => {
    const seen: string[] = [];
    const ok = await getReviewStatus({
      apiKey: "cnx_test",
      baseUrl: "https://engine.example.com",
      decisionId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      fetchImpl: async (url, init) => {
        seen.push(`${init.method} ${url}`);
        return {
          ok: true,
          status: 200,
          json: async () => ({ decision_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", status: "approved", notes: "secret" }),
          text: async () => "",
        };
      },
    });
    expect(ok).toEqual({ decision_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", status: "approved" });
    expect(seen[0]).toBe(
      "GET https://engine.example.com/api/v1/decisions/01ARZ3NDEKTSV4RRFFQ69G5FAV/review",
    );
    await expect(
      getReviewStatus({
        apiKey: "cnx_test",
        baseUrl: "https://engine.example.com",
        decisionId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        fetchImpl: async () => ({
          ok: false,
          status: 404,
          json: async () => ({ detail: "missing" }),
          text: async () => "",
        }),
      }),
    ).rejects.toBeInstanceOf(DecisionError);
  });

  it("throws DecisionError on HTTP 503", async () => {
    await expect(
      postDecision({
        apiKey: "cnx_test",
        baseUrl: "https://engine.example.com",
        action: "exec",
        target: "grokbot:tool:exec",
        payload: "{}",
        agentDid: "bot",
        fetchImpl: fakeFetch(503, { detail: "audit_unavailable" }),
      }),
    ).rejects.toBeInstanceOf(DecisionError);
  });

  it("falls back to env then the hosted origin", () => {
    expect(resolveApiKey()).toBeUndefined();
    expect(resolveBaseUrl()).toBe("https://app.cognexuslabs.ai");
    process.env.COGNEXUS_API_KEY = "env-key";
    expect(resolveApiKey()).toBe("env-key");
  });

  it("MYAPP_API_KEY alone yields no key plus the warning", () => {
    const lines: string[] = [];
    const write = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    try {
      process.env.COGNEXUS_API_KEY = "env-key";
      process.env.MYAPP_API_KEY = "legacy-only-key";
      expect(resolveApiKey()).toBe("env-key");
      expect(lines).toEqual([]);

      delete process.env.COGNEXUS_API_KEY;
      expect(resolveApiKey()).toBeUndefined();
    } finally {
      process.stderr.write = write;
    }
    const warned = lines.join("");
    expect(warned).toContain("no key");
    expect(warned).toContain("MYAPP_API_KEY");
    expect(warned).not.toContain("legacy-only-key");
    expect(warned).not.toContain("env-key");
  });
});
