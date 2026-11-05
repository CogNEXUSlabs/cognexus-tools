import { beforeEach, describe, expect, it } from "vitest";

import type { FetchLike } from "./client.js";
import { handleBeforeToolCall, resetAnnounceForTests, resetEnrollForTests } from "./gate.js";

type Captured = { url: string; init: Parameters<FetchLike>[1] };

function fakeFetch(status = 200, decision: unknown = { outcome: "allow", decision_id: "d1", reasons: [] }): {
  impl: FetchLike;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const impl: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => decision,
      text: async () => JSON.stringify(decision),
    };
  };
  return { impl, calls };
}

const pluginConfig = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  enroll: false,
  announce: false,
};

beforeEach(() => {
  resetAnnounceForTests();
  resetEnrollForTests();
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
});

describe("handleBeforeToolCall", () => {
  it("maps a hook event onto the decision and returns nothing on allow", async () => {
    const { impl, calls } = fakeFetch();
    const event = {
      toolName: "send_email",
      params: { to: "ops@example.com" },
      toolCallId: "call-1",
      runId: "run-9",
      context: { pluginConfig },
    };
    const ctx = { agentId: "research-bot" };

    const result = await handleBeforeToolCall(event, ctx, impl);

    expect(result).toBeUndefined();
    const decisions = calls.filter((call) => call.url.endsWith("/decisions"));
    expect(decisions).toHaveLength(1);
    const sent = JSON.parse(String(decisions[0].init?.body));
    expect(sent.action).toBe("send_email");
    expect(sent.agent_did).toBe("research-bot");
    expect(sent.target).toBe("grokbot:tool:send_email");
    expect(sent.request_id).toBe("call-1");
    expect(sent.surface).toBe("grokbot");
    expect(sent.payload).toContain("send_email");
    expect(JSON.stringify(sent)).not.toContain("cnx_test");
  });

  it("uses the context config and runId when the event does not carry them", async () => {
    const { impl, calls } = fakeFetch();
    const result = await handleBeforeToolCall(
      { toolName: "exec", params: { command: "ls" }, runId: "run-9" },
      { pluginConfig, agentId: "ops-bot" },
      impl,
    );

    expect(result).toBeUndefined();
    const sent = JSON.parse(String(calls.find((call) => call.url.endsWith("/decisions"))?.init?.body));
    expect(sent.agent_did).toBe("ops-bot");
    expect(sent.request_id).toBe("run-9");
    expect(sent.action).toBe("exec");
  });

  it("blocks deny and review with the decision reason", async () => {
    const denied = await handleBeforeToolCall(
      { toolName: "exec", params: { command: "ls" }, toolCallId: "call-2" },
      { pluginConfig },
      fakeFetch(200, { outcome: "deny", decision_id: "d2", reasons: ["policy"] }).impl,
    );
    expect(denied).toEqual({ block: true, blockReason: "REFUSED: policy (decision d2)" });

    const queued = await handleBeforeToolCall(
      { toolName: "exec", toolCallId: "call-3" },
      { pluginConfig },
      fakeFetch(200, { outcome: "review", decision_id: "d3", reasons: ["approval"] }).impl,
    );
    expect(queued?.block).toBe(true);
    expect(queued?.blockReason).toContain("QUEUED FOR REVIEW");
    expect(JSON.stringify(queued)).not.toContain("requireApproval");
  });

  it("fails closed when the hook event has no key, and does not call the engine", async () => {
    const { impl, calls } = fakeFetch();
    const blocked = await handleBeforeToolCall({ toolName: "exec" }, {}, impl);

    expect(blocked?.block).toBe(true);
    expect(blocked?.blockReason).toContain("No API key");
    expect(blocked?.blockReason).toContain("failing closed");
    expect(calls).toHaveLength(0);
  });
});
