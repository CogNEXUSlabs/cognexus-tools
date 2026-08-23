import { describe, expect, it } from "vitest";

import { handleBeforeToolCall } from "./gate.js";
import type { FetchLike } from "./client.js";

function fakeFetch(status: number, body: unknown): FetchLike {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

const EVENT = { toolName: "exec", params: { command: "ls" }, toolCallId: "tc-9" };

describe("handleBeforeToolCall", () => {
  it("returns undefined on allow so the tool runs", async () => {
    const result = await handleBeforeToolCall(
      EVENT,
      { agentId: "bot", pluginConfig: { apiKey: "k", baseUrl: "https://e.example" } },
      fakeFetch(200, { outcome: "allow", decision_id: "d1", reasons: [] }),
    );
    expect(result).toBeUndefined();
  });

  it("blocks deny and review, and never asks OpenClaw to approve", async () => {
    const denied = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: "k", baseUrl: "https://e.example" } },
      fakeFetch(200, { outcome: "deny", decision_id: "d2", reasons: ["policy"] }),
    );
    expect(denied).toEqual({
      block: true,
      blockReason: "REFUSED: policy (decision d2)",
    });

    const queued = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: "k", baseUrl: "https://e.example" } },
      fakeFetch(200, { outcome: "review", decision_id: "d3", reasons: ["pii"] }),
    );
    expect(queued?.block).toBe(true);
    expect(queued?.blockReason).toContain("QUEUED FOR REVIEW");
    expect(JSON.stringify(queued)).not.toContain("requireApproval");
  });

  it("fails closed on 503 and on a missing key", async () => {
    const refused = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: "k", baseUrl: "https://e.example" } },
      fakeFetch(503, { detail: "audit_unavailable" }),
    );
    expect(refused?.block).toBe(true);
    expect(refused?.blockReason).toContain("failing closed");

    const missing = await handleBeforeToolCall(EVENT, {});
    expect(missing?.block).toBe(true);
    expect(missing?.blockReason).toContain("No API key");
  });
});
