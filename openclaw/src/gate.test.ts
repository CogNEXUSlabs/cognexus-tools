import { describe, expect, it } from "vitest";

import { handleBeforeToolCall } from "./gate.js";
import type { FetchLike } from "./client.js";

function fakeFetch(status: number, body: unknown): FetchLike {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
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

  it("fails closed on a non-JSON 2xx, through the DecisionError branch (§9.85)", async () => {
    const html = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: "k", baseUrl: "https://e.example" } },
      htmlFetch(200),
    );
    expect(html?.block).toBe(true);
    expect(html?.blockReason).toContain("failing closed");
    expect(html?.blockReason).toContain("HTTP 200");
    expect(html?.blockReason).toContain("non-JSON");
  });
});
