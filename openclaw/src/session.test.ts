/**
 * The gate sends the session a tool call belongs to, with no setup by the
 * operator: the engine signs `session_id` and `tool_call_id` into the
 * decision's record, and a decision trace groups a run's decisions by them.
 * The session is the host's own (its session key, else the run); the gate
 * names no parent decision, since order within a session is already given
 * by the session and the seal time.
 */
import { describe, expect, it } from "vitest";

import { handleBeforeToolCall } from "./gate.js";
import type { FetchLike } from "./client.js";

const CONFIG = { apiKey: "k", baseUrl: "https://e.example", announce: false };

/** Records the body of each Decision API request; other requests are answered and ignored. */
function recording(seen: Record<string, unknown>[]): FetchLike {
  return async (url, init) => {
    if (String(url).endsWith("/api/v1/decisions")) seen.push(JSON.parse(init.body ?? "{}"));
    const body = { outcome: "allow", decision_id: "d1", reasons: [] };
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
  };
}

async function decided(event: Record<string, unknown>, ctx: Record<string, unknown> = {}) {
  const seen: Record<string, unknown>[] = [];
  const result = await handleBeforeToolCall(
    { toolName: "exec", params: { command: "ls" }, ...event } as Parameters<typeof handleBeforeToolCall>[0],
    { pluginConfig: CONFIG, ...ctx } as Parameters<typeof handleBeforeToolCall>[1],
    recording(seen),
  );
  expect(seen).toHaveLength(1);
  return { body: seen[0], result };
}

describe("the gate's lineage", () => {
  it("sends the host's session key as the session, and the tool call's id", async () => {
    const { body } = await decided(
      { toolCallId: "tc-9", runId: "run-3" },
      { agentId: "bot", sessionKey: "agent:main:whatsapp:+15550100" },
    );
    expect(body.session_id).toBe("agent:main:whatsapp:+15550100");
    expect(body.tool_call_id).toBe("tc-9");
    // The idempotency key is unchanged.
    expect(body.request_id).toBe("tc-9");
  });

  it("falls back to the session id, then to the run", async () => {
    expect((await decided({ runId: "run-3" }, { sessionId: "sess-1" })).body.session_id).toBe("sess-1");
    expect((await decided({ toolCallId: "tc-9", runId: "run-3" })).body.session_id).toBe("run-3");
  });

  it("sends neither field when the host gives neither", async () => {
    const { body } = await decided({});
    expect(body).not.toHaveProperty("session_id");
    expect(body).not.toHaveProperty("tool_call_id");
    // An engine older than the fields sees the body it always saw.
    expect(Object.keys(body).sort()).toEqual(
      ["action", "agent_did", "context", "payload", "payload_kind", "request_id", "surface", "target"],
    );
  });

  it("names no parent decision", async () => {
    const first = await decided({ toolCallId: "tc-1", runId: "run-3" });
    const second = await decided({ toolCallId: "tc-2", runId: "run-3" });
    expect(first.body).not.toHaveProperty("parent_decision_ids");
    expect(second.body).not.toHaveProperty("parent_decision_ids");
    expect(second.body.session_id).toBe(first.body.session_id);
  });

  it("trims and cuts an id to the width the server keeps", async () => {
    const { body } = await decided({ toolCallId: ` ${"t".repeat(200)} ` }, { sessionKey: ` ${"s".repeat(200)} ` });
    expect(body.session_id).toBe("s".repeat(128));
    expect(body.tool_call_id).toBe("t".repeat(128));
  });

  it("leaves out an id the server would refuse, and still decides", async () => {
    // A lineage id is not worth a blocked tool call: the server answers a
    // control character with a 422, which the gate would turn into a block.
    const { body, result } = await decided({ toolCallId: "tc\n9", runId: "run-3" }, { sessionKey: "bad\u0007key" });
    expect(result).toBeUndefined();
    expect(body).not.toHaveProperty("tool_call_id");
    // The next source is used when the first cannot be sent.
    expect(body.session_id).toBe("run-3");
  });

  it("ignores a session that is not a string", async () => {
    const { body } = await decided({}, { sessionKey: { key: "x" }, sessionId: 7 });
    expect(body).not.toHaveProperty("session_id");
  });
});
