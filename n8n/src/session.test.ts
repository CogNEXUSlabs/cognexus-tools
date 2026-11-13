/**
 * The Decision node sends the session its decisions belong to, with no setup
 * by the workflow's author: the engine signs `session_id` into the decision's
 * record, and a decision trace groups an execution's decisions by it. The
 * session is the execution (with the instance, where n8n names it), unless
 * the Session ID parameter gives another. The node names no parent decision.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

// n8n-workflow is an optional peer dependency that is not installed in this
// package's test environment; stub the two runtime exports the nodes use.
vi.mock("n8n-workflow", () => ({
  NodeConnectionTypes: { Main: "main" },
  NodeOperationError: class NodeOperationError extends Error {
    constructor(_node: unknown, error: unknown) {
      super(error instanceof Error ? error.message : String(error));
    }
  },
}));

import type { IExecuteFunctions, INodeType } from "n8n-workflow";

import { buildDecisionBody, executionSessionId } from "./decision.js";
import { ArtzainDecision } from "./nodes/ArtzainDecision/ArtzainDecision.node.js";

describe("executionSessionId", () => {
  it("names the instance and the execution", () => {
    expect(executionSessionId("inst-A", "4711")).toBe("n8n:inst-A:4711");
  });

  it("names the execution alone when n8n gives no instance", () => {
    expect(executionSessionId(undefined, "4711")).toBe("n8n:4711");
    expect(executionSessionId("  ", " 4711 ")).toBe("n8n:4711");
  });

  it("is empty without an execution: a random id would join nothing", () => {
    expect(executionSessionId("inst-A", undefined)).toBe("");
    expect(executionSessionId("inst-A", "  ")).toBe("");
  });

  it("is empty when the execution id could not be sent, and never longer than the server keeps", () => {
    expect(executionSessionId("inst-A", "47\n11")).toBe("");
    expect(executionSessionId("bad\u0007inst", "4711")).toBe("n8n:4711");
    expect(executionSessionId("i".repeat(300), "4711").length).toBeLessThanOrEqual(128);
    expect(executionSessionId("i".repeat(300), "4711").endsWith(":4711")).toBe(true);
  });
});

describe("buildDecisionBody: session", () => {
  const base = {
    agentDid: "n8n-order-bot", action: "a", target: "t", payload: "{}", payloadKind: "tool_call", requestId: "r-1",
  };

  it("sends the session as session_id", () => {
    expect(buildDecisionBody({ ...base, sessionId: " n8n:inst-A:4711 " }).session_id).toBe("n8n:inst-A:4711");
  });

  it("leaves it out when empty, so an older engine sees the body it always saw", () => {
    for (const sessionId of [undefined, "", "   "]) {
      const body = buildDecisionBody({ ...base, sessionId });
      expect(body).not.toHaveProperty("session_id");
      expect(Object.keys(body).sort()).toEqual(
        ["action", "agent_did", "context", "payload", "payload_kind", "request_id", "surface", "target"],
      );
    }
  });

  it("cuts it to 128 characters and leaves out one the server would refuse", () => {
    expect(buildDecisionBody({ ...base, sessionId: "s".repeat(200) }).session_id).toBe("s".repeat(128));
    expect(buildDecisionBody({ ...base, sessionId: "a\nb" })).not.toHaveProperty("session_id");
  });

  it("names no parent decision", () => {
    expect(buildDecisionBody({ ...base, sessionId: "n8n:1" })).not.toHaveProperty("parent_decision_ids");
  });
});

describe("the Decision node", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  });

  async function runNode(
    params: Record<string, unknown>,
    host: Partial<IExecuteFunctions> & { getInstanceId?: () => string },
    items = 1,
  ): Promise<Record<string, unknown>[]> {
    const seen: Record<string, unknown>[] = [];
    server = createServer((req, res) => {
      let raw = "";
      req.on("data", (chunk) => { raw += chunk; });
      req.on("end", () => {
        seen.push(JSON.parse(raw));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ outcome: "allow", decision_id: "d1", reasons: [] }));
      });
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const all = { action: "a", target: "t", timeoutMs: 2_000, ...params };
    const ctx = {
      getInputData: () => Array.from({ length: items }, () => ({ json: {} })),
      getNodeParameter: (name: string, _i: number, fallback?: unknown) => (name in all ? (all as Record<string, unknown>)[name] : fallback),
      getCredentials: async () => ({ apiKey: "k", baseUrl }),
      continueOnFail: () => true,
      getNode: () => ({}),
      ...host,
    } as unknown as IExecuteFunctions;
    await (new ArtzainDecision() as INodeType).execute!.call(ctx);
    return seen;
  }

  it("sends the execution as the session of every item's decision", async () => {
    const seen = await runNode({}, { getExecutionId: () => "4711", getInstanceId: () => "inst-A" }, 2);
    expect(seen.map((body) => body.session_id)).toEqual(["n8n:inst-A:4711", "n8n:inst-A:4711"]);
    // Each item still has its own idempotency key.
    expect(new Set(seen.map((body) => body.request_id)).size).toBe(2);
  });

  it("uses the Session ID parameter when the workflow gives one", async () => {
    const seen = await runNode({ sessionId: " conversation-88 " }, { getExecutionId: () => "4711" });
    expect(seen[0].session_id).toBe("conversation-88");
  });

  it("sends no session on an n8n that names no execution", async () => {
    const seen = await runNode({}, {});
    expect(seen[0]).not.toHaveProperty("session_id");
  });

  it("offers Session ID as an optional parameter", () => {
    const props = (new ArtzainDecision().description as unknown as { properties: { name: string; default?: unknown; required?: boolean }[] }).properties;
    const session = props.find((p) => p.name === "sessionId");
    expect(session).toBeDefined();
    expect(session!.default).toBe("");
    expect(session!.required ?? false).toBe(false);
  });
});
