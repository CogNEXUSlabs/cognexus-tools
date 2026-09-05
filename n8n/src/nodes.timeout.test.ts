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

import { ArtzainDecision } from "./nodes/ArtzainDecision/ArtzainDecision.node.js";
import { ArtzainEnvelope } from "./nodes/ArtzainEnvelope/ArtzainEnvelope.node.js";
import { DEFAULT_TIMEOUT_MS, resolveTimeoutMs } from "./timeout.js";

// A fetch that settles only when the caller's AbortSignal fires — what a
// stalled server looks like to the node.
const hangingFetch = vi.fn(
  (_url: string, init?: { signal?: AbortSignal }) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    }),
);

function fakeContext(params: Record<string, unknown>): IExecuteFunctions {
  return {
    getInputData: () => [{ json: {} }],
    getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
    getCredentials: async () => ({ apiKey: "k", baseUrl: "https://engine.example.com" }),
    continueOnFail: () => true,
    getNode: () => ({}),
    getExecutionId: () => "exec-1",
  };
}

async function run(node: INodeType, params: Record<string, unknown>) {
  return node.execute!.call(fakeContext(params));
}

afterEach(() => {
  vi.unstubAllGlobals();
  hangingFetch.mockClear();
});

describe("resolveTimeoutMs", () => {
  it("defaults to 10 s and rejects junk", () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(10_000);
    expect(resolveTimeoutMs(undefined)).toBe(10_000);
    expect(resolveTimeoutMs(0)).toBe(10_000);
    expect(resolveTimeoutMs(-5)).toBe(10_000);
    expect(resolveTimeoutMs("abc")).toBe(10_000);
    expect(resolveTimeoutMs(250)).toBe(250);
    expect(resolveTimeoutMs("250")).toBe(250);
  });
});

describe("node HTTP timeouts", () => {
  it("Decision node declares a timeoutMs property", () => {
    const prop = new ArtzainDecision().description.properties.find((p) => p.name === "timeoutMs");
    expect(prop).toBeDefined();
    expect(prop!.default).toBe(10_000);
  });

  it("Envelope node declares a timeoutMs property", () => {
    const prop = new ArtzainEnvelope().description.properties.find((p) => p.name === "timeoutMs");
    expect(prop).toBeDefined();
    expect(prop!.default).toBe(10_000);
  });

  it("Decision node aborts a never-resolving fetch and fails closed onto Deny", async () => {
    vi.stubGlobal("fetch", hangingFetch);
    const [allow, review, deny] = await run(new ArtzainDecision(), {
      action: "a",
      target: "t",
      timeoutMs: 20,
    });
    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(deny![0]!.json.outcome).toBe("deny");
    expect(String(deny![0]!.json.reasons)).toContain("failing closed");
    expect(hangingFetch.mock.calls[0]![1]!.signal).toBeInstanceOf(AbortSignal);
  }, 2_000);

  it("Envelope node aborts a never-resolving fetch and fails closed", async () => {
    vi.stubGlobal("fetch", hangingFetch);
    const [out] = await run(new ArtzainEnvelope(), { userMessage: "hi", timeoutMs: 20 });
    expect(out).toHaveLength(1);
    expect(out![0]!.json.outcome).toBe("deny");
    expect(hangingFetch.mock.calls[0]![1]!.signal).toBeInstanceOf(AbortSignal);
  }, 2_000);
});
