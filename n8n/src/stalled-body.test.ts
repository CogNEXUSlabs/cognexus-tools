/**
 * The timeout covers the response body as well as the headers. It used to be
 * cleared once the headers arrived, so a server that sent them and then
 * stalled mid-body hung the workflow item for good. These tests run the nodes
 * with n8n's global fetch against a local server.
 */

import { createServer, type RequestListener, type Server } from "node:http";
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

import { ArtzainDecision } from "./nodes/ArtzainDecision/ArtzainDecision.node.js";
import { ArtzainEnvelope } from "./nodes/ArtzainEnvelope/ArtzainEnvelope.node.js";

let server: Server | undefined;

/** A server that sends `status` and its headers, starts a JSON body, then goes quiet. */
async function stallingServer(status: number): Promise<string> {
  return listen((_req, res) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.write('{"outcome":');
  });
}

async function listen(handler: RequestListener): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function context(
  baseUrl: string,
  params: Record<string, unknown>,
  continueOnFail = true,
): IExecuteFunctions {
  return {
    getInputData: () => [{ json: {} }],
    getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
    getCredentials: async () => ({ apiKey: "k", baseUrl }),
    continueOnFail: () => continueOnFail,
    getNode: () => ({}),
    getExecutionId: () => "exec-1",
  };
}

async function run(node: INodeType, ctx: IExecuteFunctions) {
  return node.execute!.call(ctx);
}

afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

describe("a body that stalls after the headers", () => {
  it("Decision node times out reading the body and fails closed onto Deny", async () => {
    const baseUrl = await stallingServer(200);
    const [allow, review, deny] = await run(
      new ArtzainDecision(),
      context(baseUrl, { action: "a", target: "t", timeoutMs: 100 }),
    );
    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(deny![0]!.json.outcome).toBe("deny");
    expect(String(deny![0]!.json.reasons)).toContain("timeout");
    expect(String(deny![0]!.json.reasons)).toContain("failing closed");
  }, 3_000);

  it("Envelope node times out reading the body and fails closed", async () => {
    const baseUrl = await stallingServer(200);
    const [out] = await run(
      new ArtzainEnvelope(),
      context(baseUrl, { userMessage: "hi", timeoutMs: 100 }),
    );
    expect(out).toHaveLength(1);
    expect(out![0]!.json.outcome).toBe("deny");
    expect(String(out![0]!.json.error)).toContain("timeout");
  }, 3_000);
});

describe("a body that is not JSON", () => {
  it("Decision node routes a proxy's HTML error page onto Deny with its text", async () => {
    const page = "<html><body>502 Bad Gateway</body></html>";
    const baseUrl = await listen((_req, res) => {
      res.writeHead(502, { "Content-Type": "text/html" });
      res.end(page);
    });
    // continueOnFail off, n8n's default: the item must still land on Deny
    // rather than raise a node error.
    const [allow, review, deny] = await run(
      new ArtzainDecision(),
      context(baseUrl, { action: "a", target: "t", timeoutMs: 2_000 }, false),
    );
    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(String(deny![0]!.json.reasons)).toContain("502 Bad Gateway");
  }, 3_000);
});
