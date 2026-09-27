/**
 * The timeout covers the response body as well as the headers. It used to be
 * cleared once the headers arrived, so a server that sent them and then
 * stalled mid-body hung the workflow item for good. These tests run the nodes
 * with n8n's global fetch against a local server.
 *
 * The stall tests run the deadline on a fake clock (setTimeout and
 * clearTimeout only; fetch and the server do real I/O) that moves only once
 * the client has the headers and the node is reading the body. On the real
 * clock the deadline could pass before the headers arrived (a cold runner
 * paying for the first fetch and connection), and the item still failed
 * closed on "timeout", so the tests passed without reaching the body. The
 * status the client saw is asserted for that reason.
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

const TIMEOUT_MS = 100;

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

/**
 * Starts `call` with the clock stopped and moves it past the deadline only
 * once the response headers are in. Resolves with the status the client saw
 * (undefined if `call` finished first) and what `call` returned.
 */
async function pastTheDeadline<T>(
  call: () => Promise<T>,
): Promise<{ status: number | undefined; result: T }> {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const realFetch = globalThis.fetch;
  let headersIn!: (status: number) => void;
  const headers = new Promise<number>((resolve) => (headersIn = resolve));
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const resp = await realFetch(input, init);
    headersIn(resp.status);
    return resp;
  });
  const pending = call();
  const status = await Promise.race([headers, pending.then(() => undefined)]);
  // Only microtasks lie between fetch resolving and the node starting on the
  // body, so a macrotask later it is waiting on the body alone.
  await new Promise((resolve) => setImmediate(resolve));
  await vi.advanceTimersByTimeAsync(TIMEOUT_MS);
  return { status, result: await pending };
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
  vi.useRealTimers();
  vi.restoreAllMocks();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

describe("a body that stalls after the headers", () => {
  it("Decision node times out reading the body and fails closed onto Deny", async () => {
    const baseUrl = await stallingServer(200);
    const { status, result } = await pastTheDeadline(() =>
      run(
        new ArtzainDecision(),
        context(baseUrl, { action: "a", target: "t", timeoutMs: TIMEOUT_MS }),
      ),
    );
    expect(status).toBe(200);
    const [allow, review, deny] = result;
    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(deny![0]!.json.outcome).toBe("deny");
    expect(String(deny![0]!.json.reasons)).toContain("timeout");
    expect(String(deny![0]!.json.reasons)).toContain("failing closed");
  }, 3_000);

  it("Envelope node times out reading the body and fails closed", async () => {
    const baseUrl = await stallingServer(200);
    const { status, result } = await pastTheDeadline(() =>
      run(
        new ArtzainEnvelope(),
        context(baseUrl, { userMessage: "hi", timeoutMs: TIMEOUT_MS }),
      ),
    );
    expect(status).toBe(200);
    const [out] = result;
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
