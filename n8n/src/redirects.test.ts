/**
 * A key goes only to the host it was issued with, and a redirect must not
 * change that. fetch follows a 3xx by default and sends the request again to
 * wherever `Location` points: it drops `Authorization` when the origin
 * changes, but not `X-Api-Key`, and on 307 and 308 it sends the body again
 * too. These tests run the nodes with n8n's global fetch against a local
 * origin that answers with a redirect to a second local server. That server
 * must receive nothing, and the item must report the status.
 *
 * The credential's Test button is not run here: n8n sends it through its own
 * request helper, which follows redirects and keeps `X-Api-Key` on them, to
 * any host, unless the request sets `disableFollowRedirect`. What is pinned
 * is that the request sets it.
 */

import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";

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

import { ArtzainApi } from "./credentials/ArtzainApi.credentials.js";
import { ArtzainDecision } from "./nodes/ArtzainDecision/ArtzainDecision.node.js";
import { ArtzainEnvelope } from "./nodes/ArtzainEnvelope/ArtzainEnvelope.node.js";
import { fetchWithTimeout } from "./timeout.js";

const KEY = "cnx_redirect_probe_0123456789";
const REDIRECTS = [301, 302, 303, 307, 308];

/** A 200 body either node would take as success. */
const ACCEPTED = {
  outcome: "allow",
  decision_id: "from-the-redirect-target",
  reasons: [],
  choices: [{ message: { role: "assistant", content: "ok" } }],
};

interface Received {
  method?: string;
  url?: string;
  key?: string;
  authorization?: string;
  body: string;
}

let servers: Server[] = [];

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join() : value;
}

async function listen(log: Received[], answer: (res: ServerResponse) => void): Promise<string> {
  const server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (body += chunk));
    req.on("end", () => {
      log.push({
        method: req.method,
        url: req.url,
        key: header(req.headers["x-api-key"]),
        authorization: header(req.headers.authorization),
        body,
      });
      answer(res);
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** What the redirecting origin puts in its body: no call may report it. */
const PAGE = "moved, says the redirecting server";

/**
 * An origin that answers every request with `status` and a `Location` on a
 * second server (another port, so another origin), which answers 200.
 */
async function redirectingOrigin(status: number) {
  const atOrigin: Received[] = [];
  const elsewhere: Received[] = [];
  const target = await listen(elsewhere, (res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ACCEPTED));
  });
  const origin = await listen(atOrigin, (res) => {
    res.writeHead(status, { Location: `${target}/landed`, "Content-Type": "application/json" });
    res.end(JSON.stringify({ detail: PAGE }));
  });
  return { origin, atOrigin, elsewhere };
}

/** Larger than fetch buffers unasked, so the connection stays busy until the body is read or dropped. */
const LARGE_BODY = 1024 * 1024;

/**
 * An origin that answers every request with a 302 and a body too large for
 * fetch to take in unasked, and hands back the socket each request came in on.
 */
async function redirectingWithLargeBody(): Promise<{ origin: string; sockets: Socket[] }> {
  const sockets: Socket[] = [];
  const server = createServer((req, res) => {
    sockets.push(req.socket);
    req.resume();
    req.on("end", () => {
      res.writeHead(302, { Location: "http://127.0.0.1:9/landed", "Content-Type": "text/plain" });
      res.end(Buffer.alloc(LARGE_BODY, "x"));
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, sockets };
}

/** Whether the client lets go of `socket` within `ms`. */
function closesWithin(socket: Socket, ms: number): Promise<boolean> {
  if (socket.destroyed) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    socket.once("close", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

function context(
  baseUrl: string,
  params: Record<string, unknown>,
  continueOnFail: boolean,
): IExecuteFunctions {
  return {
    getInputData: () => [{ json: {} }],
    getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
    getCredentials: async () => ({ apiKey: KEY, baseUrl }),
    continueOnFail: () => continueOnFail,
    getNode: () => ({}),
    getExecutionId: () => "exec-1",
  };
}

async function run(node: INodeType, ctx: IExecuteFunctions) {
  return node.execute!.call(ctx);
}

afterEach(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  servers = [];
});

describe.each(REDIRECTS)("an origin that answers HTTP %i to another server", (status) => {
  it("Decision node sends nothing there and routes the item to Deny with the status", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    // continueOnFail off, n8n's default: the item must still land on Deny.
    const [allow, review, deny] = await run(
      new ArtzainDecision(),
      context(origin, { action: "a", target: "t", timeoutMs: 2_000 }, false),
    );
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(deny![0]!.json.outcome).toBe("deny");
    expect(String(deny![0]!.json.reasons)).toContain(`HTTP ${status}`);
    expect(String(deny![0]!.json.reasons)).toContain("redirect");
    expect(String(deny![0]!.json.reasons)).not.toContain(PAGE);
  });

  it("Envelope node sends nothing there and fails closed with the status", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    const [out] = await run(
      new ArtzainEnvelope(),
      context(origin, { userMessage: "hi", timeoutMs: 2_000 }, true),
    );
    expect(atOrigin.map((r) => r.authorization)).toEqual([`Bearer ${KEY}`]);
    expect(elsewhere).toEqual([]);
    expect(out).toHaveLength(1);
    expect(out![0]!.json.outcome).toBe("deny");
    expect(String(out![0]!.json.error)).toContain(`HTTP ${status}`);
    expect(String(out![0]!.json.error)).toContain("redirect");
    expect(String(out![0]!.json.error)).not.toContain(PAGE);
  });
});

describe("fetchWithTimeout", () => {
  it("does not follow a redirect even when the caller's init asks it to", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(307);
    const { status } = await fetchWithTimeout(
      `${origin}/api/v1/decisions`,
      { method: "POST", headers: { "X-Api-Key": KEY }, body: "{}", redirect: "follow" },
      2_000,
      { what: "Decision API", baseSource: "the credential's Base URL" },
    );
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(status).toBe(307);
  });
});

describe("the Decision credential's test request", () => {
  const test = new ArtzainApi().test as {
    request: Record<string, unknown>;
    rules?: Array<{ type: string; properties: { value: number; message: string } }>;
  };

  it("does not follow a redirect", () => {
    expect(test.request.disableFollowRedirect).toBe(true);
  });

  it("names the status when the Base URL answers any 3xx", () => {
    for (let status = 300; status <= 308; status++) {
      const rule = test.rules?.find((r) => r.properties.value === status);
      expect(rule?.type).toBe("responseCode");
      expect(rule?.properties.message).toContain(`HTTP ${status}`);
    }
  });
});

describe("a redirect's body, left unread", () => {
  it("Envelope node lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    const [out] = await run(
      new ArtzainEnvelope(),
      context(origin, { userMessage: "hi", timeoutMs: 2_000 }, true),
    );
    expect(out![0]!.json.outcome).toBe("deny");
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });
});
