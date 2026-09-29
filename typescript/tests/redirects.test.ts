/**
 * A key goes only to the host it was issued with, and a redirect must not
 * change that. fetch follows a 3xx by default and sends the request again to
 * wherever `Location` points: it drops `Authorization` when the origin
 * changes, but not `X-Api-Key`, and on 307 and 308 it sends the body again
 * too. These tests run the default global fetch against a local origin that
 * answers with a redirect to a second local server. That server must receive
 * nothing, and the call must report the status.
 */

import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { configure, decide, DecisionError, fetchApiKeyIdentity, postSdkEvent } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const KEY = "cnx_redirect_probe_0123456789";
const REDIRECTS = [301, 302, 303, 307, 308];
const ENV = ["COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL", "COGNEXUS_CREDENTIALS_PATH"];

/** A 200 body each call would take as success. */
const ACCEPTED = {
  outcome: "allow",
  decision_id: "from-the-redirect-target",
  audit_block_id: "b",
  contributing_agents: [],
  policy_bundle_version: "builtin:v0",
  resolution_policy: "builtin/strict-v0",
  latency_ms: 1,
  reasons: [],
  user_id: 1,
};

interface Received {
  method?: string;
  url?: string;
  key?: string;
  body: string;
}

let servers: Server[] = [];

async function listen(log: Received[], answer: (res: ServerResponse) => void): Promise<string> {
  const server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (body += chunk));
    req.on("end", () => {
      const key = req.headers["x-api-key"];
      log.push({ method: req.method, url: req.url, key: Array.isArray(key) ? key.join() : key, body });
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

beforeEach(() => {
  for (const name of ENV) delete process.env[name];
  // No profile: the key and host come from configure() alone.
  process.env.COGNEXUS_CREDENTIALS_PATH = join(tmpdir(), "artzain-no-profile", "credentials.toml");
});

afterEach(async () => {
  _resetConfigForTests();
  for (const name of ENV) delete process.env[name];
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  servers = [];
});

describe.each(REDIRECTS)("an origin that answers HTTP %i to another server", (status) => {
  it("decide() sends nothing there and throws DecisionError with the status", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    configure({ apiKey: KEY, baseUrl: origin });
    const err = await decide({ action: "a", target: "t", payload: "p" }).catch((e: unknown) => e);
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).status).toBe(status);
    expect((err as DecisionError).message).toContain(`HTTP ${status}`);
    expect((err as DecisionError).message).toContain("redirect");
    expect((err as DecisionError).message).not.toContain(PAGE);
    expect((err as DecisionError).detail).toBeUndefined();
  });

  it("fetchApiKeyIdentity() sends nothing there and throws DecisionError with the status", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    configure({ apiKey: KEY, baseUrl: origin });
    const err = await fetchApiKeyIdentity().catch((e: unknown) => e);
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).status).toBe(status);
    expect((err as DecisionError).message).toContain(`HTTP ${status}`);
    expect((err as DecisionError).message).toContain("redirect");
    expect((err as DecisionError).message).not.toContain(PAGE);
    expect((err as DecisionError).detail).toBeUndefined();
  });

  it("postSdkEvent() sends nothing there and returns false", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    configure({ apiKey: KEY, baseUrl: origin });
    expect(await postSdkEvent({ eventType: "guard.block" })).toBe(false);
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
  });
});

describe("a custom fetchImpl", () => {
  it("is asked not to follow redirects by every call that sends the key", async () => {
    configure({ apiKey: KEY, baseUrl: "https://engine.example.com" });
    const modes: unknown[] = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      modes.push((init as { redirect?: unknown }).redirect);
      return {
        ok: true,
        status: 200,
        json: async () => ACCEPTED,
        text: async () => JSON.stringify(ACCEPTED),
      };
    };
    await decide({ action: "a", target: "t", payload: "p", fetchImpl });
    await fetchApiKeyIdentity({ fetchImpl });
    await postSdkEvent({ eventType: "guard.block", fetchImpl });
    expect(modes).toEqual(["manual", "manual", "manual"]);
  });
});

describe("a redirect's body, left unread", () => {
  it("decide() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    configure({ apiKey: KEY, baseUrl: origin });
    const err = await decide({ action: "a", target: "t", payload: "p" }).catch((e: unknown) => e);
    expect((err as DecisionError).status).toBe(302);
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });

  it("fetchApiKeyIdentity() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    configure({ apiKey: KEY, baseUrl: origin });
    const err = await fetchApiKeyIdentity().catch((e: unknown) => e);
    expect((err as DecisionError).status).toBe(302);
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });

  it("postSdkEvent() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    configure({ apiKey: KEY, baseUrl: origin });
    expect(await postSdkEvent({ eventType: "guard.block" })).toBe(false);
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });
});
