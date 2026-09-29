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

import { afterEach, describe, expect, it } from "vitest";

import { announceInstance } from "./announce.js";
import { DecisionError, postDecision, type FetchLike } from "./client.js";
import { enrollInstance } from "./enroll.js";

const KEY = "cnx_redirect_probe_0123456789";
const REDIRECTS = [301, 302, 303, 307, 308];

/** A 200 body each call would take as success. */
const ACCEPTED = {
  outcome: "allow",
  decision_id: "from-the-redirect-target",
  reasons: [],
  registered: 1,
  adapter: { primary: "grokbot" },
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

afterEach(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  servers = [];
});

describe.each(REDIRECTS)("an origin that answers HTTP %i to another server", (status) => {
  it("postDecision() sends nothing there and throws DecisionError with the status", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    const err = await postDecision({
      apiKey: KEY,
      baseUrl: origin,
      action: "exec",
      target: "grokbot:tool:exec",
      payload: "{}",
      agentDid: "bot",
    }).catch((e: unknown) => e);
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).status).toBe(status);
    expect((err as DecisionError).message).toContain(`HTTP ${status}`);
    expect((err as DecisionError).message).toContain("redirect");
    expect((err as DecisionError).message).not.toContain(PAGE);
    expect((err as DecisionError).detail).toBeUndefined();
  });

  it("announceInstance() sends nothing there and reports the status as a refusal", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    const lines: string[] = [];
    const out = await announceInstance(
      { announce: true, apiKey: KEY, baseUrl: origin, instance: "laptop" },
      undefined,
      (line) => lines.push(line),
    );
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(out).toMatchObject({ ok: false, status, retryable: false });
    expect(lines.join("\n")).toContain(`HTTP ${status}`);
    expect(lines.join("\n")).not.toContain(PAGE);
  });

  it("enrollInstance() sends nothing there and reports the status as a refusal", async () => {
    const { origin, atOrigin, elsewhere } = await redirectingOrigin(status);
    const lines: string[] = [];
    const out = await enrollInstance(
      { apiKey: KEY, baseUrl: origin, instance: "laptop" },
      undefined,
      (line) => lines.push(line),
    );
    expect(atOrigin.map((r) => r.key)).toEqual([KEY]);
    expect(elsewhere).toEqual([]);
    expect(out).toMatchObject({ ok: false, status, retryable: false });
    expect(lines.join("\n")).toContain(`HTTP ${status}`);
    expect(lines.join("\n")).not.toContain(PAGE);
  });
});

describe("a custom fetch", () => {
  it("is asked not to follow redirects by every call that sends the key", async () => {
    const modes: unknown[] = [];
    const impl: FetchLike = async (_url, init) => {
      modes.push((init as { redirect?: unknown }).redirect);
      return {
        ok: true,
        status: 200,
        json: async () => ACCEPTED,
        text: async () => JSON.stringify(ACCEPTED),
      };
    };
    const cfg = { apiKey: KEY, baseUrl: "https://engine.example", instance: "laptop" };
    await postDecision({ ...cfg, action: "exec", target: "t", payload: "{}", agentDid: "bot", fetchImpl: impl });
    await announceInstance({ ...cfg, announce: true }, impl);
    await enrollInstance(cfg, impl);
    expect(modes).toEqual(["manual", "manual", "manual"]);
  });
});

describe("a redirect's body, left unread", () => {
  it("postDecision() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    const err = await postDecision({
      apiKey: KEY,
      baseUrl: origin,
      action: "exec",
      target: "t",
      payload: "{}",
      agentDid: "bot",
    }).catch((e: unknown) => e);
    expect((err as DecisionError).status).toBe(302);
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });

  it("announceInstance() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    const out = await announceInstance({ announce: true, apiKey: KEY, baseUrl: origin, instance: "laptop" });
    expect(out).toMatchObject({ ok: false, status: 302 });
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });

  it("enrollInstance() lets go of the connection", async () => {
    const { origin, sockets } = await redirectingWithLargeBody();
    const out = await enrollInstance({ apiKey: KEY, baseUrl: origin, instance: "laptop" });
    expect(out).toMatchObject({ ok: false, status: 302 });
    expect(sockets).toHaveLength(1);
    expect(await closesWithin(sockets[0]!, 2_000)).toBe(true);
  });
});
