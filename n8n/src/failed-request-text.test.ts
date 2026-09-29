/**
 * A failed request is reported without its error's text.
 *
 * Both nodes put the text of the error a request failed with into the item
 * (the Deny reason, the Envelope `error`) or the node error n8n shows, and
 * attached the error to the item. That can carry what an execution log, or a
 * later node, must not: fetch quotes a header value it refuses, so an API key
 * pasted with a line break was quoted in full, and it quotes a base URL that
 * holds a user name and password; the error's cause names the host of a
 * certificate issued for another name, or the server's address when the
 * connection drops mid-body. They now name the error's kind (for fetch's
 * "fetch failed", its cause's) and, when no answer came back, where the base
 * URL came from, and attach an error of their own.
 */

import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { inspect } from "node:util";

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

const KEY = "cnx_failed_request_text_0123456789abcdef";
/** A key pasted with a line break: fetch refuses it and quotes both halves. */
const HEAD = "cnx_failed_request_head_0123456789";
const TAIL = "tail_abcdefghijklmnopqrstuvwxyz";
const BROKEN_KEY = `${HEAD}\n${TAIL}`;
const HOST = "tenant-host.example.test";
const CREDENTIAL = "the credential's Base URL";

let server: Server | undefined;

afterEach(async () => {
  vi.unstubAllGlobals();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

/** A local origin nothing listens on: a request to it is refused. */
async function closedOrigin(): Promise<string> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return `http://127.0.0.1:${port}`;
}

async function serve(handler: RequestListener): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** A server that answers `status`, starts the body, then drops the connection. */
async function droppingServer(status = 200): Promise<string> {
  return serve((_req, res) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.write('{"outcome":');
    setTimeout(() => res.socket?.destroy(), 20);
  });
}

/** What the socket of a dropped connection would show: its addresses and ports. */
const SOCKET_DETAILS = ["remoteAddress", "remotePort", "localAddress", "localPort"];

/** An error whose every property read throws, with a message that names the host. */
function unreadable(): object {
  return new Proxy(
    {},
    {
      get() {
        throw new Error(`read refused at ${HOST}`);
      },
    },
  );
}

/** What undici rejects with when the server's certificate names another host. */
function certificateForAnotherName(host: string): TypeError {
  const cause = Object.assign(
    new Error(
      `Hostname/IP does not match certificate's altnames: Host: ${host}. ` +
        "is not in the cert's altnames: DNS:other.example.test",
    ),
    { code: "ERR_TLS_CERT_ALTNAME_INVALID", host },
  );
  return new TypeError("fetch failed", { cause });
}

function context(
  credentials: Record<string, unknown>,
  params: Record<string, unknown>,
  continueOnFail = true,
): IExecuteFunctions {
  return {
    getInputData: () => [{ json: {} }],
    getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
    getCredentials: async () => credentials,
    continueOnFail: () => continueOnFail,
    getNode: () => ({}),
    getExecutionId: () => "exec-1",
  };
}

async function run(node: INodeType, ctx: IExecuteFunctions) {
  return node.execute!.call(ctx);
}

const DECISION = { action: "a", target: "t", timeoutMs: 2_000 };
const ENVELOPE = { userMessage: "hi", timeoutMs: 2_000 };

describe("the Decision node", () => {
  it("does not quote an API key fetch refuses to send", async () => {
    const [allow, review, deny] = await run(
      new ArtzainDecision(),
      context({ apiKey: BROKEN_KEY, baseUrl: await closedOrigin() }, DECISION),
    );

    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny).toHaveLength(1);
    expect(deny![0]!.json.reasons).toEqual([
      `Decision API unreachable: TypeError (base URL from ${CREDENTIAL}) — failing closed`,
    ]);
    const item = inspect(deny![0], { depth: 8 });
    expect(item).not.toContain(HEAD);
    expect(item).not.toContain(TAIL);
  });

  it("raises a node error without the key when Continue On Fail is off", async () => {
    const err = await run(
      new ArtzainDecision(),
      context({ apiKey: BROKEN_KEY, baseUrl: await closedOrigin() }, DECISION, false),
    ).catch((e: unknown) => e);

    expect((err as Error).message).toBe(`Decision API unreachable: TypeError (base URL from ${CREDENTIAL})`);
  });

  it("names a certificate for another name by its cause's kind, without the host", async () => {
    vi.stubGlobal("fetch", async () => {
      throw certificateForAnotherName(HOST);
    });
    const [, , deny] = await run(new ArtzainDecision(), context({ apiKey: KEY, baseUrl: `https://${HOST}` }, DECISION));

    expect(deny![0]!.json.reasons).toEqual([
      `Decision API unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from ${CREDENTIAL}) — failing closed`,
    ]);
    expect(inspect(deny![0], { depth: 8 })).not.toContain(HOST);
  });

  it("names the default when the credential sets no base URL", async () => {
    vi.stubGlobal("fetch", async () => {
      throw certificateForAnotherName(HOST);
    });
    const [, , deny] = await run(new ArtzainDecision(), context({ apiKey: KEY, baseUrl: "" }, DECISION));

    expect(deny![0]!.json.reasons).toEqual([
      "Decision API unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from default) — failing closed",
    ]);
  });

  it("reports its own timeout as a timeout, whatever fetch rejected with", async () => {
    vi.stubGlobal(
      "fetch",
      (_url: string, init?: { signal?: AbortSignal }) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error(`socket to ${HOST} aborted`)));
        }),
    );
    const [, , deny] = await run(
      new ArtzainDecision(),
      context({ apiKey: KEY, baseUrl: `https://${HOST}` }, { ...DECISION, timeoutMs: 20 }),
    );

    expect(deny![0]!.json.reasons).toEqual([
      `Decision API unreachable: TimeoutError, aborted when the timeout passed (base URL from ${CREDENTIAL}) — failing closed`,
    ]);
  }, 2_000);

  it("names the kind of a body that could not be read, and attaches nothing of the socket's", async () => {
    const [allow, review, deny] = await run(
      new ArtzainDecision(),
      context({ apiKey: KEY, baseUrl: await droppingServer() }, DECISION),
    );

    expect(allow).toHaveLength(0);
    expect(review).toHaveLength(0);
    expect(deny![0]!.json.reasons).toEqual([
      "Decision API returned HTTP 200 but its body could not be read: SocketError [UND_ERR_SOCKET] — failing closed",
    ]);
    const item = inspect(deny![0], { depth: 8 });
    for (const detail of SOCKET_DETAILS) expect(item).not.toContain(detail);
  });

  it("gives the status the unreadable body came with", async () => {
    const [, , deny] = await run(
      new ArtzainDecision(),
      context({ apiKey: KEY, baseUrl: await droppingServer(503) }, DECISION),
    );

    expect(deny![0]!.json.reasons).toEqual([
      "Decision API returned HTTP 503 but its body could not be read: SocketError [UND_ERR_SOCKET] — failing closed",
    ]);
  });

  it("does not quote a base URL's user name and password", async () => {
    // fetch refuses a URL with credentials in it, and quotes the URL.
    const baseUrl = (await closedOrigin()).replace("//", "//someone:secretpw@");
    const [, , deny] = await run(new ArtzainDecision(), context({ apiKey: KEY, baseUrl }, DECISION));

    expect(deny![0]!.json.reasons).toEqual([
      `Decision API unreachable: TypeError (base URL from ${CREDENTIAL}) — failing closed`,
    ]);
    expect(inspect(deny![0], { depth: 8 })).not.toContain("secretpw");
  });

  it("names an error whose properties cannot be read as Error", async () => {
    vi.stubGlobal("fetch", async () => {
      throw unreadable();
    });
    const [, , deny] = await run(new ArtzainDecision(), context({ apiKey: KEY, baseUrl: `https://${HOST}` }, DECISION));

    expect(deny![0]!.json.reasons).toEqual([
      `Decision API unreachable: Error (base URL from ${CREDENTIAL}) — failing closed`,
    ]);
  });
});

describe("the Envelope node", () => {
  it("does not quote an envelope key fetch refuses to send", async () => {
    const [out] = await run(
      new ArtzainEnvelope(),
      context({ apiKey: BROKEN_KEY, baseUrl: await closedOrigin() }, ENVELOPE),
    );

    expect(out).toHaveLength(1);
    expect(out![0]!.json).toEqual({
      error: `envelope unreachable: TypeError (base URL from ${CREDENTIAL})`,
      outcome: "deny",
    });
    const item = inspect(out![0], { depth: 8 });
    expect(item).not.toContain(HEAD);
    expect(item).not.toContain(TAIL);
  });

  it("names a certificate for another name by its cause's kind, without the host", async () => {
    vi.stubGlobal("fetch", async () => {
      throw certificateForAnotherName(HOST);
    });
    const [out] = await run(new ArtzainEnvelope(), context({ apiKey: KEY, baseUrl: `https://${HOST}` }, ENVELOPE));

    expect(out![0]!.json.error).toBe(
      `envelope unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from ${CREDENTIAL})`,
    );
    expect(inspect(out![0], { depth: 8 })).not.toContain(HOST);
  });

  it("names the default when the credential sets no base URL", async () => {
    vi.stubGlobal("fetch", async () => {
      throw certificateForAnotherName(HOST);
    });
    const [out] = await run(new ArtzainEnvelope(), context({ apiKey: KEY, baseUrl: "" }, ENVELOPE));

    expect(out![0]!.json.error).toBe(
      "envelope unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from default)",
    );
  });

  it("names the kind of a body that could not be read, and attaches nothing of the socket's", async () => {
    const [out] = await run(new ArtzainEnvelope(), context({ apiKey: KEY, baseUrl: await droppingServer() }, ENVELOPE));

    expect(out![0]!.json).toEqual({
      error: "envelope returned HTTP 200 but its body could not be read: SocketError [UND_ERR_SOCKET]",
      outcome: "deny",
    });
    const item = inspect(out![0], { depth: 8 });
    for (const detail of SOCKET_DETAILS) expect(item).not.toContain(detail);
  });

  it("gives the status the unreadable body came with", async () => {
    const [out] = await run(new ArtzainEnvelope(), context({ apiKey: KEY, baseUrl: await droppingServer(502) }, ENVELOPE));

    expect(out![0]!.json.error).toBe(
      "envelope returned HTTP 502 but its body could not be read: SocketError [UND_ERR_SOCKET]",
    );
  });

  it("still reports a status it fails closed on with what the server sent", async () => {
    vi.stubGlobal("fetch", async () => new Response("engine down", { status: 503 }));
    const [out] = await run(new ArtzainEnvelope(), context({ apiKey: KEY, baseUrl: `https://${HOST}` }, ENVELOPE));

    expect(out![0]!.json).toEqual({ error: "envelope HTTP 503: engine down — failing closed", outcome: "deny" });
  });
});
