/**
 * A failed request is reported without its error's text.
 *
 * The gate's block reason, `postDecision()`'s DecisionError and the announce
 * and enroll log lines quoted the error a request failed with. That text can
 * carry what a log, or the model the block reason goes back to, must not:
 * fetch quotes a header value it refuses, so an API key pasted with a line
 * break was quoted in full, and it quotes a base URL that holds a user name
 * and password. They now name the error's kind (for fetch's "fetch failed",
 * its cause's, whose text is left out too: a certificate issued for another
 * name puts the host in it) and where the base URL came from. A body that is
 * not JSON is reported without the parser's text, which quotes the body.
 */

import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { inspect } from "node:util";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ANNOUNCE_TIMEOUT_MS, announceInstance } from "./announce.js";
import { DecisionError, postDecision, type FetchLike } from "./client.js";
import { ENROLL_TIMEOUT_MS, enrollInstance } from "./enroll.js";
import { handleBeforeToolCall, resetAnnounceForTests, type PluginConfig } from "./gate.js";

const KEY = "cnx_failed_request_text_0123456789abcdef";
/** A key pasted with a line break: fetch refuses it and quotes both halves. */
const HEAD = "cnx_failed_request_head_0123456789";
const TAIL = "tail_abcdefghijklmnopqrstuvwxyz";
const BROKEN_KEY = `${HEAD}\n${TAIL}`;
const HOST = "tenant-host.example.test";

const EVENT = { toolName: "exec", params: { command: "ls" }, toolCallId: "tc-1" };

let server: Server | undefined;

beforeEach(() => {
  resetAnnounceForTests();
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
});

afterEach(async () => {
  vi.useRealTimers();
  delete process.env.COGNEXUS_API_BASE_URL;
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

function rejecting(error: unknown): FetchLike {
  return async () => {
    throw error;
  };
}

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

/** Settles only when the call's own AbortSignal fires, rejecting with the transport's own error. */
const hang: FetchLike = (_url, init) =>
  new Promise((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(new Error(`socket to ${HOST} aborted`)));
  });

/** Answers 200; reading the body rejects with `bodyError()` once the call's own AbortSignal fires. */
function bodyFailsAtDeadline(bodyError: () => unknown): FetchLike {
  return async (_url, init) => ({
    ok: true,
    status: 200,
    json: () =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(bodyError()));
      }),
    text: async () => "",
  });
}

/** Answers 200; reading the body rejects with `bodyError` at once. */
function bodyFails(bodyError: unknown): FetchLike {
  return async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw bodyError;
    },
    text: async () => "",
  });
}

async function decisionFailure(options: Partial<Parameters<typeof postDecision>[0]>): Promise<DecisionError> {
  const err = await postDecision({
    apiKey: KEY,
    baseUrl: `https://${HOST}`,
    action: "exec",
    target: "openclaw:tool:exec",
    payload: "{}",
    agentDid: "bot",
    ...options,
  }).catch((e: unknown) => e);
  expect(err).toBeInstanceOf(DecisionError);
  return err as DecisionError;
}

/** Everything a logger shows for the error: `console.error` prints `inspect`. */
function printed(err: unknown): string {
  return inspect(err, { depth: 8 });
}

describe("postDecision()", () => {
  it("does not quote an API key fetch refuses to send", async () => {
    const err = await decisionFailure({ apiKey: BROKEN_KEY, baseUrl: await closedOrigin() });

    expect(err.message).toBe("Decision API unreachable: TypeError (base URL from the baseUrl option)");
    expect(printed(err)).not.toContain(HEAD);
    expect(printed(err)).not.toContain(TAIL);
  });

  it("names the kind of a refused connection and the base URL's source it is given", async () => {
    const err = await decisionFailure({ baseUrl: await closedOrigin(), baseSource: "plugin config baseUrl" });

    expect(err.message).toBe(
      "Decision API unreachable: Error [ECONNREFUSED] (base URL from plugin config baseUrl)",
    );
  });

  it("names a certificate for another name by its cause's kind, without the host", async () => {
    const err = await decisionFailure({ fetchImpl: rejecting(certificateForAnotherName(HOST)) });

    expect(err.message).toBe(
      "Decision API unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from the baseUrl option)",
    );
    expect(printed(err)).not.toContain(HOST);
    expect(Object.prototype.hasOwnProperty.call(err, "cause")).toBe(false);
  });

  it("reports its own timeout as a timeout, whatever the transport rejected with", async () => {
    const err = await decisionFailure({ fetchImpl: hang, timeoutMs: 20 });

    expect(err.message).toBe(
      "Decision API unreachable: TimeoutError, aborted when the timeout passed (base URL from the baseUrl option)",
    );
  }, 2_000);

  it("does not quote a body that is not JSON", async () => {
    // A 200 that echoes what it was sent, as a misrouted request can get.
    const echo = await serve((req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(String(req.headers["x-api-key"]));
    });
    const err = await decisionFailure({ baseUrl: echo });

    expect(err.message).toBe("Decision API returned HTTP 200 with a non-JSON body");
    expect(err.status).toBe(200);
    expect(printed(err)).not.toContain(KEY.slice(0, 8));
  });

  it("does not quote a base URL's user name and password", async () => {
    // fetch refuses a URL with credentials in it, and quotes the URL.
    const err = await decisionFailure({ baseUrl: (await closedOrigin()).replace("//", "//someone:secretpw@") });

    expect(err.message).toBe("Decision API unreachable: TypeError (base URL from the baseUrl option)");
    expect(printed(err)).not.toContain("secretpw");
  });

  it("names an error whose properties cannot be read as Error", async () => {
    const err = await decisionFailure({ fetchImpl: rejecting(unreadable()) });

    expect(err.message).toBe("Decision API unreachable: Error (base URL from the baseUrl option)");
  });

  it("reports a body read that fails after its own timeout as that timeout, even with a SyntaxError", async () => {
    const err = await decisionFailure({
      fetchImpl: bodyFailsAtDeadline(() => new SyntaxError("Unexpected end of JSON input")),
      timeoutMs: 20,
    });

    expect(err.message).toBe(
      "Decision API returned HTTP 200 but its body could not be read: " +
        "TimeoutError, aborted when the timeout passed",
    );
  }, 2_000);

  it("names a body error whose properties cannot be read as Error", async () => {
    const err = await decisionFailure({ fetchImpl: bodyFails(unreadable()) });

    expect(err.message).toBe("Decision API returned HTTP 200 but its body could not be read: Error");
  });
});

describe("the gate's block reason", () => {
  it("does not quote an API key fetch refuses to send", async () => {
    const result = await handleBeforeToolCall(EVENT, {
      pluginConfig: { apiKey: BROKEN_KEY, baseUrl: await closedOrigin(), enroll: false },
    });

    expect(result).toEqual({
      block: true,
      blockReason:
        "decision unavailable (Decision API unreachable: TypeError " +
        "(base URL from plugin config baseUrl)) — failing closed",
    });
  });

  it("names where the base URL came from", async () => {
    const tls = rejecting(certificateForAnotherName(HOST));
    const configured = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: KEY, baseUrl: `https://${HOST}`, enroll: false } },
      tls,
    );
    process.env.COGNEXUS_API_BASE_URL = `https://${HOST}`;
    const env = await handleBeforeToolCall(EVENT, { pluginConfig: { apiKey: KEY, enroll: false } }, tls);
    delete process.env.COGNEXUS_API_BASE_URL;
    const fallback = await handleBeforeToolCall(EVENT, { pluginConfig: { apiKey: KEY, enroll: false } }, tls);

    const reason = (source: string) =>
      "decision unavailable (Decision API unreachable: Error [ERR_TLS_CERT_ALTNAME_INVALID] " +
      `(base URL from ${source})) — failing closed`;
    expect(configured?.blockReason).toBe(reason("plugin config baseUrl"));
    expect(env?.blockReason).toBe(reason("COGNEXUS_API_BASE_URL"));
    expect(fallback?.blockReason).toBe(reason("default"));
  });

  it("does not quote a base URL's user name and password", async () => {
    const baseUrl = (await closedOrigin()).replace("//", "//someone:secretpw@");
    const result = await handleBeforeToolCall(EVENT, { pluginConfig: { apiKey: KEY, baseUrl, enroll: false } });

    expect(result).toEqual({
      block: true,
      blockReason:
        "decision unavailable (Decision API unreachable: TypeError " +
        "(base URL from plugin config baseUrl)) — failing closed",
    });
  });

  it("names an error whose properties cannot be read, and still fails closed", async () => {
    const result = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { apiKey: KEY, baseUrl: `https://${HOST}`, enroll: false } },
      rejecting(unreadable()),
    );

    expect(result).toEqual({
      block: true,
      blockReason:
        "decision unavailable (Decision API unreachable: Error " +
        "(base URL from plugin config baseUrl)) — failing closed",
    });
  });
});

describe("the announce and enroll log lines", () => {
  const CFG: PluginConfig = {
    apiKey: BROKEN_KEY,
    announce: true,
    instance: "failed-request-text",
    announceAgents: ["main"],
  };

  it("announce names the failure's kind, not the key", async () => {
    const logs: string[] = [];
    const out = await announceInstance({ ...CFG, baseUrl: await closedOrigin() }, undefined, (m) => logs.push(m));

    expect(logs).toEqual([
      "artzain announce failed: TypeError (base URL from plugin config baseUrl) " +
        "(will retry on a later gated call)",
    ]);
    expect(out).toEqual({ ok: false, reason: "TypeError", retryable: true });
  });

  it("enroll names the failure's kind, not the key", async () => {
    const logs: string[] = [];
    const out = await enrollInstance({ ...CFG, baseUrl: await closedOrigin() }, undefined, (m) => logs.push(m));

    expect(logs).toEqual([
      "artzain enroll failed: TypeError (base URL from plugin config baseUrl) " +
        "(will retry on a later gated call)",
    ]);
    expect(out).toEqual({ ok: false, reason: "TypeError", retryable: true });
  });

  it("neither names the host of a certificate for another name", async () => {
    process.env.COGNEXUS_API_BASE_URL = `https://${HOST}`;
    const logs: string[] = [];
    const tls = rejecting(certificateForAnotherName(HOST));
    const announced = await announceInstance({ ...CFG, apiKey: KEY }, tls, (m) => logs.push(m));
    const enrolled = await enrollInstance({ ...CFG, apiKey: KEY }, tls, (m) => logs.push(m));

    expect(logs).toEqual([
      "artzain announce failed: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from " +
        "COGNEXUS_API_BASE_URL) (will retry on a later gated call)",
      "artzain enroll failed: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from " +
        "COGNEXUS_API_BASE_URL) (will retry on a later gated call)",
    ]);
    expect(announced.reason).toBe("Error [ERR_TLS_CERT_ALTNAME_INVALID]");
    expect(enrolled.reason).toBe("Error [ERR_TLS_CERT_ALTNAME_INVALID]");
  });

  it("both report their own timeout as a timeout", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const logs: string[] = [];
    const cfg = { ...CFG, apiKey: KEY, baseUrl: `https://${HOST}` };
    const announced = announceInstance(cfg, hang, (m) => logs.push(m));
    await vi.advanceTimersByTimeAsync(ANNOUNCE_TIMEOUT_MS);
    const enrolled = enrollInstance(cfg, hang, (m) => logs.push(m));
    await vi.advanceTimersByTimeAsync(ENROLL_TIMEOUT_MS);

    const timedOut = "TimeoutError, aborted when the timeout passed";
    expect(await announced).toEqual({ ok: false, reason: timedOut, retryable: true });
    expect(await enrolled).toEqual({ ok: false, reason: timedOut, retryable: true });
    expect(logs).toEqual([
      `artzain announce failed: ${timedOut} (base URL from plugin config baseUrl) ` +
        "(will retry on a later gated call)",
      `artzain enroll failed: ${timedOut} (base URL from plugin config baseUrl) ` +
        "(will retry on a later gated call)",
    ]);
  });

  it("both name a baseUrl that is not a string as the config's", async () => {
    const logs: string[] = [];
    const cfg = { ...CFG, apiKey: KEY, baseUrl: 42 as unknown as string };
    const notReached = rejecting(new Error("not reached"));
    const announced = await announceInstance(cfg, notReached, (m) => logs.push(m));
    const enrolled = await enrollInstance(cfg, notReached, (m) => logs.push(m));

    expect(announced).toEqual({ ok: false, reason: "TypeError", retryable: true });
    expect(enrolled).toEqual({ ok: false, reason: "TypeError", retryable: true });
    expect(logs).toEqual([
      "artzain announce failed: TypeError (base URL from plugin config baseUrl) " +
        "(will retry on a later gated call)",
      "artzain enroll failed: TypeError (base URL from plugin config baseUrl) " +
        "(will retry on a later gated call)",
    ]);
  });
});
