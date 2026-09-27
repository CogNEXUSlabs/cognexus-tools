/**
 * The timeout covers the response body as well as the headers. It used to be
 * cleared once the headers arrived, so a server that sent them and then
 * stalled mid-body hung the call for good. These tests run the default global
 * fetch against a local server that does exactly that.
 *
 * The deadline runs on a fake clock (setTimeout and clearTimeout only; fetch
 * and the server do real I/O) that moves only once the client has the
 * headers and the SDK is reading the body. On the real clock the deadline
 * could pass before the headers arrived (a cold runner paying for the first
 * fetch and connection), and the call then failed as unreachable, with no
 * status and nothing shown about the body.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { configure, decide, DecisionError, fetchApiKeyIdentity } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";

const TIMEOUT_MS = 100;

let server: Server | undefined;

/** A server that sends `status` and its headers, starts a JSON body, then goes quiet. */
async function stallingServer(status: number): Promise<string> {
  server = createServer((_req, res) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.write('{"outcome":');
  });
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/**
 * Starts `call` with the clock stopped and moves it past the deadline only
 * once the response headers are in. Resolves with what `call` threw.
 */
async function pastTheDeadline(call: () => Promise<unknown>): Promise<unknown> {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const realFetch = globalThis.fetch;
  let headersIn!: () => void;
  const headers = new Promise<void>((resolve) => (headersIn = resolve));
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const resp = await realFetch(input, init);
    headersIn();
    return resp;
  });
  const settled = call().catch((e: unknown) => e);
  await Promise.race([headers, settled]);
  // Only microtasks lie between fetch resolving and the SDK starting on the
  // body, so a macrotask later it is waiting on the body alone.
  await new Promise((resolve) => setImmediate(resolve));
  await vi.advanceTimersByTimeAsync(TIMEOUT_MS);
  return settled;
}

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  _resetConfigForTests();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

describe("a body that stalls after the headers", () => {
  it("decide() times out reading a 200 body and throws DecisionError", async () => {
    configure({ apiKey: "cnx_test", baseUrl: await stallingServer(200) });
    const err = (await pastTheDeadline(() =>
      decide({ action: "a", target: "t", payload: "p", timeoutMs: TIMEOUT_MS }),
    )) as DecisionError;
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("could not be read");
    expect(err.message).toContain("timeout");
    expect(err.message).not.toContain("non-JSON");
  }, 3_000);

  it("decide() times out reading a 503 body and still reports the status", async () => {
    configure({ apiKey: "cnx_test", baseUrl: await stallingServer(503) });
    const err = (await pastTheDeadline(() =>
      decide({ action: "a", target: "t", payload: "p", timeoutMs: TIMEOUT_MS }),
    )) as DecisionError;
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(503);
    expect(err.detail).toBeUndefined();
  }, 3_000);

  it("fetchApiKeyIdentity() times out reading the body and throws DecisionError", async () => {
    configure({ apiKey: "cnx_test", baseUrl: await stallingServer(200) });
    const err = (await pastTheDeadline(() =>
      fetchApiKeyIdentity({ timeoutMs: TIMEOUT_MS }),
    )) as DecisionError;
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("could not be read");
  }, 3_000);
});
