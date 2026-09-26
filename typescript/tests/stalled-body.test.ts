/**
 * The timeout covers the response body as well as the headers. It used to be
 * cleared once the headers arrived, so a server that sent them and then
 * stalled mid-body hung the call for good. These tests run the default global
 * fetch against a local server that does exactly that.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { configure, decide, DecisionError, fetchApiKeyIdentity } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";

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

afterEach(async () => {
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
    const err = await decide({ action: "a", target: "t", payload: "p", timeoutMs: 100 }).catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("could not be read");
    expect(err.message).toContain("timeout");
    expect(err.message).not.toContain("non-JSON");
  }, 3_000);

  it("decide() times out reading a 503 body and still reports the status", async () => {
    configure({ apiKey: "cnx_test", baseUrl: await stallingServer(503) });
    const err = await decide({ action: "a", target: "t", payload: "p", timeoutMs: 100 }).catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(503);
    expect(err.detail).toBeUndefined();
  }, 3_000);

  it("fetchApiKeyIdentity() times out reading the body and throws DecisionError", async () => {
    configure({ apiKey: "cnx_test", baseUrl: await stallingServer(200) });
    const err = await fetchApiKeyIdentity({ timeoutMs: 100 }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("could not be read");
  }, 3_000);
});
