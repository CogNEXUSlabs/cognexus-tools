/**
 * Two requests more than 4 s apart share one connection. Node's `fetch`
 * keeps an idle connection for 4 s unless the answer says how long it may be
 * kept, so the second request of a workflow that runs less often than that
 * used to open a new one and pay for the DNS lookup and the TCP and TLS
 * handshakes again: far from the engine, most of a decision's time. Both
 * nodes send their requests through `fetchWithTimeout`. The server here
 * sends no such hint, and keeps its end of the connection open, so what is
 * measured is the client's choice.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, expect, it } from "vitest";

import { fetchWithTimeout } from "./timeout.js";

/** Longer than the 4 s Node's `fetch` keeps an idle connection for. */
const QUIET_MS = 6_000;

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

it("two requests 6 s apart go out on one connection", { timeout: QUIET_MS + 10_000 }, async () => {
  const ports: number[] = []; // the client's end of each request's connection
  server = createServer((req, res) => {
    ports.push(req.socket.remotePort!);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"outcome":"allow"}');
    });
  });
  server.keepAliveTimeout = 0; // no Keep-Alive hint, and no close from this end
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const send = () =>
    fetchWithTimeout(
      `http://127.0.0.1:${(server!.address() as AddressInfo).port}/api/v1/decisions`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
      5_000,
      { what: "Decision API", baseSource: "the credential's Base URL" },
    );

  expect(await send()).toEqual({ status: 200, text: '{"outcome":"allow"}' });
  await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
  expect(await send()).toEqual({ status: 200, text: '{"outcome":"allow"}' });
  expect(ports).toHaveLength(2);
  expect(ports[1]).toBe(ports[0]);
});
