/**
 * A failed request is reported without its error's text.
 *
 * `decide()` and `fetchApiKeyIdentity()` threw a DecisionError whose message
 * quoted the error the request failed with. That text can carry what a log
 * must not: fetch quotes a header value it refuses, so an API key pasted with
 * a line break was quoted in full, and it quotes a base URL that holds a user
 * name and password. The message now names the error's kind (for fetch's
 * "fetch failed", its cause's, whose text is left out too: a certificate
 * issued for another name puts the host in it) and where the base URL came
 * from, and the error is not kept as the DecisionError's cause, which a
 * logger prints too. A body that is not JSON is reported without the
 * parser's text, which quotes the body.
 */

import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { configure, decide, DecisionError, fetchApiKeyIdentity } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const KEY = "cnx_failed_request_text_0123456789abcdef";
/** A key pasted with a line break: fetch refuses it and quotes both halves. */
const HEAD = "cnx_failed_request_head_0123456789";
const TAIL = "tail_abcdefghijklmnopqrstuvwxyz";
const HOST = "tenant-host.example.test";
const CONFIGURED = "configure({ baseUrl })";

const ENV = ["COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL", "COGNEXUS_CREDENTIALS_PATH"];

let server: Server | undefined;

beforeEach(() => {
  for (const name of ENV) delete process.env[name];
  // No profile: the machine's own `artzain login` must not decide the host.
  process.env.COGNEXUS_CREDENTIALS_PATH = join(tmpdir(), "artzain-no-profile", "credentials.toml");
});

afterEach(async () => {
  _resetConfigForTests();
  for (const name of ENV) delete process.env[name];
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

/** Settles only when the call's own AbortSignal fires, rejecting with the transport's own error. */
const hang: FetchLike = (_url, init) =>
  new Promise((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(new Error(`socket to ${HOST} aborted`)));
  });

interface Surface {
  name: string;
  call(options?: { fetchImpl?: FetchLike; timeoutMs?: number }): Promise<unknown>;
  /** How the message begins when no answer came back. */
  unreachable: string;
  /** How the message begins when an answer came back. */
  answered: string;
}

const SURFACES: Surface[] = [
  {
    name: "decide()",
    call: (options) =>
      decide({ action: "send_email", target: "crm:contact:1", payload: "hello", ...options }),
    unreachable: "Decision API unreachable",
    answered: "Decision API returned",
  },
  {
    name: "fetchApiKeyIdentity()",
    call: (options) => fetchApiKeyIdentity(options),
    unreachable: "Key validation unreachable",
    answered: "Key validation returned",
  },
];

async function failure(surface: Surface, options?: Parameters<Surface["call"]>[0]): Promise<DecisionError> {
  const err = await surface.call(options).then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(DecisionError);
  return err as DecisionError;
}

/** Everything a logger shows for the error: `console.error` prints `inspect`. */
function printed(err: DecisionError): string {
  return `${String(err)}\n${err.stack ?? ""}\n${inspect(err, { depth: 8 })}`;
}

describe.each(SURFACES)("$name", (surface) => {
  it("does not quote an API key fetch refuses to send", async () => {
    configure({ apiKey: `${HEAD}\n${TAIL}`, baseUrl: await closedOrigin() });
    const err = await failure(surface);

    expect(err.message).toBe(`${surface.unreachable}: TypeError (base URL from ${CONFIGURED})`);
    expect(err.status).toBeUndefined();
    const text = printed(err);
    expect(text).not.toContain(HEAD);
    expect(text).not.toContain(TAIL);
  });

  it("does not quote a base URL's user name and password", async () => {
    // fetch refuses a URL with credentials in it, and quotes the URL.
    configure({ apiKey: KEY, baseUrl: (await closedOrigin()).replace("//", "//someone:secretpw@") });
    const err = await failure(surface);

    expect(err.message).toBe(`${surface.unreachable}: TypeError (base URL from ${CONFIGURED})`);
    expect(printed(err)).not.toContain("secretpw");
  });

  it("names the kind of a refused connection, not where it was refused", async () => {
    const origin = await closedOrigin();
    configure({ apiKey: KEY, baseUrl: origin });
    const err = await failure(surface);

    expect(err.message).toBe(
      `${surface.unreachable}: Error [ECONNREFUSED] (base URL from ${CONFIGURED})`,
    );
    expect(printed(err)).not.toContain(origin.slice("http://".length));
  });

  it("names a certificate for another name by its cause's kind, without the host", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const err = await failure(surface, { fetchImpl: rejecting(certificateForAnotherName(HOST)) });

    expect(err.message).toBe(
      `${surface.unreachable}: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from ${CONFIGURED})`,
    );
    expect(printed(err)).not.toContain(HOST);
  });

  it("does not quote a transport's own error either", async () => {
    // A custom transport that rejects with the TLS error itself, unwrapped.
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const tls = certificateForAnotherName(HOST).cause;
    const err = await failure(surface, { fetchImpl: rejecting(tls) });

    expect(err.message).toBe(
      `${surface.unreachable}: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from ${CONFIGURED})`,
    );
    expect(printed(err)).not.toContain(HOST);
  });

  it("keeps neither the error nor its cause on the DecisionError", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const err = await failure(surface, { fetchImpl: rejecting(certificateForAnotherName(HOST)) });

    expect(Object.prototype.hasOwnProperty.call(err, "cause")).toBe(false);
    expect(Object.keys(err).sort()).toEqual(["detail", "name", "status"].sort());
  });

  it("names where the base URL came from", async () => {
    process.env.COGNEXUS_API_BASE_URL = `https://${HOST}`;
    configure({ apiKey: KEY });
    const env = await failure(surface, { fetchImpl: rejecting(certificateForAnotherName(HOST)) });
    expect(env.message).toBe(
      `${surface.unreachable}: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from COGNEXUS_API_BASE_URL)`,
    );

    delete process.env.COGNEXUS_API_BASE_URL;
    const fallback = await failure(surface, { fetchImpl: rejecting(certificateForAnotherName(HOST)) });
    expect(fallback.message).toBe(
      `${surface.unreachable}: Error [ERR_TLS_CERT_ALTNAME_INVALID] (base URL from default)`,
    );
  });

  it("reports its own timeout as a timeout, whatever the transport rejected with", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const err = await failure(surface, { fetchImpl: hang, timeoutMs: 20 });

    expect(err.message).toBe(
      `${surface.unreachable}: TimeoutError, aborted when the timeout passed (base URL from ${CONFIGURED})`,
    );
    expect(printed(err)).not.toContain(HOST);
  }, 2_000);

  it("does not name an error by a name or code that is not an identifier", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const odd = Object.assign(new Error("x"), { name: `refused by ${HOST}`, code: `at ${HOST}` });
    const err = await failure(surface, { fetchImpl: rejecting(odd) });

    expect(err.message).toBe(`${surface.unreachable}: Error (base URL from ${CONFIGURED})`);
    for (const thrown of [undefined, null, `down at ${HOST}`, 42]) {
      const other = await failure(surface, { fetchImpl: rejecting(thrown) });
      expect(other.message).toBe(`${surface.unreachable}: Error (base URL from ${CONFIGURED})`);
    }
  });

  it("uses a name or code only when the whole of it is an identifier", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const names = [`Refused by ${HOST}`, `${HOST} Refused`, KEY, `E${"x".repeat(64)}`];
    const codes = [`ENOTFOUND ${HOST}`, `ENOTFOUND ${HOST.toUpperCase()}`, `ERR_${KEY}`, `E${"X".repeat(64)}`];
    const odd = [
      ...names.map((name) => Object.assign(new Error("x"), { name })),
      ...codes.map((code) => Object.assign(new Error("x"), { code })),
    ];
    for (const error of odd) {
      const err = await failure(surface, { fetchImpl: rejecting(error) });
      expect(err.message).toBe(`${surface.unreachable}: Error (base URL from ${CONFIGURED})`);
    }
  });

  it("names an error whose properties cannot be read as Error", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const err = await failure(surface, { fetchImpl: rejecting(unreadable()) });

    expect(err.message).toBe(`${surface.unreachable}: Error (base URL from ${CONFIGURED})`);
  });

  it("names the cause only of a TypeError, only a cause that is an object, and only one level", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const cause = Object.assign(new Error(`getaddrinfo ENOTFOUND ${HOST}`), { code: "ENOTFOUND" });
    const cases: Array<[unknown, string]> = [
      [new RangeError("x", { cause }), "RangeError"],
      [new TypeError("fetch failed", { cause: `getaddrinfo ENOTFOUND ${HOST}` }), "TypeError"],
      [new TypeError("fetch failed", { cause: new TypeError("inner", { cause }) }), "TypeError"],
    ];
    for (const [error, kind] of cases) {
      const err = await failure(surface, { fetchImpl: rejecting(error) });
      expect(err.message).toBe(`${surface.unreachable}: ${kind} (base URL from ${CONFIGURED})`);
    }
  });

  it("does not quote a body that is not JSON", async () => {
    // A 200 that echoes what it was sent, as a misrouted request can get.
    const echo = await serve((req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(String(req.headers["x-api-key"]));
    });
    configure({ apiKey: KEY, baseUrl: echo });
    const err = await failure(surface);

    expect(err.message).toBe(`${surface.answered} HTTP 200 with a non-JSON body`);
    expect(err.status).toBe(200);
    expect(printed(err)).not.toContain(KEY.slice(0, 8));
  });

  it("names the kind of a body that could not be read", async () => {
    const dropped = await serve((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"outcome":');
      setTimeout(() => res.socket?.destroy(), 20);
    });
    configure({ apiKey: KEY, baseUrl: dropped });
    const err = await failure(surface);

    expect(err.message).toBe(
      `${surface.answered} HTTP 200 but its body could not be read: SocketError [UND_ERR_SOCKET]`,
    );
    expect(err.status).toBe(200);
  });

  it("reports a body read that fails after its own timeout as that timeout, whatever it rejected with", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const errors = [() => new Error(`socket to ${HOST} closed`), () => new SyntaxError("Unexpected end of JSON input")];
    for (const bodyError of errors) {
      const err = await failure(surface, { fetchImpl: bodyFailsAtDeadline(bodyError), timeoutMs: 20 });
      expect(err.message).toBe(
        `${surface.answered} HTTP 200 but its body could not be read: ` +
          "TimeoutError, aborted when the timeout passed",
      );
    }
  }, 2_000);

  it("names a body error whose properties cannot be read as Error", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const err = await failure(surface, { fetchImpl: bodyFails(unreadable()) });

    expect(err.message).toBe(`${surface.answered} HTTP 200 but its body could not be read: Error`);
  });
});

describe("decide()", () => {
  it("reports a context that does not serialize as its own, before anything is sent", async () => {
    configure({ apiKey: KEY, baseUrl: `https://${HOST}` });
    const calls: string[] = [];
    const err = await decide({
      action: "send_email",
      target: "crm:contact:1",
      payload: "hello",
      context: { attempt: 1n },
      fetchImpl: async (url) => {
        calls.push(url);
        throw new Error("not reached");
      },
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(DecisionError);
    // The text is V8's, and describes the caller's data.
    expect((err as DecisionError).message).toBe(
      "Decision request not sent: it does not serialize to JSON: Do not know how to serialize a BigInt",
    );
    expect(calls).toEqual([]);
  });
});
