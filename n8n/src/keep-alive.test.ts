/**
 * The kept pool is used only while Node's default pool is as Node made it,
 * and never when switched off. What it saves, a connection between two
 * decisions more than 4 s apart, is shown by each package's own test of its
 * requests (`kept-connection.test.ts`).
 *
 * This file and `keep-alive.ts` are the same in the OpenClaw plugin and the
 * n8n nodes; the last test fails when the copies differ.
 */

import { readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { KEEP_ALIVE_MS, keepAliveDispatcher, keptFetch } from "./keep-alive.js";

const DEFAULT_POOL = Symbol.for("undici.globalDispatcher.1");
const host = globalThis as unknown as Record<symbol, unknown>;

// Reading `Headers` makes Node install its default pool, as a request would.
void globalThis.Headers;
const nodeDefault = host[DEFAULT_POOL] as object;
const Agent = nodeDefault.constructor as new (options?: object) => object;

/** Runs `body` with `pool` installed as the default, then puts Node's back. */
function withDefault<T>(pool: unknown, body: () => T): T {
  host[DEFAULT_POOL] = pool;
  try {
    return body();
  } finally {
    host[DEFAULT_POOL] = nodeDefault;
  }
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("on Node's default pool", () => {
  it("hands out one pool that keeps connections, built from the default's class", () => {
    // Fails if a Node release changes the internals the check reads: the
    // requests would then go out as before, without keep-alive.
    const pool = keepAliveDispatcher();
    expect(pool).toBeInstanceOf(Agent);
    expect(pool).not.toBe(nodeDefault);
    expect(keepAliveDispatcher()).toBe(pool);
    expect(KEEP_ALIVE_MS).toBe(60_000);
  });

  it.each(["0", "false", "no", "OFF", " 0 "])("is switched off by COGNEXUS_KEEP_ALIVE=%j", (value) => {
    vi.stubEnv("COGNEXUS_KEEP_ALIVE", value);
    expect(keepAliveDispatcher()).toBeUndefined();
  });

  it.each(["1", "true", ""])("stays on with COGNEXUS_KEEP_ALIVE=%j", (value) => {
    vi.stubEnv("COGNEXUS_KEEP_ALIVE", value);
    expect(keepAliveDispatcher()).toBeInstanceOf(Agent);
  });
});

describe("a default the host replaced is left alone", () => {
  it.each([
    ["its own certificate authority", { connect: { ca: "-----BEGIN CERTIFICATE-----" } }],
    ["its own keep-alive", { keepAliveTimeout: 1_000 }],
    ["its own connection limit", { connections: 4 }],
  ])("an Agent with %s", (_what, options) => {
    expect(withDefault(new Agent(options), keepAliveDispatcher)).toBeUndefined();
  });

  it("an Agent with its own factory", () => {
    const factory = (): never => {
      throw new Error("not called");
    };
    expect(withDefault(new Agent({ factory }), keepAliveDispatcher)).toBeUndefined();
  });

  it.each(["ProxyAgent", "EnvHttpProxyAgent", "MockAgent"])("a %s", (name) => {
    const Other = { [name]: class {} }[name]!;
    expect(withDefault(new Other(), keepAliveDispatcher)).toBeUndefined();
  });

  it("one whose internals throw when read", () => {
    const hostile = new Proxy(new Agent(), {
      ownKeys() {
        throw new Error("no");
      },
    });
    expect(withDefault(hostile, keepAliveDispatcher)).toBeUndefined();
  });

  it("no default pool at all", () => {
    expect(withDefault({}, keepAliveDispatcher)).toBeUndefined();
  });

  it("and the kept pool comes back once Node's default is", () => {
    const pool = keepAliveDispatcher();
    withDefault(new Agent({ connect: { ca: "x" } }), () => {
      expect(keepAliveDispatcher()).toBeUndefined();
    });
    expect(keepAliveDispatcher()).toBe(pool);
  });
});

describe("keptFetch", () => {
  const init: RequestInit = { method: "POST", body: "{}", redirect: "manual" };

  it("adds the kept pool to the init and passes the rest through", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    await keptFetch("https://engine.example/api/v1/decisions", init);
    expect(fetch).toHaveBeenCalledWith("https://engine.example/api/v1/decisions", {
      ...init,
      dispatcher: keepAliveDispatcher(),
    });
  });

  it("passes the init untouched when there is no kept pool", async () => {
    vi.stubEnv("COGNEXUS_KEEP_ALIVE", "0");
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    await keptFetch("https://engine.example/api/v1/decisions", init);
    expect(fetch.mock.calls[0]![1]).toBe(init);
  });

  it("rejects as fetch does", async () => {
    const failure = new TypeError("fetch failed");
    vi.spyOn(globalThis, "fetch").mockRejectedValue(failure);
    await expect(keptFetch("https://engine.example/", init)).rejects.toBe(failure);
  });
});

describe("the copies", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  // openclaw/src and n8n/src sit side by side, here under sdk/ and on the mirror.
  const sibling = basename(dirname(here)) === "openclaw" ? "n8n" : "openclaw";
  const read = (dir: string, file: string): string =>
    readFileSync(join(dir, file), "utf8").replace(/\r\n/g, "\n");

  it.each(["keep-alive.ts", "keep-alive.test.ts"])("%s is the same in both packages", (file) => {
    expect(read(here, file)).toBe(read(join(here, "..", "..", sibling, "src"), file));
  });
});
