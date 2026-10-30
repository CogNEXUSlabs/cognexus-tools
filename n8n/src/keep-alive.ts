/**
 * Keep the connection to the Decision API between decisions.
 *
 * Node's built-in `fetch` keeps an idle connection for 4 s, unless the answer
 * says how long it may be kept. A decision on a new connection pays for the
 * DNS lookup and the TCP and TLS handshakes before its request, and far from
 * the engine that is most of its time. So the requests here go through a pool
 * that keeps an idle connection for 60 s, as the Python SDK does.
 *
 * The package takes no dependency, so the pool is built from the class of
 * Node's own default pool, the one the built-in `fetch` uses. It is used only
 * while that default is as Node made it. A host that replaced it keeps its
 * own: a proxy (`NODE_USE_ENV_PROXY`, a `ProxyAgent`), its own certificate
 * authority, any option at all. So does every request when
 * `COGNEXUS_KEEP_ALIVE` is `0`, and every request on a runtime other than
 * Node. Those requests go out exactly as they did before.
 *
 * This file is the same in the OpenClaw plugin and the n8n nodes;
 * `keep-alive.test.ts` fails when the copies differ.
 */

/** How long an idle connection is kept, as in the Python SDK. */
export const KEEP_ALIVE_MS = 60_000;
/** The most a server's `Keep-Alive: timeout=` hint can stretch that to. */
export const KEEP_ALIVE_MAX_MS = 600_000;

/** Where undici, the library behind Node's `fetch`, keeps the default pool. */
const DEFAULT_POOL = Symbol.for("undici.globalDispatcher.1");

let kept: { base: object; pool: object } | undefined;

function switchedOff(): boolean {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env;
  const raw = (env?.COGNEXUS_KEEP_ALIVE ?? "").trim().toLowerCase();
  return raw === "0" || raw === "false" || raw === "no" || raw === "off";
}

/** The own property of `value` keyed by the symbol `description` names. */
function internal(value: object, description: string): unknown {
  const key = Object.getOwnPropertySymbols(value).find((s) => s.description === description);
  return key === undefined ? undefined : (value as Record<symbol, unknown>)[key];
}

/**
 * Whether `pool` is undici's `Agent` as Node builds it: no options, the
 * default factory. A pool the host built itself, or anything else, is not.
 */
function asNodeMadeIt(pool: unknown): pool is object {
  if (typeof pool !== "object" || pool === null || pool.constructor?.name !== "Agent") {
    return false;
  }
  const options = internal(pool, "options");
  const factory = internal(pool, "factory");
  return (
    typeof options === "object" &&
    options !== null &&
    Object.values(options).every((v) => v === undefined) &&
    typeof factory === "function" &&
    factory.name === "defaultFactory"
  );
}

/**
 * The pool that keeps connections for `KEEP_ALIVE_MS`, for `fetch`'s
 * `dispatcher` option; undefined when the request should go out as it would
 * without it (see the top of this file).
 */
export function keepAliveDispatcher(): object | undefined {
  try {
    if (switchedOff()) return undefined;
    const host = globalThis as Record<symbol, unknown> & { Headers?: unknown };
    // Node loads undici, which installs the default pool, the first time
    // `fetch` is called or `Headers` is read. Reading it here lets the
    // first decision take the kept pool too, rather than the second
    // decision opening a connection of its own.
    if (!(DEFAULT_POOL in host)) void host.Headers;
    const base = host[DEFAULT_POOL];
    if (!asNodeMadeIt(base)) return undefined;
    if (kept?.base !== base) {
      const Agent = base.constructor as new (options: object) => object;
      kept = {
        base,
        pool: new Agent({ keepAliveTimeout: KEEP_ALIVE_MS, keepAliveMaxTimeout: KEEP_ALIVE_MAX_MS }),
      };
    }
    return kept.pool;
  } catch {
    // An internal that throws when read, or a class that will not build:
    // the request goes out on the host's own pool.
    return undefined;
  }
}

/**
 * The global `fetch`, on the kept pool when there is one. `init` is passed
 * through as it is otherwise: `redirect`, `signal` and errors are the
 * caller's, as with `fetch` itself.
 */
export function keptFetch(input: string, init: RequestInit): Promise<Response> {
  const dispatcher = keepAliveDispatcher();
  return globalThis.fetch(input, dispatcher ? ({ ...init, dispatcher } as RequestInit) : init);
}
