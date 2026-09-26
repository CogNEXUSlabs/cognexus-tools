/**
 * SDK configuration — mirrors the Python SDK (`artzain.credentials`). The API
 * key comes from `configure()`, then `COGNEXUS_API_KEY` / `MYAPP_API_KEY`, then
 * the profile that `artzain login` writes to `~/.artzain/credentials.toml`.
 * The host is decided with the key (`resolveCredentials`): a key goes only to
 * the host it was issued with.
 *
 * The profile is read only under Node 20.16+ / 22.3+, where
 * `process.getBuiltinModule` gives synchronous access to `node:fs` without a
 * static import that would break other runtimes. Elsewhere it is simply
 * absent, and the env var is the way in.
 */

const DEFAULT_BASE_URL = "https://app.cognexuslabs.ai";

export interface CognexusConfig {
  apiKey?: string;
  baseUrl?: string;
}

const state: CognexusConfig = {};

export function configure(config: CognexusConfig): void {
  if (config.apiKey !== undefined) state.apiKey = config.apiKey;
  if (config.baseUrl !== undefined) state.baseUrl = config.baseUrl;
}

function env(name: string): string | undefined {
  // globalThis.process keeps the module importable outside Node.
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  const v = p?.env?.[name];
  return v && v.trim() ? v.trim() : undefined;
}

/** Path of the credentials profile; `COGNEXUS_CREDENTIALS_PATH` overrides. */
export function credentialsPath(): string | undefined {
  const override = env("COGNEXUS_CREDENTIALS_PATH");
  if (override) return override;
  const home = env("HOME") ?? env("USERPROFILE");
  if (!home) return undefined;
  const sep = home.includes("\\") ? "\\" : "/";
  return `${home}${sep}.artzain${sep}credentials.toml`;
}

interface NodeFsLike {
  readFileSync(path: string, encoding: "utf8"): string;
}

function nodeFs(): NodeFsLike | undefined {
  const p = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  const get = p?.getBuiltinModule;
  if (typeof get !== "function") return undefined;
  try {
    return get.call(p, "node:fs") as NodeFsLike;
  } catch {
    return undefined;
  }
}

/**
 * The `[default]` table of `credentials.toml` — the same minimal TOML subset
 * the Python CLI writes and reads (`key = "value"` lines under a `[section]`
 * header; no dependency). `{}` when there is no file, no reader, or no
 * `[default]` table.
 */
export function readProfile(): Record<string, string> {
  const path = credentialsPath();
  const fs = nodeFs();
  if (!path || !fs) return {};
  let text: string;
  try {
    text = fs.readFileSync(path, "utf8");
  } catch {
    return {};
  }
  const tables: Record<string, Record<string, string>> = { default: {} };
  let section = "default";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1).trim() || "default";
      tables[section] ??= {};
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    (tables[section] ??= {})[key] = val;
  }
  return tables.default ?? {};
}

function profileValue(key: string): string | undefined {
  const v = readProfile()[key];
  return v && v.trim() ? v.trim() : undefined;
}

function trimSlashes(raw: string): string {
  // Scanned rather than trimmed with /\/+$/, which backtracks quadratically
  // on a value made up mostly of slashes.
  let end = raw.length;
  while (end > 0 && raw.charCodeAt(end - 1) === 47) end--;
  return raw.slice(0, end);
}

/** Label for the profile. Messages name sources, never values. */
const PROFILE_SOURCE = "credentials profile";

/**
 * The host that is set is not the host the API key was issued with. Nothing
 * was sent; the message names the settings involved, never their values.
 */
export class CredentialConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialConflictError";
  }
}

/** An API key and the host it goes to, decided together. Sources are labels. */
export interface ResolvedCredentials {
  apiKey?: string;
  baseUrl: string;
  keySource: string;
  baseSource: string;
}

/**
 * Pick the API key, then the host it may be sent to — the same rule as the
 * Python SDK's `artzain.credentials.resolve_credentials`.
 *
 * A key read from the profile goes to the profile's `base_url`, and so does a
 * `configure()` or environment key equal to it. The profile's host is never
 * used with any other key: that goes to `configure({ baseUrl })`, then
 * `COGNEXUS_API_BASE_URL`, then the production default. A profile without
 * `base_url` records no host. With no key at all the profile's host may name
 * the default, since nothing is sent.
 *
 * @throws CredentialConflictError when `configure({ baseUrl })` or
 *   `COGNEXUS_API_BASE_URL` names a host other than the key's.
 */
export function resolveCredentials(): ResolvedCredentials {
  let named: string | undefined;
  let namedSource = "";
  if (state.baseUrl !== undefined) {
    named = trimSlashes(state.baseUrl);
    namedSource = "configure({ baseUrl })";
  } else if (env("COGNEXUS_API_BASE_URL") !== undefined) {
    named = trimSlashes(env("COGNEXUS_API_BASE_URL") as string);
    namedSource = "COGNEXUS_API_BASE_URL";
  }

  const profileKey = profileValue("api_key");
  const rawProfileBase = profileValue("base_url");
  const profileBase = rawProfileBase ? trimSlashes(rawProfileBase) || undefined : undefined;

  let apiKey: string | undefined;
  let keySource = "none";
  if (state.apiKey) {
    apiKey = state.apiKey;
    keySource = "configure({ apiKey })";
  } else if (env("COGNEXUS_API_KEY")) {
    apiKey = env("COGNEXUS_API_KEY");
    keySource = "COGNEXUS_API_KEY";
  } else if (env("MYAPP_API_KEY")) {
    apiKey = env("MYAPP_API_KEY");
    keySource = "MYAPP_API_KEY";
  } else if (profileKey) {
    apiKey = profileKey;
    keySource = PROFILE_SOURCE;
  }

  if (apiKey === undefined) {
    if (named !== undefined) return { baseUrl: named, keySource, baseSource: namedSource };
    if (profileBase) return { baseUrl: profileBase, keySource, baseSource: PROFILE_SOURCE };
    return { baseUrl: DEFAULT_BASE_URL, keySource, baseSource: "default" };
  }

  // The profile records which host issued its key; that key goes nowhere
  // else, however it was supplied.
  if (profileKey && profileBase && apiKey === profileKey) {
    if (named !== undefined && named.toLowerCase() !== profileBase.toLowerCase()) {
      throw new CredentialConflictError(
        `Not sent: ${namedSource} names a different host from the one the API key ` +
          `from ${keySource} was issued with (recorded in ${PROFILE_SOURCE}). Set ` +
          "COGNEXUS_API_KEY to a key for that host, run `artzain login` against it, " +
          `or unset ${namedSource}.`,
      );
    }
    return { apiKey, baseUrl: profileBase, keySource, baseSource: PROFILE_SOURCE };
  }
  if (named !== undefined) return { apiKey, baseUrl: named, keySource, baseSource: namedSource };
  return { apiKey, baseUrl: DEFAULT_BASE_URL, keySource, baseSource: "default" };
}

/** The resolved API key; `undefined` when there is none or the settings conflict. */
export function effectiveApiKey(): string | undefined {
  try {
    return resolveCredentials().apiKey;
  } catch {
    return undefined;
  }
}

/**
 * The host the resolved API key goes to. When the settings conflict, the
 * host that was named, else the default; nothing is sent in that case.
 */
export function effectiveBaseUrl(): string {
  try {
    return resolveCredentials().baseUrl;
  } catch {
    const named = state.baseUrl ?? env("COGNEXUS_API_BASE_URL") ?? DEFAULT_BASE_URL;
    return trimSlashes(named);
  }
}

export function hasApiKey(): boolean {
  return effectiveApiKey() !== undefined;
}

/** Test seam — reset module state between test cases. */
export function _resetConfigForTests(): void {
  delete state.apiKey;
  delete state.baseUrl;
}
