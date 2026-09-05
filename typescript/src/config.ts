/**
 * SDK configuration — mirrors the Python SDK's resolution order
 * (`artzain.cloud` + `artzain.credentials`): explicit `configure()` values
 * win, then the `COGNEXUS_API_KEY` / `MYAPP_API_KEY` /
 * `COGNEXUS_API_BASE_URL` environment variables, then the profile that
 * `artzain login` writes to `~/.artzain/credentials.toml`, then the
 * production default host.
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

export function effectiveApiKey(): string | undefined {
  return (
    state.apiKey ?? env("COGNEXUS_API_KEY") ?? env("MYAPP_API_KEY") ?? profileValue("api_key")
  );
}

export function effectiveBaseUrl(): string {
  const raw =
    state.baseUrl ?? env("COGNEXUS_API_BASE_URL") ?? profileValue("base_url") ?? DEFAULT_BASE_URL;
  // Scanned rather than trimmed with /\/+$/, which backtracks quadratically
  // on a value made up mostly of slashes.
  let end = raw.length;
  while (end > 0 && raw.charCodeAt(end - 1) === 47) end--;
  return raw.slice(0, end);
}

export function hasApiKey(): boolean {
  return effectiveApiKey() !== undefined;
}

/** Test seam — reset module state between test cases. */
export function _resetConfigForTests(): void {
  delete state.apiKey;
  delete state.baseUrl;
}
