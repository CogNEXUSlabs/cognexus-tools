/**
 * SDK configuration — mirrors the Python SDK's resolution order
 * (`cognexus.cloud`): explicit `configure()` values win, then the
 * `COGNEXUS_API_KEY` / `MYAPP_API_KEY` / `COGNEXUS_API_BASE_URL`
 * environment variables, then the production default host.
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

export function effectiveApiKey(): string | undefined {
  return state.apiKey ?? env("COGNEXUS_API_KEY") ?? env("MYAPP_API_KEY");
}

export function effectiveBaseUrl(): string {
  const raw = state.baseUrl ?? env("COGNEXUS_API_BASE_URL") ?? DEFAULT_BASE_URL;
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
