/**
 * The W15 tool taxonomy: a connector tool name becomes one action and one
 * target. The action is what a policy rule matches. The target is
 * `<system>:<kind>/<id>`, for example `slack:channel/C123` or
 * `github:repo/acme/inventory`.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const UNKNOWN_ACTION = "unknown_tool";

export interface ClassifiedTool {
  action: string;
  target: string;
  known: boolean;
}

interface ToolRow {
  action: string;
  target: string;
}

interface TaxonomyFile {
  actions: string[];
  tools: Record<string, ToolRow>;
}

type Loaded = TaxonomyFile | { problem: string };

let cached: Loaded | undefined;

function readTaxonomy(): Loaded {
  if (cached) return cached;
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "taxonomy.json"), join(here, "..", "src", "taxonomy.json")];
  for (const path of candidates) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as TaxonomyFile;
      if (!parsed || !Array.isArray(parsed.actions) || !parsed.tools) {
        cached = { problem: "taxonomy.json is not a tool map" };
        return cached;
      }
      cached = parsed;
      return cached;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        cached = { problem: code ?? "unreadable" };
        return cached;
      }
    }
  }
  cached = { problem: "ENOENT" };
  return cached;
}

function fill(template: string, args: Record<string, string>): string {
  const filled = template.replace(/\{([A-Za-z0-9_]+)\}/g, (_match, key: string) => args[key] ?? "");
  return filled.replace(/\/+$/, "");
}

/**
 * The action and target for a connector tool name. `args` fills the id in
 * the target template. An unknown name is `unknown_tool` and
 * `unknown:tool/<name>`.
 */
export function classifyTool(name: string, args: Record<string, string> = {}): ClassifiedTool {
  const taxonomy = readTaxonomy();
  const raw = name.trim();
  if ("problem" in taxonomy) {
    return { action: UNKNOWN_ACTION, target: `unknown:tool/${raw}`, known: false };
  }
  const row = taxonomy.tools[raw.toLowerCase()];
  if (!row) {
    return { action: UNKNOWN_ACTION, target: `unknown:tool/${raw}`, known: false };
  }
  return { action: row.action, target: fill(row.target, args), known: true };
}
