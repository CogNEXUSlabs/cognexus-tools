/**
 * Connector tool names this command maps onto the decision taxonomy.
 *
 * A target is `<system>:<kind>/<id>`, for example `slack:channel/C123` or
 * `github:repo/Quantumskipper/CogNEXUS`. The id is filled from the call's
 * arguments. A name that is not listed is the action `unknown_tool`.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface ToolRow {
  action: string;
  /** `<system>:<kind>/{argument}` with the id still to fill. */
  target: string;
}

export interface TaxonomyFile {
  actions: string[];
  tools: Record<string, ToolRow>;
}

export interface ClassifiedTool {
  action: string;
  target: string;
  known: boolean;
}

const UNKNOWN_ACTION = "unknown_tool";

function taxonomyPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const beside = join(here, "taxonomy.json");
  const packaged = join(here, "..", "src", "taxonomy.json");
  for (const path of [beside, packaged]) {
    try {
      readFileSync(path);
      return path;
    } catch (err) {
      if ((err as { code?: string }).code !== "ENOENT") throw err;
    }
  }
  return beside;
}

let cached: TaxonomyFile | undefined;

/** The taxonomy file, or a problem when it cannot be read. */
export function readTaxonomy(): TaxonomyFile | { problem: string } {
  if (cached) return cached;
  try {
    const parsed = JSON.parse(readFileSync(taxonomyPath(), "utf8")) as TaxonomyFile;
    if (!parsed || !Array.isArray(parsed.actions) || !parsed.tools) {
      return { problem: "taxonomy.json could not be read" };
    }
    cached = parsed;
    return parsed;
  } catch {
    return { problem: "taxonomy.json could not be read" };
  }
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
