/**
 * The host's profiles, read as agent ids only.
 *
 * Each agent is a directory under `<sand-data>/agents/<id>/`. The current
 * profile is `agents/active-agent.json`'s `activeAgentId`. `profile.json`
 * holds a description, so it is not read. `gateway.json` is not read.
 *
 * The root is `SAND_DATA_ROOT` when that is an absolute path, otherwise
 * `SAND_USER_DATA_DIR/sand-data`, otherwise `/home/box/sand-data`.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

const DEFAULT_SAND_ROOT = "/home/box/sand-data";

export function resolveSandRoot(env: NodeJS.ProcessEnv = process.env): string {
  const dataRoot = env.SAND_DATA_ROOT?.trim();
  if (dataRoot && isAbsolute(dataRoot)) return dataRoot;
  const userData = env.SAND_USER_DATA_DIR?.trim();
  if (userData) {
    const base = isAbsolute(userData) ? userData : resolve(userData);
    return join(base, "sand-data");
  }
  return DEFAULT_SAND_ROOT;
}

/** A folder name the host accepts as an agent id: no traversal, no surrounding space. */
export function isValidSandAgentId(agentId: string): boolean {
  return (
    agentId.length > 0 &&
    agentId === agentId.trim() &&
    !agentId.includes("/") &&
    !agentId.includes("\\") &&
    !agentId.includes("\0") &&
    agentId !== "." &&
    agentId !== ".."
  );
}

function agentsDir(sandRoot: string): string {
  return join(sandRoot, "agents");
}

/** Every profile's agent id, sorted. A missing directory is an empty list. */
export function listProfileAgentIds(sandRoot: string): string[] {
  let names: string[];
  try {
    names = readdirSync(agentsDir(sandRoot));
  } catch {
    return [];
  }
  const ids: string[] = [];
  for (const id of names) {
    if (!isValidSandAgentId(id)) continue;
    try {
      if (!statSync(join(agentsDir(sandRoot), id)).isDirectory()) continue;
    } catch {
      continue;
    }
    ids.push(id);
  }
  return ids.sort((a, b) => a.localeCompare(b));
}

/** The current profile's agent, when that directory is on disk. */
export function readActiveProfileAgent(sandRoot: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(join(agentsDir(sandRoot), "active-agent.json"), "utf8"));
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;
  const id = (parsed as { activeAgentId?: unknown }).activeAgentId;
  if (typeof id !== "string" || !isValidSandAgentId(id)) return undefined;
  try {
    if (!statSync(join(agentsDir(sandRoot), id)).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  return id;
}

export function selectAnnounceAgents(input: {
  allProfiles: boolean;
  /** `GROKBOT_ANNOUNCE_AGENTS`, already split. Kept when `--all-profiles` is absent. */
  announceAgents?: string[];
  /** `--agent-did`, `GROKBOT_AGENT_ID`, or `COGNEXUS_AGENT_DID`. */
  configuredAgent?: string;
  sandRoot: string;
}): { agents: string[]; problem?: string } {
  if (input.allProfiles) {
    const agents = listProfileAgentIds(input.sandRoot);
    if (agents.length === 0) {
      return { agents: [], problem: "artzain announce skipped: no profiles on this host" };
    }
    return { agents };
  }
  if (input.announceAgents && input.announceAgents.length > 0) {
    return { agents: input.announceAgents };
  }
  const configured = input.configuredAgent?.trim();
  if (configured) return { agents: [configured] };
  const active = readActiveProfileAgent(input.sandRoot);
  if (active) return { agents: [active] };
  return { agents: ["grokbot-agent"] };
}
