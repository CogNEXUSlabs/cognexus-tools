/**
 * Ask for a decision, then exec the real binary by absolute path.
 * Log-only records the decision and always runs. Enforce runs only on
 * allow. Any other outcome exits 126 and the binary is not started.
 * Arguments stay out of stderr: a reason is the decision's reason, or a
 * failure kind, never the command line.
 */

import { spawn } from "node:child_process";

import { appendActionLine, defaultShimLog } from "../coverage.js";
import { failureKind, postDecision, resolveApiKey, resolveBaseUrlSetting } from "../client.js";
import { readProfile, type ShimMode } from "../profile.js";
import { planShim, type ShimContext } from "./parse.js";
import { findRealBinary } from "./which.js";
import { readManifest } from "./install.js";

export const BLOCKED = 126;

export interface ShimDecision {
  outcome: string;
  reason: string;
  decisionId?: string;
  agent?: string;
}

export interface ShimAction {
  at: string;
  agent: string;
  action: string;
  target: string;
  decision_id: string;
}

export interface RunDeps {
  decide: (target: string, argv: string[]) => Promise<ShimDecision>;
  findBinary: (name: string) => string | undefined;
  spawnPath: (file: string, args: string[]) => Promise<number>;
  mode: ShimMode;
  stderr: (line: string) => void;
  /** Called only when the real binary is about to run. */
  record?: (row: ShimAction) => Promise<void>;
}

export async function runGuarded(command: string, args: string[], ctx: ShimContext, deps: RunDeps): Promise<number> {
  const plan = planShim(command, args, ctx);
  if (!plan.target) {
    const direct = deps.findBinary(command);
    if (!direct) return missing(deps);
    return deps.spawnPath(direct, args);
  }

  let decision: ShimDecision;
  try {
    decision = await deps.decide(plan.target, [command, ...args]);
  } catch (err) {
    decision = { outcome: "deny", reason: `decision unavailable (${failureKind(err)}). Failing closed.` };
  }
  if (deps.mode === "enforce" && decision.outcome !== "allow") {
    deps.stderr(decision.reason || "REFUSED: failing closed.");
    return BLOCKED;
  }
  const binary = deps.findBinary(command);
  if (!binary) return missing(deps);
  if (deps.record && plan.target) {
    await deps.record({
      at: new Date().toISOString(),
      agent: decision.agent || "grokbot-agent",
      action: "run_command",
      target: plan.target,
      decision_id: decision.decisionId || "",
    });
  }
  return deps.spawnPath(binary, args);
}

function missing(deps: RunDeps): number {
  deps.stderr("the real command was not found outside ~/.local/bin");
  return 127;
}

/** The mode for this process: the active profile, then the manifest. */
export async function modeFor(env: NodeJS.ProcessEnv, home: string): Promise<ShimMode> {
  const manifest = await readManifest(home);
  const name = env.GROKBOT_BOT || manifest?.profile || "";
  if (name) {
    try {
      const profile = await readProfile(name);
      if (profile.shims) return profile.shims;
    } catch {
      /* a profile that is not opted in keeps the mode install recorded */
    }
  }
  return manifest?.mode === "enforce" ? "enforce" : "log-only";
}

export async function decideCommand(target: string, argv: string[], env: NodeJS.ProcessEnv): Promise<ShimDecision> {
  let agentDid = env.GROKBOT_AGENT_ID || "";
  const profileName = env.GROKBOT_BOT || "";
  if (!agentDid && profileName) {
    try {
      agentDid = (await readProfile(profileName)).agent_id ?? "";
    } catch {
      agentDid = "";
    }
  }
  const agent = agentDid || "grokbot-agent";
  const apiKey = resolveApiKey(undefined, env);
  if (!apiKey) {
    return { outcome: "deny", reason: "decision unavailable (no API key). Failing closed.", decisionId: "", agent };
  }
  const base = resolveBaseUrlSetting(env.COGNEXUS_API_BASE_URL, "COGNEXUS_API_BASE_URL");
  try {
    const decision = await postDecision({
      apiKey,
      baseUrl: base.url,
      baseSource: base.source,
      action: "run_command",
      target,
      payload: JSON.stringify({ tool: "run_command", arguments: { argv } }),
      agentDid: agent,
    });
    const decisionId = decision.decision_id || "";
    if (decision.outcome === "allow") return { outcome: "allow", reason: "", decisionId, agent };
    const reasons = (decision.reasons || []).filter((item) => typeof item === "string").join("; ");
    return { outcome: decision.outcome, reason: reasons || decision.outcome, decisionId, agent };
  } catch (err) {
    return {
      outcome: "deny",
      reason: `decision unavailable (${failureKind(err)}). Failing closed.`,
      decisionId: "",
      agent,
    };
  }
}

export function spawnAbsolute(file: string, args: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  if (!file) return Promise.resolve(127);
  return new Promise((resolve) => {
    const child = spawn(file, args, { stdio: "inherit", env, windowsHide: true });
    child.on("error", () => resolve(127));
    child.on("exit", (code) => resolve(code ?? 1));
  });
}

export async function launchShim(command: string, args: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const home = userHome(env);
  const ctx: ShimContext = { cwd: process.cwd(), env, home };
  const mode = await modeFor(env, home);
  return runGuarded(command, args, ctx, {
    mode,
    decide: (target, argv) => decideCommand(target, argv, env),
    findBinary: (name) => findRealBinary(name, env.PATH ?? "", home),
    spawnPath: (file, spawnArgs) => spawnAbsolute(file, spawnArgs, env),
    stderr: (line) => {
      process.stderr.write(`${line}\n`);
    },
    record: async (row) => {
      try {
        await appendActionLine(defaultShimLog(), row);
      } catch {
        process.stderr.write("artzain shim could not record the action\n");
      }
    },
  });
}

export function userHome(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = process.platform === "win32" ? env.USERPROFILE : env.HOME;
  return fromEnv || "";
}
