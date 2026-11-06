/**
 * The gateway's action log: one JSON line for each tools/call it forwards
 * after an allow. `grokbot-artzain coverage` reads it beside the command
 * shims' log and the Bot's action journal, and counts its lines per agent.
 *
 * A call the gateway refuses (deny, review, an outage) never reaches the
 * upstream, so it is not an action and gets no line, the way an enforcing
 * command shim records nothing for a command it does not run. A line holds
 * the time, the agent, the action, the target and the decision id: never the
 * arguments, a header, an env value or the key.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, posix, win32 } from "node:path";

/** One line, typed the way `grokbot-artzain coverage` types it. */
export type ActionLine = { at: string; agent: string; action: string; target: string; decision_id: string };

/**
 * `ARTZAIN_GATEWAY_LOG` when set, otherwise `%APPDATA%\artzain-mcp-gateway\gateway.jsonl`
 * on Windows and `~/.config/artzain-mcp-gateway/gateway.jsonl` elsewhere: the
 * path `grokbot-artzain coverage` reads by default.
 */
export function defaultActionLog(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  const named = env.ARTZAIN_GATEWAY_LOG?.trim();
  if (named) return named;
  if (platform === "win32") {
    const base = env.APPDATA || win32.join(homedir(), "AppData", "Roaming");
    return win32.join(base, "artzain-mcp-gateway", "gateway.jsonl");
  }
  const home = env.HOME || homedir();
  return posix.join(home, ".config", "artzain-mcp-gateway", "gateway.jsonl");
}

/** Append one line. A failure is the caller's to report. */
export async function appendActionLine(file: string, row: ActionLine): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify(row)}\n`, "utf8");
}
