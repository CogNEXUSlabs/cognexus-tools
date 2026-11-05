/**
 * `grokbot-artzain shims install` and `shims uninstall`.
 * `shims exec` is what a wrapper runs. It is not in the help text.
 */

import { launchShim } from "./run.js";
import { installShims, uninstallShims } from "./install.js";
import type { ShimMode } from "../profile.js";

function homeFromEnv(): string {
  if (process.platform === "win32") return process.env.USERPROFILE || process.env.HOME || "";
  return process.env.HOME || "";
}

export async function runShims(
  args: string[],
  log: (msg: string) => void,
  _print: (msg: string) => void,
): Promise<number> {
  const sub = args[0];
  if (sub === "exec") {
    const command = args[1] ?? "";
    if (!command) {
      log("grokbot-artzain shims: exec needs a command");
      return 2;
    }
    return launchShim(command, args.slice(2));
  }
  if (sub !== "install" && sub !== "uninstall") {
    log("usage: grokbot-artzain shims install|uninstall [--profile <name>] [--enforce]");
    return 2;
  }
  let profile = process.env.GROKBOT_BOT || "";
  let enforce = false;
  for (let i = 1; i < args.length; i += 1) {
    const word = args[i] ?? "";
    if (word === "--profile") {
      profile = args[++i] ?? "";
      if (!profile) {
        log("grokbot-artzain shims: --profile needs a name");
        return 2;
      }
      continue;
    }
    if (word === "--enforce") {
      enforce = true;
      continue;
    }
    log("grokbot-artzain shims: a word that is not an option");
    return 2;
  }
  if (sub === "uninstall" && enforce) {
    log("grokbot-artzain shims: --enforce is an option of install");
    return 2;
  }
  const home = homeFromEnv();
  if (!home) {
    log("grokbot-artzain shims: HOME is not set");
    return 2;
  }
  if (sub === "uninstall") {
    const removed = await uninstallShims(home);
    if (!removed.ok) {
      log(`grokbot-artzain shims: ${removed.message}`);
      return 2;
    }
    return 0;
  }
  const mode: ShimMode = enforce ? "enforce" : "log-only";
  const installed = await installShims({ home, profile, mode, env: process.env });
  if (!installed.ok) {
    log(`grokbot-artzain shims: ${installed.message}`);
    return 2;
  }
  return 0;
}
