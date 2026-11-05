/**
 * A saved name for one Bot.
 *
 * The file is `profiles/<name>.json` under `~/.config/grokbot-artzain`, or
 * under `%APPDATA%\grokbot-artzain` on Windows. It holds an agent id, an
 * instance, a base URL, and the name of the environment variable that
 * holds the key. The key itself is not stored.
 *
 * The write uses the same rename retry as the enroll state file: on
 * Windows a refusal is tried again, and a failed write leaves the previous
 * file in place.
 */

import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

import { replaceFile, stateDirectory } from "./state.js";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export type ShimMode = "log-only" | "enforce";

export interface BotProfile {
  agent_id?: string;
  instance?: string;
  base_url?: string;
  /** The environment variable that holds the key. Not the key. */
  key_env?: string;
  /** Set when this profile opts in to the command shims. */
  shims?: ShimMode;
}

export function profilesDirectory(): string {
  return join(stateDirectory(), "profiles");
}

function profileNameProblem(name: string): string | undefined {
  if (!NAME.test(name)) return "a profile name is letters, digits, and . _ -";
  return undefined;
}

/** The file for `name`, after the name has been checked. */
function profileFile(name: string): string {
  const root = resolve(profilesDirectory());
  const dest = resolve(root, `${name}.json`);
  if (dest !== join(root, `${name}.json`) && !dest.startsWith(root + sep)) {
    return "";
  }
  return dest;
}

function textOf(profile: BotProfile): string {
  const body: BotProfile = {};
  if (profile.agent_id) body.agent_id = profile.agent_id;
  if (profile.instance) body.instance = profile.instance;
  if (profile.base_url) body.base_url = profile.base_url;
  if (profile.key_env) body.key_env = profile.key_env;
  if (profile.shims) body.shims = profile.shims;
  return `${JSON.stringify(body, null, 2)}\n`;
}

async function writePrivate(path: string, data: string): Promise<void> {
  const handle = await open(path, "w", FILE_MODE);
  try {
    await handle.writeFile(data, "utf8");
    if (process.platform !== "win32") await handle.chmod(FILE_MODE);
  } finally {
    await handle.close();
  }
  if (process.platform !== "win32") {
    try {
      await chmod(path, FILE_MODE);
    } catch {
      /* the descriptor already carries the mode */
    }
  }
}

/**
 * Save `profile` as `name`. A bad name or a key env value that is not a
 * variable name is a `problem`, and the problem does not quote that value.
 */
export async function writeProfile(
  name: string,
  profile: BotProfile,
): Promise<{ path: string } | { problem: string }> {
  const nameProblem = profileNameProblem(name);
  if (nameProblem) return { problem: nameProblem };
  if (profile.key_env !== undefined && !ENV_NAME.test(profile.key_env)) {
    return { problem: "--key-env is an environment variable name" };
  }
  const dest = profileFile(name);
  if (!dest) return { problem: "a profile name is letters, digits, and . _ -" };
  const dir = profilesDirectory();
  await mkdir(dir, { recursive: true, mode: DIR_MODE });
  if (process.platform !== "win32") {
    try {
      await chmod(dir, DIR_MODE);
    } catch {
      /* a directory that already has the mode */
    }
  }
  const temp = join(dir, `.profile.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  await writePrivate(temp, textOf(profile));
  await replaceFile(temp, dest);
  return { path: dest };
}

function field(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  return text || undefined;
}

/**
 * The saved profile. A missing or unreadable file throws. A key that
 * someone put in the file is ignored.
 */
export async function readProfile(name: string): Promise<BotProfile> {
  const nameProblem = profileNameProblem(name);
  if (nameProblem) {
    const err = new Error(nameProblem);
    (err as { code?: string }).code = "EINVAL";
    throw err;
  }
  const text = await readFile(profileFile(name), "utf8");
  const parsed = JSON.parse(text) as Record<string, unknown>;
  const profile: BotProfile = {};
  const agent = field(parsed.agent_id);
  const instance = field(parsed.instance);
  const base = field(parsed.base_url);
  const keyEnv = field(parsed.key_env);
  const shims = field(parsed.shims);
  if (agent) profile.agent_id = agent;
  if (instance) profile.instance = instance;
  if (base) profile.base_url = base;
  if (keyEnv && ENV_NAME.test(keyEnv)) profile.key_env = keyEnv;
  if (shims === "log-only" || shims === "enforce") profile.shims = shims;
  return profile;
}
