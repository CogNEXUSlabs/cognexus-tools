/**
 * Install writes one wrapper per command into ~/.local/bin and a manifest
 * of those paths. It edits no shell profile. Uninstall deletes the paths
 * in the manifest and nothing else.
 *
 * After the files are written, a new `bash -c 'command -v curl'` has to
 * resolve to the curl wrapper. When it does not, install removes the files
 * it wrote and leaves the profile unchanged.
 */

import { execFile } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { access, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readProfile, writeProfile, type ShimMode } from "../profile.js";
import { localBin } from "./which.js";

export const SHIM_NAMES = ["curl", "wget", "git", "gh", "npm", "aws", "ssh", "scp", "rm"] as const;
export const MARKER = "grokbot-artzain-shim";
const MANIFEST_NAME = ".grokbot-artzain-shims.json";

export interface ShimManifest {
  version: 1;
  profile: string;
  mode: ShimMode;
  files: string[];
}

export function manifestPath(home: string): string {
  return resolve(localBin(home), MANIFEST_NAME);
}

export function launchScriptPath(): string {
  return fileURLToPath(new URL("./launch.js", import.meta.url));
}

function wrapper(nodePath: string, launchPath: string, name: string): string {
  const quote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;
  return `#!/usr/bin/env bash\n# ${MARKER}\nexec ${quote(nodePath)} ${quote(launchPath)} ${name} "$@"\n`;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function isOurShim(path: string): Promise<boolean> {
  try {
    const text = await readFile(path, "utf8");
    return text.includes(MARKER);
  } catch {
    return false;
  }
}

export async function readManifest(home: string): Promise<ShimManifest | undefined> {
  try {
    const parsed = JSON.parse(await readFile(manifestPath(home), "utf8")) as ShimManifest;
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.files)) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

function insideBin(home: string, path: string): boolean {
  const root = localBin(home);
  const resolved = resolve(path);
  const prefix = process.platform === "win32" ? root.toLowerCase() : root;
  const candidate = process.platform === "win32" ? resolved.toLowerCase() : resolved;
  return candidate === prefix || candidate.startsWith(`${prefix}${process.platform === "win32" ? "\\" : "/"}`);
}

export async function installShims(options: {
  home: string;
  profile: string;
  mode: ShimMode;
  env: NodeJS.ProcessEnv;
  nodePath?: string;
  launchPath?: string;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  if (!options.profile) return { ok: false, message: "shims install needs a profile: pass --profile or set GROKBOT_BOT" };
  let profile;
  try {
    profile = await readProfile(options.profile);
  } catch {
    return { ok: false, message: "shims install needs a profile that already exists" };
  }
  const bin = localBin(options.home);
  await mkdir(bin, { recursive: true });
  for (const name of SHIM_NAMES) {
    const dest = resolve(bin, name);
    if (await exists(dest) && !(await isOurShim(dest))) {
      return { ok: false, message: `shims install left ${name} in place because it is not a shim` };
    }
  }
  const nodePath = options.nodePath || process.execPath;
  const launchPath = options.launchPath || launchScriptPath();
  const written: string[] = [];
  try {
    for (const name of SHIM_NAMES) {
      const dest = resolve(bin, name);
      const prior = await exists(dest);
      await writeFile(dest, wrapper(nodePath, launchPath, name), { mode: 0o755 });
      await chmod(dest, 0o755);
      if (!prior) written.push(dest);
    }
    const manifest: ShimManifest = {
      version: 1,
      profile: options.profile,
      mode: options.mode,
      files: [...SHIM_NAMES.map((name) => resolve(bin, name)), manifestPath(options.home)],
    };
    const manifestPrior = await exists(manifestPath(options.home));
    await writeFile(manifestPath(options.home), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
    if (!manifestPrior) written.push(manifestPath(options.home));
    const seen = await curlIsShim(options.env);
    if (!seen) {
      await removePaths(options.home, written);
      return { ok: false, message: "shims install failed: command -v curl in bash -c did not resolve to the shim" };
    }
  } catch {
    await removePaths(options.home, written);
    return { ok: false, message: "shims install could not write the wrappers" };
  }
  const saved = await writeProfile(options.profile, { ...profile, shims: options.mode });
  if ("problem" in saved) {
    await removePaths(options.home, written);
    return { ok: false, message: "shims install could not record the profile" };
  }
  return { ok: true };
}

/**
 * A bash that runs a command and reads no profile, which is how the Bot
 * runs. On Windows the `bash` on PATH is a stub, and Git's `bin/bash.exe`
 * prepends its own directories, so the check uses `usr/bin/bash.exe`.
 */
export function bashProgram(): string {
  if (process.platform === "win32") {
    const gitBash = "C:\\Program Files\\Git\\usr\\bin\\bash.exe";
    if (existsSync(gitBash)) return gitBash;
  }
  return "bash";
}

const CURL_CHECK = "p=$(command -v curl) || exit 1; grep -q grokbot-artzain-shim \"$p\" </dev/null";

function curlIsShim(env: NodeJS.ProcessEnv): Promise<boolean> {
  return new Promise((resolve) => {
    execFile(
      bashProgram(),
      ["--noprofile", "--norc", "-c", CURL_CHECK],
      { env, windowsHide: true, timeout: 8000 },
      (err) => resolve(!err),
    );
  });
}

async function removePaths(home: string, paths: string[]): Promise<void> {
  for (const path of paths) {
    if (!insideBin(home, path)) continue;
    await unlink(path).catch(() => undefined);
  }
}

export async function uninstallShims(home: string): Promise<{ ok: true; removed: string[] } | { ok: false; message: string }> {
  const manifest = await readManifest(home);
  if (!manifest) return { ok: false, message: "shims uninstall found no manifest" };
  const removed: string[] = [];
  for (const path of manifest.files) {
    if (!insideBin(home, path)) continue;
    if (!(await exists(path))) continue;
    if (path !== manifestPath(home) && !(await isOurShim(path))) continue;
    await unlink(path);
    removed.push(path);
  }
  if (manifest.profile) {
    try {
      const profile = await readProfile(manifest.profile);
      const next = { ...profile };
      delete next.shims;
      await writeProfile(manifest.profile, next);
    } catch {
      /* the wrappers are already gone when the profile cannot be read */
    }
  }
  return { ok: true, removed };
}
