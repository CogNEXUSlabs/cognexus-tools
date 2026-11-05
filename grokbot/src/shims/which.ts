/**
 * The real binary is the first PATH entry that is not the shim directory.
 * `~/.local/bin` is where the wrappers are installed, so it is left out
 * even when it is the first directory. A copy of a wrapper elsewhere is
 * left out too, so a shim cannot exec itself.
 */

import { readFileSync, statSync } from "node:fs";
import { delimiter, join, resolve } from "node:path";

const MARKER = "grokbot-artzain-shim";

export function localBin(home: string): string {
  return resolve(home, ".local", "bin");
}

export function findRealBinary(name: string, pathEnv: string, home: string): string | undefined {
  const skip = localBin(home);
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    let resolved: string;
    try {
      resolved = resolve(dir);
    } catch {
      continue;
    }
    if (sameDir(resolved, skip)) continue;
    for (const candidate of candidates(resolved, name)) {
      if (isShim(candidate)) continue;
      if (isFile(candidate)) return candidate;
    }
  }
  return undefined;
}

function candidates(dir: string, name: string): string[] {
  const names = process.platform === "win32" ? [name, `${name}.exe`, `${name}.cmd`] : [name];
  return names.map((file) => join(dir, file));
}

function sameDir(left: string, right: string): boolean {
  const a = process.platform === "win32" ? left.toLowerCase() : left;
  const b = process.platform === "win32" ? right.toLowerCase() : right;
  return a === b;
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isShim(path: string): boolean {
  try {
    return readFileSync(path).subarray(0, 240).toString("utf8").includes(MARKER);
  } catch {
    return false;
  }
}
