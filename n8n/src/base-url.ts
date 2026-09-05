/** Base-URL trimming shared by both nodes. */

/**
 * Strip trailing slashes. Scanned rather than trimmed with /\/+$/, which
 * backtracks quadratically on a value made up mostly of slashes (the same
 * loop `sdk/typescript/src/config.ts` uses).
 */
export function trimTrailingSlashes(raw: string): string {
  let end = raw.length;
  while (end > 0 && raw.charCodeAt(end - 1) === 47) end--;
  return raw.slice(0, end);
}
