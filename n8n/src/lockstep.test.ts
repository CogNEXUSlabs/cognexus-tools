/**
 * The nodes carry no runtime dependency on `@cognexuslabs/artzain` (an n8n
 * community package installs with its own dependencies only, and each npm
 * package is released from its own tag on the mirror with no ordering between
 * them), so `failure.ts` is a hand copy of the SDK's `failureKind`. This test
 * keeps that copy honest: every `// lockstep:begin <name>` …
 * `// lockstep:end <name>` block must be byte-identical in both trees. Edit
 * the SDK first, then paste.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
// sdk/n8n/src -> sdk/typescript/src here; n8n/src -> typescript/src on the
// mirror, where the packages are siblings too.
const SDK_SRC = join(here, "..", "..", "typescript", "src");

function read(path: string): string {
  // Git stores these files with LF, but a Windows checkout (`* text=auto`, no
  // core.eol) writes CRLF, and the `\n` in `block` then finds no marker.
  return readFileSync(path, "utf8").replace(/\r\n/g, "\n");
}

function block(source: string, file: string, name: string): string {
  const begin = `// lockstep:begin ${name}\n`;
  const end = `// lockstep:end ${name}`;
  const start = source.indexOf(begin);
  const stop = source.indexOf(end);
  if (start < 0 || stop < 0 || stop < start) {
    throw new Error(`${file}: no "${name}" lockstep block`);
  }
  return source.slice(start + begin.length, stop);
}

describe("failure.ts stays in lockstep with sdk/typescript", () => {
  it("failureKind is byte-identical to errors.ts", () => {
    const failure = read(join(here, "failure.ts"));
    const sdk = read(join(SDK_SRC, "errors.ts"));
    expect(block(failure, "failure.ts", "failure-kind")).toBe(
      block(sdk, "errors.ts", "failure-kind"),
    );
  });
});
