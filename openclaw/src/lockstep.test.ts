/**
 * The plugin deliberately carries no runtime dependency (it is installed from
 * a git checkout with `openclaw plugins install ./sdk/openclaw`, loaded from
 * `src/index.ts` with no install step, and each npm package is released from
 * its own tag on the mirror with no ordering between them), so the Decision
 * API client is a hand copy of `sdk/typescript/src/decide.ts`. This test is
 * what keeps that copy honest: every `// lockstep:begin <name>` …
 * `// lockstep:end <name>` block must be byte-identical in both trees. Edit
 * the SDK first, then paste.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
// sdk/openclaw/src -> sdk/typescript/src here; openclaw/src -> typescript/src
// on the mirror, where the packages are siblings too.
const SDK_SRC = join(here, "..", "..", "typescript", "src");

function read(path: string): string {
  return readFileSync(path, "utf8");
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

const client = read(join(here, "client.ts"));

describe("client.ts stays in lockstep with sdk/typescript (§9.85)", () => {
  it("DecisionError is byte-identical to errors.ts", () => {
    const sdk = read(join(SDK_SRC, "errors.ts"));
    expect(block(client, "client.ts", "DecisionError")).toBe(
      block(sdk, "errors.ts", "DecisionError"),
    );
  });

  it("DecisionResponse and FetchLike are byte-identical to decide.ts", () => {
    const sdk = read(join(SDK_SRC, "decide.ts"));
    expect(block(client, "client.ts", "decision-types")).toBe(
      block(sdk, "decide.ts", "decision-types"),
    );
  });

  it("response handling is byte-identical to decide.ts", () => {
    const sdk = read(join(SDK_SRC, "decide.ts"));
    expect(block(client, "client.ts", "decision-response")).toBe(
      block(sdk, "decide.ts", "decision-response"),
    );
  });
});
