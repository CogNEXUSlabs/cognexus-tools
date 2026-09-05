// Copies the static node assets into dist/. npm runs package scripts through
// cmd.exe on Windows, where `mkdir -p` and `cp` do not exist, so this must
// stay plain Node with no shell commands and no dependencies.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const assets = [
  ["src/nodes/artzain.svg", "dist/nodes/ArtzainDecision/artzain.svg"],
  ["src/nodes/ArtzainDecision/ArtzainDecision.node.json", "dist/nodes/ArtzainDecision/ArtzainDecision.node.json"],
  ["src/nodes/artzain.svg", "dist/nodes/ArtzainEnvelope/artzain.svg"],
  ["src/nodes/ArtzainEnvelope/ArtzainEnvelope.node.json", "dist/nodes/ArtzainEnvelope/ArtzainEnvelope.node.json"],
];

for (const [src, dest] of assets) {
  const target = join(pkgRoot, dest);
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(join(pkgRoot, src), target);
}
