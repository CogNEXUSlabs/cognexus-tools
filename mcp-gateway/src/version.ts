/**
 * This package's version, read from the package.json npm ships beside dist/.
 * The gateway reports it as its MCP serverInfo, as the client it opens
 * upstreams with, and in each decision's product.
 */

import { readFileSync } from "node:fs";

export const VERSION: string = (
  JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }
).version;
