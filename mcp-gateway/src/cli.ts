#!/usr/bin/env node
import { run } from "./server.js";

const code = await run(process.argv.slice(2));
process.exit(code);
