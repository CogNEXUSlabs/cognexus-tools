#!/usr/bin/env node
/**
 * The process a wrapper execs. argv is: node launch.js <command> [args...]
 */
import { launchShim, userHome } from "./run.js";

const command = process.argv[2] ?? "";
const code = await launchShim(command, process.argv.slice(3), {
  ...process.env,
  HOME: process.env.HOME || userHome(),
});
process.exitCode = code;
