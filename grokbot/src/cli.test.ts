/**
 * `grokbot-artzain decide` gives its verdict as an exit code (README,
 * "Contract"): 0 on allow, 2 on anything else. A Bot acts on that code, so it
 * must hold on every platform with enroll on, as it is by default.
 *
 * These tests compile the CLI from this source into a temporary directory
 * (CI runs the tests before it builds) and run it in a child process, as a
 * Bot does, against a local origin that gets both of its requests: enroll
 * and the decision. On Windows the CLI used to abort as it exited, whatever
 * the answer: a libuv assertion on stderr and exit code 3221226505.
 *
 * The origin keeps idle connections open for a minute, as servers do, so
 * none closes under the CLI. Enroll is telemetry: one still in flight when
 * the verdict is in gets a short grace and is then cut off, and so is a
 * response whose body is never read. Timings start at the verdict on stdout,
 * because starting a process on a busy Windows machine has itself taken
 * seconds.
 */

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { createServer, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ENROLL_TIMEOUT_MS } from "./enroll.js";

const here = dirname(fileURLToPath(import.meta.url));

const KEEP_ALIVE_MS = 60_000;
/**
 * Time a run is given before it is killed: well under KEEP_ALIVE_MS, and
 * room for a slow start (a busy Windows machine has taken seconds).
 */
const RUN_TIMEOUT_MS = 30_000;
/** How long the slow origin holds its answer to enroll: within the CLI's grace. */
const ENROLL_DELAY_MS = 500;
/**
 * A run that ends this soon after printing its verdict waited out neither
 * enroll's own timeout nor the garbage collection that frees a body left
 * unread. The CLI's grace for telemetry is 2 s.
 */
const PROMPT_MS = ENROLL_TIMEOUT_MS / 2;

let outDir = "";

beforeAll(() => {
  // The compiler `npm run build` uses, so a run tests this source and not
  // whatever an earlier build left in dist/.
  const tsPackage = createRequire(import.meta.url).resolve("typescript/package.json");
  const { bin } = JSON.parse(readFileSync(tsPackage, "utf8")) as { bin: { tsc: string } };
  outDir = mkdtempSync(join(tmpdir(), "grokbot-cli-"));
  try {
    execFileSync(
      process.execPath,
      [
        join(dirname(tsPackage), bin.tsc),
        "-p", join(here, "..", "tsconfig.json"),
        "--outDir", outDir,
        "--declaration", "false",
        "--declarationMap", "false",
        "--sourceMap", "false",
      ],
      { stdio: "pipe" },
    );
  } catch (err) {
    throw new Error(`tsc failed:\n${(err as { stdout?: Buffer }).stdout?.toString() ?? err}`);
  }
  // The package is ESM ("type": "module"), and outside it this copy must be too.
  writeFileSync(join(outDir, "package.json"), '{"type":"module"}\n');
}, 120_000);

afterAll(async () => {
  // Best effort: a directory left in the temp folder fails nothing, and on a
  // busy Windows machine removing it has taken longer than the 10 s a hook
  // gets by default.
  if (outDir) await rm(outDir, { recursive: true, force: true, maxRetries: 5 }).catch(() => {});
}, 60_000);

type Answer = (res: ServerResponse) => void;

function json(status: number, body: unknown): Answer {
  return (res) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
}

/** Accepts either request: enroll reads `adapter`, the decision `outcome`. */
const ALLOW = json(200, { outcome: "allow", decision_id: "d1", reasons: [], adapter: { primary: "grokbot" } });
const DENY = json(200, { outcome: "deny", decision_id: "d2", reasons: ["refused by policy"] });
const FORBIDDEN = json(403, { detail: "forbidden" });
const UNAVAILABLE = json(503, { detail: "kill_switch_active" });
/** Followed, it would reach ALLOW on this origin, so the call would pass. */
const REDIRECT: Answer = (res) => {
  res.writeHead(302, { Location: "/moved" });
  res.end();
};

/**
 * A refusal whose body enroll never reads. At this size an unread body
 * holds its connection until garbage collection, seconds later.
 */
const FORBIDDEN_PAGE: Answer = (res) => {
  res.writeHead(403, { "Content-Type": "text/html" });
  res.end("x".repeat(64 * 1024));
};
/** Never answers. */
const SILENT: Answer = () => {};

function later(ms: number, answer: Answer): Answer {
  return (res) => {
    setTimeout(() => answer(res), ms);
  };
}

let server: Server | undefined;

/** A local origin that answers enroll with `enroll` and everything else with `other`. */
async function origin(enroll: Answer, other: Answer): Promise<{ base: string; seen: string[] }> {
  const seen: string[] = [];
  server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => (req.url === "/api/v1/registry/enroll" ? enroll : other)(res));
  });
  server.keepAliveTimeout = KEEP_ALIVE_MS;
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

interface Run {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  /** From the verdict on stdout to the end of the process. */
  afterVerdictMs: number;
}

/** Runs `grokbot-artzain decide` against `base` with enroll on (no flag turns it off). */
function decide(base: string): Promise<Run> {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    // The CLI's own settings come only from the flags below.
    if (/^(COGNEXUS_|GROKBOT_)/.test(name) || name === "MYAPP_API_KEY") delete env[name];
  }
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(outDir, "cli.js"), "decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base],
      { env, timeout: RUN_TIMEOUT_MS, windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    let verdictAt = Number.NaN;
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      if (!stdout) verdictAt = Date.now();
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status, signal) =>
      resolve({ status, signal, stdout, stderr, afterVerdictMs: Date.now() - verdictAt }),
    );
  });
}

const CASES = [
  { answer: "an allow", enroll: ALLOW, decision: ALLOW, exit: 0, outcome: "allow" },
  { answer: "a deny", enroll: ALLOW, decision: DENY, exit: 2, outcome: "deny" },
  { answer: "HTTP 403", enroll: FORBIDDEN, decision: FORBIDDEN, exit: 2, outcome: "deny" },
  { answer: "HTTP 503", enroll: UNAVAILABLE, decision: UNAVAILABLE, exit: 2, outcome: "deny" },
  { answer: "HTTP 302", enroll: REDIRECT, decision: REDIRECT, exit: 2, outcome: "deny" },
  { answer: "an allow, with enroll refused", enroll: FORBIDDEN, decision: ALLOW, exit: 0, outcome: "allow" },
];

describe("grokbot-artzain decide, with enroll on", () => {
  it.each(CASES)("exits $exit on $answer", async ({ enroll, decision, exit, outcome }) => {
    const { base, seen } = await origin(enroll, decision);

    const run = await decide(base);

    expect(seen).toContain("POST /api/v1/registry/enroll");
    expect(seen).toContain("POST /api/v1/decisions");
    expect(run.signal, run.stderr).toBeNull();
    expect(run.status, run.stderr).toBe(exit);
    expect(JSON.parse(run.stdout).outcome).toBe(outcome);
  }, 45_000);

  it("lets an enroll that answers soon after the verdict finish, then exits with the decision's code", async () => {
    const { base } = await origin(later(ENROLL_DELAY_MS, ALLOW), ALLOW);

    const run = await decide(base);

    expect(run.signal, run.stderr).toBeNull();
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout).outcome).toBe("allow");
    expect(run.stderr).toContain("artzain enroll ok");
  }, 45_000);

  it("cuts off an enroll that does not answer, well before enroll's own timeout", async () => {
    const { base } = await origin(SILENT, ALLOW);

    const run = await decide(base);

    expect(run.signal, run.stderr).toBeNull();
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout).outcome).toBe("allow");
    expect(run.stderr).toContain("artzain enroll failed");
    expect(run.afterVerdictMs).toBeLessThan(PROMPT_MS);
  }, 45_000);

  it("does not wait for garbage collection to free a refusal body enroll left unread", async () => {
    const { base } = await origin(FORBIDDEN_PAGE, ALLOW);

    const run = await decide(base);

    expect(run.signal, run.stderr).toBeNull();
    expect(run.status, run.stderr).toBe(0);
    expect(run.stderr).toContain("artzain enroll refused: HTTP 403");
    expect(run.afterVerdictMs).toBeLessThan(PROMPT_MS);
  }, 45_000);
});
