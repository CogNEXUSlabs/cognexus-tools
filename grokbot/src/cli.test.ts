/**
 * `grokbot-artzain decide` gives its verdict as an exit code (README, "The
 * answer"): 0 on allow, 2 on anything else. A Bot acts on that code, so it
 * must hold on every platform with enroll on, as it is by default.
 *
 * These tests compile the CLI from this source into a temporary directory
 * laid out as the published package is (`dist/`, with `package.json` and
 * `SKILL.md` beside it; CI runs the tests before it builds) and run it in a
 * child process, as a Bot does, against a local origin that gets both of its
 * requests: enroll and the decision. On Windows the CLI used to abort as it
 * exited, whatever the answer: a libuv assertion on stderr and exit code
 * 3221226505.
 *
 * The origin keeps idle connections open for a minute, as servers do, so
 * none closes under the CLI. Enroll is telemetry: one still in flight when
 * the verdict is in gets a short grace and is then cut off, and so is a
 * response whose body is never read. Timings start at the verdict on stdout,
 * because starting a process on a busy Windows machine has itself taken
 * seconds.
 */

import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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
        "--outDir", join(outDir, "dist"),
        "--declaration", "false",
        "--declarationMap", "false",
        "--sourceMap", "false",
      ],
      { stdio: "pipe" },
    );
  } catch (err) {
    throw new Error(`tsc failed:\n${(err as { stdout?: Buffer }).stdout?.toString() ?? err}`);
  }
  // The package's own package.json makes this copy ESM ("type": "module"),
  // as the package is, and gives `--version` its answer; `skill` names the
  // SKILL.md beside it.
  for (const shipped of ["package.json", "SKILL.md"]) {
    copyFileSync(join(here, "..", shipped), join(outDir, shipped));
  }
  copyFileSync(join(here, "taxonomy.json"), join(outDir, "dist", "taxonomy.json"));
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
const QUEUED = json(200, { outcome: "review", decision_id: "d3", reasons: ["needs a person"] });
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

/**
 * A local origin that answers enroll with `enroll` and everything else with
 * `other`. `bodies` holds the last request body each path was sent.
 */
async function origin(
  enroll: Answer,
  other: Answer,
): Promise<{
  base: string;
  seen: string[];
  bodies: Record<string, string>;
  announceBodies: string[];
  keys: Record<string, string | undefined>;
}> {
  const seen: string[] = [];
  const bodies: Record<string, string> = {};
  const announceBodies: string[] = [];
  const keys: Record<string, string | undefined> = {};
  server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    keys[req.url ?? ""] = req.headers["x-api-key"] as string | undefined;
    let body = "";
    req.setEncoding("utf8").on("data", (chunk: string) => (body += chunk));
    req.on("end", () => {
      bodies[req.url ?? ""] = body;
      if (req.url === "/api/v1/registry/announce") announceBodies.push(body);
      (req.url === "/api/v1/registry/enroll" ? enroll : other)(res);
    });
  });
  server.keepAliveTimeout = KEEP_ALIVE_MS;
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    seen,
    bodies,
    announceBodies,
    keys,
  };
}

function sentDecision(bodies: Record<string, string>): { agent_did?: string } {
  return JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { agent_did?: string };
}

/** Where this platform keeps grokbot-artzain state for the CLI's home. */
function profileFile(name: string): string {
  const root = process.platform === "win32"
    ? join(cliHome, "AppData", "Roaming")
    : join(cliHome, ".config");
  return join(root, "grokbot-artzain", "profiles", `${name}.json`);
}

function saveProfile(name: string, profile: Record<string, string>): void {
  const file = profileFile(name);
  mkdirSync(join(file, ".."), { recursive: true });
  writeFileSync(file, `${JSON.stringify(profile)}\n`, "utf8");
}

async function closeOrigin(): Promise<void> {
  const current = server;
  if (!current) return;
  server = undefined;
  current.closeAllConnections();
  await new Promise<void>((resolve) => current.close(() => resolve()));
}

function queueDir(): string {
  return process.platform === "win32"
    ? join(cliHome, "AppData", "Roaming", "grokbot-artzain", "queue")
    : join(cliHome, ".config", "grokbot-artzain", "queue");
}

function queuedTexts(): string[] {
  if (!existsSync(queueDir())) return [];
  return readdirSync(queueDir())
    .filter((name) => name.endsWith(".json"))
    .map((name) => readFileSync(join(queueDir(), name), "utf8"));
}

/** The `payload` the Decision API was sent, as the engine parses it. */
function sentPayload(bodies: Record<string, string>): unknown {
  const body = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { payload?: string };
  return JSON.parse(body.payload ?? "null");
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

/** A home the child can write its enroll state into, not the real profile. */
const cliHome = mkdtempSync(join(tmpdir(), "grokbot-cli-home-"));

/** The environment a run gets: the CLI's own settings come only from its flags. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (/^(COGNEXUS_|GROKBOT_|SAND_)/.test(name) || name === "MYAPP_API_KEY") delete env[name];
  }
  env.HOME = cliHome;
  env.USERPROFILE = cliHome;
  env.APPDATA = join(cliHome, "AppData", "Roaming");
  return env;
}

/** Runs `grokbot-artzain decide` against `base` with enroll on (no flag turns it off). */
function decide(base: string, ...more: string[]): Promise<Run> {
  return runCli(["decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base, ...more]);
}

/** The same decide, with `stdin` as the bytes `--payload-file -` reads. */
function decideStdin(base: string, stdin: Buffer, ...more: string[]): Promise<Run> {
  return runCli(
    ["decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base, ...more],
    stdin,
  );
}

/** Runs the CLI with these arguments. */
function cli(...args: string[]): Promise<Run> {
  return runCli(args);
}

/** The same run, with these variables added after the cleaned environment. */
function cliEnv(extra: NodeJS.ProcessEnv, ...args: string[]): Promise<Run> {
  return runCli(args, undefined, extra);
}

/** Runs the compiled CLI. `stdin`, when given, is written and then closed. */
function runCli(args: string[], stdin?: Buffer, extra?: NodeJS.ProcessEnv): Promise<Run> {
  const env = cleanEnv();
  if (extra) Object.assign(env, extra);
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(outDir, "dist", "cli.js"), ...args],
      { env, timeout: RUN_TIMEOUT_MS, windowsHide: true },
    );
    if (stdin !== undefined) {
      if (stdin.length > 0) child.stdin.write(stdin);
      child.stdin.end();
    }
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
  it("exits 2 and prints failing closed when a retryable 503 is exhausted", async () => {
    const { base, seen } = await origin(ALLOW, json(503, { detail: "audit_unavailable" }));

    const run = await decide(base);

    expect(seen.filter((line) => line === "POST /api/v1/decisions")).toHaveLength(3);
    expect(run.signal, run.stderr).toBeNull();
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toContain("failing closed");
  }, 45_000);

  it("prints the account minimum refusal and does not ask the engine again", async () => {
    const tooOld = json(422, {
      detail: { code: "client_too_old", detail: "Run grokbot-artzain upgrade." },
    });
    const { base, seen } = await origin(ALLOW, tooOld);

    const run = await decide(base);

    expect(seen.filter((line) => line === "POST /api/v1/decisions")).toHaveLength(1);
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toContain(
      "REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.",
    );
    expect(JSON.parse(run.stdout).outcome).toBe("deny");
  }, 45_000);

  it("maps --tool to an action and writes that action into the payload", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await cli(
      "decide",
      "--tool",
      "slack_send_message",
      "--arg",
      "channel=C123",
      "--api-key",
      "cnx_cli_probe",
      "--base-url",
      base,
      "--no-enroll",
    );
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as {
      action?: string;
      target?: string;
      payload?: string;
    };
    expect(sent.action).toBe("send_chat_message");
    expect(sent.target).toBe("slack:channel/C123");
    expect(JSON.parse(sent.payload ?? "{}")).toEqual({
      tool: "send_chat_message",
      arguments: { channel: "C123" },
    });
  }, 45_000);

  it("lets --action win when --tool is also given", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await cli(
      "decide",
      "--tool",
      "slack_send_message",
      "--action",
      "send_email",
      "--arg",
      "channel=C123",
      "--api-key",
      "cnx_cli_probe",
      "--base-url",
      base,
      "--no-enroll",
    );
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as {
      action?: string;
      target?: string;
      payload?: string;
    };
    expect(sent.action).toBe("send_email");
    expect(sent.target).toBe("slack:channel/C123");
    expect(JSON.parse(sent.payload ?? "{}").tool).toBe("send_email");
  }, 45_000);

  it("maps an unknown --tool to unknown_tool", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await cli(
      "decide",
      "--tool",
      "custom_widget",
      "--api-key",
      "cnx_cli_probe",
      "--base-url",
      base,
      "--no-enroll",
    );
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as {
      action?: string;
      target?: string;
      payload?: string;
    };
    expect(sent.action).toBe("unknown_tool");
    expect(sent.target).toBe("unknown:tool/custom_widget");
    expect(JSON.parse(sent.payload ?? "{}").tool).toBe("unknown_tool");
  }, 45_000);

  it("fills a repo target that contains a slash", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await cli(
      "decide",
      "--tool",
      "write_repo",
      "--arg",
      "repo=Quantumskipper/CogNEXUS",
      "--api-key",
      "cnx_cli_probe",
      "--base-url",
      base,
      "--no-enroll",
    );
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { action?: string; target?: string };
    expect(sent.action).toBe("write_repo");
    expect(sent.target).toBe("github:repo/Quantumskipper/CogNEXUS");
  }, 45_000);

  it("sends --cites-review as context.cites_review", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await decide(base, "--cites-review", "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { context?: Record<string, string> };
    expect(sent.context).toEqual({ cites_review: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
  }, 45_000);

  it("sends an empty context when --cites-review is absent", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await decide(base);
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { context?: Record<string, string> };
    expect(sent.context).toEqual({});
  }, 45_000);

  it("sends --request-id on the decide", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await decide(base, "--request-id", "order-8812");
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(bodies["/api/v1/decisions"] ?? "{}").request_id).toBe("order-8812");
  }, 45_000);

  it("generates a request id when --request-id is absent", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const run = await decide(base);
    expect(run.status, run.stderr).toBe(0);
    const sent = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { request_id?: string; product?: string };
    expect(sent.request_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    const version = (JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string }).version;
    expect(sent.product).toBe(`grokbot-artzain@${version}`);
  }, 45_000);

  it("prints a client update on stderr and adds notice, without changing the exit code", async () => {
    const warning = {
      warning: "client_update",
      latest: "9.9.9",
      upgrade_command: "npm install -g @cognexuslabs/grokbot-artzain@9.9.9",
    };
    const allow = await origin(ALLOW, json(200, {
      outcome: "allow", decision_id: "d1", reasons: [], warnings: [warning],
    }));
    const allowed = await decide(allow.base);
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(allowed.stderr).toContain("grokbot-artzain 9.9.9 is available");
    expect(allowed.stderr).toContain(warning.upgrade_command);
    const allowLine = JSON.parse(allowed.stdout);
    expect(allowLine.outcome).toBe("allow");
    expect(allowLine.notice).toContain("9.9.9");
    expect(allowed.stdout.trim().split("\n")).toHaveLength(1);

    const deny = await origin(ALLOW, json(200, {
      outcome: "deny", decision_id: "d2", reasons: ["refused by policy"], warnings: [warning],
    }));
    const denied = await decide(deny.base);
    expect(denied.status, denied.stderr).toBe(2);
    const denyLine = JSON.parse(denied.stdout);
    expect(denyLine.outcome).toBe("deny");
    expect(denyLine.notice).toContain(warning.upgrade_command);
    expect(denied.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

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

describe("grokbot-artzain decide, the tool call's arguments", () => {
  it("builds the payload from --arg pairs", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--arg", "to=ops@example.com", "--arg", "subject=Q3 report, final");

    expect(run.status, run.stderr).toBe(0);
    expect(sentPayload(bodies)).toEqual({
      tool: "send_email",
      arguments: { to: "ops@example.com", subject: "Q3 report, final" },
    });
  }, 45_000);

  it("splits an --arg at its first equals sign only", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--arg", "query=a=b&c=d", "--arg", "empty=");

    expect(run.status, run.stderr).toBe(0);
    expect(sentPayload(bodies)).toEqual({
      tool: "send_email",
      arguments: { query: "a=b&c=d", empty: "" },
    });
  }, 45_000);

  // Each of these lines reads as a call with arguments. Sent on as written,
  // the engine would be asked about a call with none, or with other ones.
  it.each([
    { what: "an --arg with no equals sign", args: ["--arg", "ops@example.com"], says: "--arg" },
    { what: "an --arg with no name", args: ["--arg", "=ops@example.com"], says: "--arg" },
    { what: "an --arg name given twice", args: ["--arg", "to=a@example.com", "--arg", "to=b@example.com"], says: "--arg" },
    { what: "--arg beside --payload", args: ["--arg", "to=a@example.com", "--payload", '{"tool":"send_email"}'], says: "--arg" },
    { what: "--arg beside --payload-file", args: ["--arg", "to=a@example.com", "--payload-file", "payload.json"], says: "--arg" },
    { what: "--payload beside --payload-file", args: ["--payload", '{"tool":"send_email"}', "--payload-file", "payload.json"], says: "--payload-file" },
    { what: "an option it does not know", args: ["--args", "to=ops@example.com"], says: "--args" },
    { what: "an option joined to its value by an equals sign", args: ["--arg=to=ops@example.com"], says: "--arg" },
    { what: "a stray word, as an unquoted space leaves one", args: ["--arg", "body=wire", "5000"], says: "not an option" },
    { what: "--payload with nothing after it", args: ["--payload"], says: "--payload" },
    { what: "--payload followed by another option", args: ["--payload", "--target", "mailbox"], says: "--payload" },
    { what: "an empty --payload, as an unset shell variable leaves one", args: ["--payload", ""], says: "--payload" },
    { what: "--payload given twice", args: ["--payload", '{"tool":"a"}', "--payload", '{"tool":"b"}'], says: "--payload" },
    { what: "--target given twice", args: ["--target", "mailbox", "--target", "other"], says: "--target" },
    { what: "--action given twice", args: ["--action", "read_file"], says: "--action" },
    { what: "an --enroll-token, which only enroll takes", args: ["--enroll-token", "one-time"], says: "--enroll-token" },
  ])("blocks on $what without asking the engine", async ({ args, says }) => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decide(base, ...args);

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
    const printed = JSON.parse(run.stdout) as { outcome: string; error: string };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain(says);
  }, 45_000);

  it("blocks without asking the engine when no --action is given", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    // The second is the bare command, which reads as `decide`.
    for (const args of [["decide", "--api-key", "cnx_cli_probe", "--base-url", base], []]) {
      const run = await cli(...args);

      expect(run.status, run.stderr).toBe(2);
      expect(seen).toEqual([]);
      expect((JSON.parse(run.stdout) as { outcome: string }).outcome).toBe("deny");
    }
    const run = await cli("decide", "--api-key", "cnx_cli_probe", "--base-url", base, "--arg", "to=ops@example.com");
    expect((JSON.parse(run.stdout) as { error: string }).error).toContain("--action");
  }, 45_000);

  it("does not repeat an option's value when it refuses the option", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--api-key=hush-hush-value");

    expect(run.status).toBe(2);
    expect(seen).toEqual([]);
    expect(run.stdout + run.stderr).not.toContain("hush-hush-value");
  }, 45_000);

  it.each([
    { what: "empty", bytes: Buffer.alloc(0) },
    { what: "nothing but a byte order mark", bytes: Buffer.from([0xef, 0xbb, 0xbf]) },
    { what: "nothing but white space", bytes: Buffer.from(" \r\n") },
  ])("blocks without asking the engine when the --payload-file is $what", async ({ bytes }) => {
    const { base, seen } = await origin(ALLOW, ALLOW);
    const file = join(outDir, "empty-payload.json");
    writeFileSync(file, bytes);

    const run = await decide(base, "--payload-file", file);

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
    expect((JSON.parse(run.stdout) as { error: string }).error).toContain("--payload-file");
  }, 45_000);

  it.each([
    { encoding: "UTF-8", bytes: (text: string) => Buffer.from(text, "utf8") },
    {
      encoding: "UTF-8 with a byte order mark",
      bytes: (text: string) => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, "utf8")]),
    },
    {
      // What `>` writes in Windows PowerShell 5.1.
      encoding: "UTF-16 with a byte order mark",
      bytes: (text: string) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]),
    },
  ])("reads the payload from a --payload-file in $encoding", async ({ bytes }) => {
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const payload = { tool: "send_email", arguments: { to: "ops@example.com", body: 'He said "é", twice.\n' } };
    const file = join(outDir, "payload.json");
    writeFileSync(file, bytes(JSON.stringify(payload)));

    const run = await decide(base, "--payload-file", file);

    expect(run.status, run.stderr).toBe(0);
    expect(sentPayload(bodies)).toEqual(payload);
  }, 45_000);

  it("blocks without asking the engine when the --payload-file cannot be read", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--payload-file", join(outDir, "no-such-file.json"));

    expect(run.status, run.stderr).toBe(2);
    expect(seen).not.toContain("POST /api/v1/decisions");
    const printed = JSON.parse(run.stdout) as { outcome: string; error: string };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain("--payload-file");
    expect(printed.error).toContain("ENOENT");
  }, 45_000);

  it("reads the payload from stdin when --payload-file is -", async () => {
    const { base, bodies, seen } = await origin(ALLOW, ALLOW);
    const payload = { tool: "send_email", arguments: { to: "ops@example.com", body: 'He said "é".' } };

    const run = await decideStdin(base, Buffer.from(JSON.stringify(payload), "utf8"), "--payload-file", "-");

    expect(run.status, run.stderr).toBe(0);
    expect(seen).toContain("POST /api/v1/decisions");
    expect(sentPayload(bodies)).toEqual(payload);
    const line = JSON.parse(run.stdout) as { outcome: string; decision_id?: string; next_step?: string };
    expect(line.outcome).toBe("allow");
    expect(line.decision_id).toBe("d1");
    expect(line.next_step).toBe("run");
    expect(run.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

  it.each([
    { what: "empty", bytes: Buffer.alloc(0) },
    { what: "nothing but a byte order mark", bytes: Buffer.from([0xef, 0xbb, 0xbf]) },
    { what: "nothing but white space", bytes: Buffer.from(" \r\n") },
  ])("blocks without asking the engine when stdin for --payload-file - is $what", async ({ bytes }) => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decideStdin(base, bytes, "--payload-file", "-");

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
    const printed = JSON.parse(run.stdout) as {
      outcome: string;
      error: string;
      decision_id?: string;
      next_step?: string;
    };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain("the --payload-file is empty");
    expect(printed.error).not.toContain("ENOENT");
    expect(printed.decision_id).toBeUndefined();
    expect(printed.next_step).toBe("do not run");
    expect(run.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

  it("reads a Windows PowerShell 5.1 here-string from stdin", async () => {
    // What `@"..."@ | grokbot-artzain` delivers on Windows PowerShell 5.1:
    // UTF-8 with a byte order mark, and the newline the here-string keeps.
    const { base, bodies } = await origin(ALLOW, ALLOW);
    const payload = '{"tool":"send_email","arguments":{"to":"ops@example.com"}}';
    const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${payload}\r\n`, "utf8")]);

    const run = await decideStdin(base, bytes, "--payload-file", "-");

    expect(run.status, run.stderr).toBe(0);
    expect(sentPayload(bodies)).toEqual(JSON.parse(payload));
  }, 45_000);

  it.runIf(process.platform === "win32")(
    "reads a PowerShell here-string piped to --payload-file -",
    async () => {
      const { base, bodies } = await origin(ALLOW, ALLOW);
      const payload = '{"tool":"send_email","arguments":{"to":"ops@example.com"}}';
      const script = join(outDir, "here-string.ps1");
      const cliPath = join(outDir, "dist", "cli.js");
      const quote = (value: string) => value.split("'").join("''");
      writeFileSync(
        script,
        [
          "@'",
          payload,
          `'@ | & '${quote(process.execPath)}' '${quote(cliPath)}' decide --action send_email --api-key cnx_cli_probe --base-url ${base} --payload-file -`,
          "exit $LASTEXITCODE",
          "",
        ].join("\r\n"),
        "utf8",
      );

      const status = await new Promise<number | null>((resolve, reject) => {
        const child = spawn("powershell.exe", ["-NoProfile", "-File", script], {
          env: cleanEnv(),
          timeout: RUN_TIMEOUT_MS,
          windowsHide: true,
        });
        child.on("error", reject);
        child.on("close", resolve);
      });

      expect(status).toBe(0);
      expect(sentPayload(bodies)).toEqual(JSON.parse(payload));
    },
    45_000,
  );

  it.each([
    {
      what: "an allow",
      decision: ALLOW,
      exit: 0,
      line: { outcome: "allow", decision_id: "d1", next_step: "run" },
    },
    {
      what: "a deny",
      decision: DENY,
      exit: 2,
      line: {
        outcome: "deny",
        decision_id: "d2",
        error: "REFUSED: refused by policy (decision d2)",
        next_step: "do not run",
      },
    },
    {
      what: "a review",
      decision: QUEUED,
      exit: 2,
      line: {
        outcome: "review",
        decision_id: "d3",
        error: "QUEUED FOR REVIEW: needs a person (decision d3)",
        next_step: "wait for review",
      },
    },
  ])("prints next_step and decision_id for $what", async ({ decision, exit, line }) => {
    const { base } = await origin(ALLOW, decision);

    const run = await decide(base);

    expect(run.status, run.stderr).toBe(exit);
    expect(JSON.parse(run.stdout)).toEqual(line);
    expect(run.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

  it.each([
    { what: "HTTP 403", decision: FORBIDDEN, error: "decision unavailable" },
    {
      what: "the account minimum",
      decision: json(422, { detail: { code: "client_too_old", detail: "Run grokbot-artzain upgrade." } }),
      error: "REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.",
    },
  ])("prints next_step and no decision_id when $what has no decision", async ({ decision, error }) => {
    const { base } = await origin(ALLOW, decision);

    const run = await decide(base);

    expect(run.status, run.stderr).toBe(2);
    const printed = JSON.parse(run.stdout) as {
      outcome: string;
      error: string;
      decision_id?: string;
      next_step?: string;
    };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain(error);
    expect(printed.decision_id).toBeUndefined();
    expect(printed.next_step).toBe("do not run");
    expect(run.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

  it("MYAPP_API_KEY alone yields no key plus the warning", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cliEnv(
      { MYAPP_API_KEY: "cnx_legacy_only" },
      "decide",
      "--action",
      "send_email",
      "--base-url",
      base,
    );

    expect(run.status, run.stderr).toBe(2);
    expect(seen).not.toContain("POST /api/v1/decisions");
    const printed = JSON.parse(run.stdout) as { error?: string };
    expect(printed.error).toContain("No API key configured");
    expect(run.stderr).toContain("no key");
    expect(run.stderr).toContain("MYAPP_API_KEY");
    expect(run.stdout + run.stderr).not.toContain("cnx_legacy_only");
  }, 45_000);

  it("prints next_step and no decision_id when no key is configured", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cli("decide", "--action", "send_email", "--base-url", base);

    expect(run.status, run.stderr).toBe(2);
    expect(seen).not.toContain("POST /api/v1/decisions");
    const printed = JSON.parse(run.stdout) as {
      outcome: string;
      error: string;
      decision_id?: string;
      next_step?: string;
    };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain("No API key configured");
    expect(printed.decision_id).toBeUndefined();
    expect(printed.next_step).toBe("do not run");
  }, 45_000);

  it("prints next_step and no decision_id when neither --action nor --tool is given", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cli("decide", "--api-key", "cnx_cli_probe", "--base-url", base);

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
    const printed = JSON.parse(run.stdout) as {
      outcome: string;
      error: string;
      decision_id?: string;
      next_step?: string;
    };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain("--action or --tool is required");
    expect(printed.decision_id).toBeUndefined();
    expect(printed.next_step).toBe("do not run");
    expect(run.stdout.trim().split("\n")).toHaveLength(1);
  }, 45_000);

  it("says why when --payload arrives without its double quotes, as cmd.exe delivers it", async () => {
    const { base, bodies } = await origin(ALLOW, DENY);

    // What `--payload '{"tool":"send_email",…}'` is by the time npm's .cmd
    // shim hands it to Node.
    const stripped = "{tool:send_email,arguments:{to:ops@example.com}}";
    const run = await decide(base, "--payload", stripped);

    // The engine still gets it, and its answer still decides.
    const body = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { payload?: string };
    expect(body.payload).toBe(stripped);
    expect(run.status, run.stderr).toBe(2);
    expect(run.stderr).toContain("--payload is not valid JSON");
    expect(run.stderr).toContain("--arg");
  }, 45_000);

  it("says so when the --payload-file does not hold JSON, and still asks the engine", async () => {
    const { base, bodies } = await origin(ALLOW, DENY);
    const file = join(outDir, "not-json.txt");
    writeFileSync(file, "send the report to ops");

    const run = await decide(base, "--payload-file", file);

    const body = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as { payload?: string };
    expect(body.payload).toBe("send the report to ops");
    expect(run.status, run.stderr).toBe(2);
    expect(run.stderr).toContain("--payload-file does not hold valid JSON");
  }, 45_000);

  it("sends --model, --workload, --session, --parent and --on-behalf-of on the decision", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);

    const run = await decide(
      base,
      "--model", "model-a",
      "--workload", "inbox",
      "--session", "sess-1",
      "--parent", "01PARENT",
      "--on-behalf-of", "alice",
      "--request-id", "req-flags",
    );

    expect(run.status, run.stderr).toBe(0);
    const body = JSON.parse(bodies["/api/v1/decisions"] ?? "{}") as Record<string, unknown>;
    expect(body.model_id).toBe("model-a");
    expect(body.workload_id).toBe("inbox");
    expect(body.request_id).toBe("req-flags");
    expect(body.context).toEqual({ session: "sess-1", parent: "01PARENT", on_behalf_of: "alice" });
  }, 45_000);

  it("says nothing about a --payload that is JSON", async () => {
    const { base } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--payload", '{"tool":"send_email","arguments":{"to":"ops@example.com"}}');

    expect(run.status, run.stderr).toBe(0);
    expect(run.stderr).not.toContain("not valid JSON");
  }, 45_000);

  it.runIf(process.platform === "win32")(
    "keeps --arg pairs whole through cmd.exe and a .cmd shim, as npm installs one on Windows",
    async () => {
      const { base, bodies } = await origin(ALLOW, ALLOW);
      const shim = join(outDir, "grokbot-artzain.cmd");
      writeFileSync(shim, `@"${process.execPath}" "%~dp0\\dist\\cli.js" %*\r\n`);

      const line =
        `"${shim}" decide --action send_email --api-key cnx_cli_probe --base-url ${base} ` +
        '--arg to=ops@example.com --arg "subject=Q3 report, final"';
      const status = await new Promise<number | null>((resolve, reject) => {
        const child = spawn("cmd.exe", ["/d", "/s", "/c", `"${line}"`], {
          env: cleanEnv(),
          timeout: RUN_TIMEOUT_MS,
          windowsHide: true,
          windowsVerbatimArguments: true,
        });
        child.on("error", reject);
        child.on("close", resolve);
      });

      expect(status).toBe(0);
      expect(sentPayload(bodies)).toEqual({
        tool: "send_email",
        arguments: { to: "ops@example.com", subject: "Q3 report, final" },
      });
    },
    45_000,
  );
});

describe("grokbot-artzain profiles", () => {
  const SENTINEL = "cnx_SENTINEL_profile_key_9f3a7c1e";

  it("saves a profile with init --bot and does not store a key", async () => {
    const run = await cliEnv(
      { BOT_API_KEY: SENTINEL },
      "init",
      "--bot",
      "ops",
      "--instance",
      "ops-desk",
      "--base-url",
      "http://127.0.0.1:9",
      "--key-env",
      "BOT_API_KEY",
    );

    expect(run.status, run.stderr).toBe(0);
    const text = readFileSync(run.stdout.trim(), "utf8");
    expect(text).not.toContain(SENTINEL);
    expect(run.stdout + run.stderr).not.toContain(SENTINEL);
    expect(JSON.parse(text)).toEqual({
      agent_id: "ops",
      instance: "ops-desk",
      base_url: "http://127.0.0.1:9",
      key_env: "BOT_API_KEY",
    });
  }, 45_000);

  it("uses flag, then env, then profile, then the default", async () => {
    const { base, bodies, keys } = await origin(ALLOW, ALLOW);
    saveProfile("ops", {
      agent_id: "from-profile",
      instance: "from-profile-host",
      base_url: "http://127.0.0.1:1",
      key_env: "BOT_API_KEY",
    });

    const fromProfile = await cliEnv(
      { BOT_API_KEY: "from-profile-env" },
      "decide",
      "--action",
      "send_email",
      "--profile",
      "ops",
      "--base-url",
      base,
    );
    expect(fromProfile.status, fromProfile.stderr).toBe(0);
    expect(sentDecision(bodies).agent_did).toBe("from-profile");
    expect(keys["/api/v1/decisions"]).toBe("from-profile-env");

    const fromEnv = await cliEnv(
      { GROKBOT_AGENT_ID: "from-env", COGNEXUS_API_KEY: "from-env-key", BOT_API_KEY: "from-profile-env" },
      "decide",
      "--action",
      "send_email",
      "--profile",
      "ops",
      "--base-url",
      base,
    );
    expect(fromEnv.status, fromEnv.stderr).toBe(0);
    expect(sentDecision(bodies).agent_did).toBe("from-env");
    expect(keys["/api/v1/decisions"]).toBe("from-env-key");

    const fromFlag = await cliEnv(
      { GROKBOT_AGENT_ID: "from-env", GROKBOT_BOT: "ops" },
      "decide",
      "--action",
      "send_email",
      "--agent-did",
      "from-flag",
      "--api-key",
      "from-flag-key",
      "--base-url",
      base,
    );
    expect(fromFlag.status, fromFlag.stderr).toBe(0);
    expect(sentDecision(bodies).agent_did).toBe("from-flag");
    expect(keys["/api/v1/decisions"]).toBe("from-flag-key");

    saveProfile("near", { agent_id: "from-profile", base_url: "http://127.0.0.1:1" });
    const baseFromEnv = await cliEnv(
      { COGNEXUS_API_BASE_URL: base, COGNEXUS_API_KEY: "from-env-key", GROKBOT_BOT: "near" },
      "decide",
      "--action",
      "send_email",
    );
    expect(baseFromEnv.status, baseFromEnv.stderr).toBe(0);
    expect(sentDecision(bodies).agent_did).toBe("from-profile");

    const baseFromFlag = await cliEnv(
      { COGNEXUS_API_BASE_URL: "http://127.0.0.1:1", COGNEXUS_API_KEY: "from-env-key" },
      "decide",
      "--action",
      "send_email",
      "--profile",
      "near",
      "--base-url",
      base,
    );
    expect(baseFromFlag.status, baseFromFlag.stderr).toBe(0);
  }, 45_000);

  it("warns on stderr when a decide falls back to grokbot-agent", async () => {
    const { base, bodies, seen } = await origin(ALLOW, ALLOW);

    const run = await cli("decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base);

    expect(run.status, run.stderr).toBe(0);
    expect(seen).toContain("POST /api/v1/decisions");
    expect(sentDecision(bodies).agent_did).toBe("grokbot-agent");
    expect(run.stderr).toContain("grokbot-agent");
  }, 45_000);

  it("reads COGNEXUS_AGENT_DID when GROKBOT_AGENT_ID is unset", async () => {
    const { base, bodies } = await origin(ALLOW, ALLOW);

    const run = await cliEnv(
      { COGNEXUS_AGENT_DID: "from-did", COGNEXUS_API_KEY: "from-env-key" },
      "decide",
      "--action",
      "send_email",
      "--base-url",
      base,
    );

    expect(run.status, run.stderr).toBe(0);
    expect(sentDecision(bodies).agent_did).toBe("from-did");
    expect(run.stderr).not.toContain("no agent id was given");
  }, 45_000);

  it("exits 2 before any network call when GROKBOT_REQUIRE_IDENTITY=1 and no agent id was given", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cliEnv(
      { GROKBOT_REQUIRE_IDENTITY: "1" },
      "decide",
      "--action",
      "send_email",
      "--api-key",
      "cnx_cli_probe",
      "--base-url",
      base,
    );

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
    const printed = JSON.parse(run.stdout) as { outcome: string; error: string };
    expect(printed.outcome).toBe("deny");
    expect(printed.error).toContain("GROKBOT_REQUIRE_IDENTITY");
  }, 45_000);
});

const REVIEW = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

describe("grokbot-artzain review-status", () => {
  it("prints the status and does not decide or resolve", async () => {
    const { base, seen } = await origin(
      ALLOW,
      json(200, { decision_id: REVIEW, status: "approved", notes: "kept off the wire" }),
    );
    const run = await cli("review-status", REVIEW, "--api-key", "cnx_cli_probe", "--base-url", base);
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout)).toEqual({ decision_id: REVIEW, status: "approved" });
    expect(run.stdout).not.toContain("cnx_cli_probe");
    expect(run.stderr).not.toContain("cnx_cli_probe");
    expect(run.stdout).not.toContain("notes");
    expect(seen.some((line) => line.startsWith("POST "))).toBe(false);
    expect(seen).toContain(`GET /api/v1/decisions/${REVIEW}/review`);
  }, 45_000);

  it("fails closed when the review cannot be read", async () => {
    const { base, seen } = await origin(ALLOW, json(404, { detail: "No review with that id for this account." }));
    const run = await cli("review-status", REVIEW, "--api-key", "cnx_cli_probe", "--base-url", base);
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toContain("Failing closed");
    expect(run.stdout).not.toContain("approved");
    expect(seen.some((line) => line.startsWith("POST "))).toBe(false);
  }, 45_000);
});

describe("grokbot-artzain evidence", () => {
  const key = "cnx_SENTINEL_evidence_key";

  it("prints export, then verify, when the decision is sealed", async () => {
    const { base, seen } = await origin(
      ALLOW,
      json(200, {
        decisions: [{ decision_id: REVIEW, leaf_id: "01LEAF00000000000000000000", outcome: "allow" }],
        next_cursor: null,
        count: 1,
      }),
    );
    const run = await cli("evidence", REVIEW, "--api-key", key, "--base-url", base);
    expect(run.status, run.stderr).toBe(0);
    const exportAt = run.stdout.indexOf("artzain audit export");
    const verifyAt = run.stdout.indexOf("artzain audit verify");
    expect(exportAt).toBeGreaterThanOrEqual(0);
    expect(verifyAt).toBeGreaterThan(exportAt);
    expect(run.stdout).toContain(
      "Receipts verify as SELF-ATTESTED until the Evidence Root is published.",
    );
    expect(run.stdout).not.toContain("VERIFIED");
    expect(run.stdout).not.toContain("allow");
    expect(run.stdout).not.toContain(key);
    expect(run.stderr).not.toContain(key);
    expect(seen).toEqual([`GET /api/v1/audit/decisions?decision=${REVIEW}`]);
  }, 45_000);

  it("prints neither command when the decision is not sealed", async () => {
    const { base, seen } = await origin(
      ALLOW,
      json(200, { decisions: [], next_cursor: null, count: 0 }),
    );
    const run = await cli("evidence", REVIEW, "--api-key", key, "--base-url", base);
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("no sealed decision");
    expect(run.stderr).not.toContain("SELF-ATTESTED");
    expect(run.stderr).not.toContain("artzain audit");
    expect(run.stderr).not.toContain(key);
    expect(seen).toEqual([`GET /api/v1/audit/decisions?decision=${REVIEW}`]);
  }, 45_000);

  it("does not print a value that is not a decision id", async () => {
    const run = await cli("evidence", key);
    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("26 letters and digits");
    expect(run.stderr).not.toContain(key);
  }, 45_000);
});

describe("grokbot-artzain, the commands that ask nothing of the engine", () => {
  it("prints the package's version", async () => {
    const { version } = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string };

    for (const flag of ["--version", "-v"]) {
      const run = await cli(flag);

      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout.trim()).toBe(version);
    }
  }, 45_000);

  it("prints its usage and exits 0 when asked for help", async () => {
    for (const flag of ["--help", "-h", "help"]) {
      const run = await cli(flag);

      expect(run.status, run.stderr).toBe(0);
      for (const command of ["decide", "announce", "enroll", "skill", "doctor", "upgrade", "review-status", "evidence", "init", "mcp", "shims", "--enforce", "--http", "--port", "--arg", "--tool", "--bot", "--profile", "--cites-review", "--json", "--offline", "--yes", "--skill", "--force", "--check", "COGNEXUS_API_KEY"]) {
        expect(run.stdout).toContain(command);
      }
    }
  }, 45_000);

  it("refuses an option upgrade does not take, and runs nothing", async () => {
    const run = await cli("upgrade", "--decide");

    expect(run.status).toBe(2);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("not an option of upgrade");
  }, 45_000);

  it("refuses extra words on mcp before it listens", async () => {
    const run = await cli("mcp", "decide", "--action", "send_email");

    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("a word that is not an option");
  }, 45_000);

  it("refuses mcp --http without a port, and a port without --http", async () => {
    const http = await cli("mcp", "--http");
    const port = await cli("mcp", "--port", "9");

    expect(http.status, http.stderr).toBe(2);
    expect(http.stdout).toBe("");
    expect(http.stderr).toContain("--http and --port go together");
    expect(port.status, port.stderr).toBe(2);
    expect(port.stdout).toBe("");
    expect(port.stderr).toContain("--http and --port go together");
  }, 45_000);

  it("refuses an option doctor does not take, and asks the engine nothing", async () => {
    const run = await cli("doctor", "--decide");

    expect(run.status).toBe(2);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("not an option of doctor");
  }, 45_000);

  it("still exits 2 on a command it does not know", async () => {
    // The last three are names every JavaScript object answers to.
    for (const command of ["approve", "toString", "constructor", "__proto__"]) {
      const run = await cli(command);

      expect(run.status).toBe(2);
      expect(run.stdout).toBe("");
      expect(run.stderr).toContain("usage: grokbot-artzain");
    }
  }, 45_000);

  it.each(["--help", "--version"])("refuses %s after `decide`, where it is not an option", async (flag) => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decide(base, flag);

    expect(run.status, run.stderr).toBe(2);
    expect(seen).toEqual([]);
  }, 45_000);

  // A caller acts on exit 0, so no line that holds a decide call may exit 0
  // unless the engine allowed that call.
  it.each([
    { front: ["--help"] },
    { front: ["help"] },
    { front: ["--version"] },
    { front: ["skill"] },
    { front: ["enroll"] },
    { front: ["announce", "--instance", "ops-desk"] },
  ])("exits 2, with nothing sent, when $front is put in front of a decide call", async ({ front }) => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cli(...front, "decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base);

    expect(run.status).toBe(2);
    expect(run.stdout).toBe("");
    expect(seen).toEqual([]);
  }, 45_000);

  it("lists every setting it reads in its help", async () => {
    const run = await cli("--help");

    for (const name of [
      "GROKBOT_AGENT_ID", "GROKBOT_INSTANCE", "GROKBOT_ANNOUNCE", "GROKBOT_ENROLL", "GROKBOT_ENROLL_TOKEN",
      "GROKBOT_ENROLL_TTL_HOURS",
      "GROKBOT_ANNOUNCE_AGENTS", "GROKBOT_ANNOUNCE_SKILLS", "GROKBOT_BOT", "GROKBOT_REQUIRE_IDENTITY",
      "COGNEXUS_API_KEY", "COGNEXUS_API_BASE_URL", "COGNEXUS_AGENT_DID",
      "--payload-file", "--request-id", "--profile", "--model", "--workload", "--session", "--parent",
      "--on-behalf-of", "--queue", "--no-enroll", "--enroll-token",
    ]) {
      expect(run.stdout).toContain(name);
    }
  }, 45_000);

  it("names the setting when a decide is told to announce and has no instance name", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await decide(base, "--announce");

    // The decision is unaffected, and no announce goes out without a name.
    expect(run.status, run.stderr).toBe(0);
    expect(seen).not.toContain("POST /api/v1/registry/announce");
    expect(run.stderr).toContain("GROKBOT_INSTANCE");
  }, 45_000);

  it("prints where the SKILL.md it ships is", async () => {
    const run = await cli("skill");

    expect(run.status, run.stderr).toBe(0);
    const path = run.stdout.trim();
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path, "utf8")).toBe(readFileSync(join(here, "..", "SKILL.md"), "utf8"));
  }, 45_000);

  it("pins the skill footer to the version in package.json", () => {
    const { version } = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string };
    const text = readFileSync(join(here, "..", "SKILL.md"), "utf8");
    const parts = text.split(/^---\s*$/m);
    const front = parts[1] ?? "";
    const body = parts.slice(2).join("---");
    const line = `Skill text for grokbot-artzain ${version}`;

    expect(front).not.toContain(line);
    expect(body.trimEnd().split(/\r?\n/).at(-1)).toBe(line);
  });

  it("reports an older installed skill as behind", async () => {
    const older = join(outDir, "saved-skill.md");
    // The doctor line matches this package. The footer is the one --check reads.
    writeFileSync(
      older,
      "Instructions the Bot saved.\n\nSkill text version: 0.1.10\nSkill text for grokbot-artzain 0.1.0\n",
    );

    const run = await cli("skill", "--check", older);

    expect(run.status, run.stderr).toBe(1);
    expect(run.stdout).toContain("behind");
    expect(run.stdout).not.toContain("current");
  }, 45_000);

  it("reports the packaged skill as current", async () => {
    const where = await cli("skill");
    expect(where.status, where.stderr).toBe(0);

    const run = await cli("skill", "--check", where.stdout.trim());

    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("current");
    expect(run.stdout).not.toContain("behind");
  }, 45_000);

  it("exits 2 when the installed skill has no footer, and does not call it current", async () => {
    const saved = join(outDir, "saved-skill-no-footer.md");
    writeFileSync(saved, "Instructions the Bot saved.\n\nSkill text version: 0.1.10\n");

    const run = await cli("skill", "--check", saved);

    expect(run.status, run.stderr).toBe(2);
    expect(run.stdout).not.toContain("current");
    expect(run.stdout).not.toContain("behind");
  }, 45_000);

  it("names the setting when announce has no instance name", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cli("announce", "--api-key", "cnx_cli_probe", "--base-url", base);

    expect(run.status).toBe(2);
    expect(seen).toEqual([]);
    expect(run.stderr).toContain("GROKBOT_INSTANCE");
    expect(run.stderr).toContain("--instance");
  }, 45_000);
});

function sandRoot(ids: string[], active?: string): string {
  const root = mkdtempSync(join(tmpdir(), "grokbot-cli-sand-"));
  const agents = join(root, "agents");
  mkdirSync(agents, { recursive: true });
  for (const id of ids) mkdirSync(join(agents, id));
  if (active) {
    writeFileSync(join(agents, "active-agent.json"), JSON.stringify({ activeAgentId: active }), "utf8");
  }
  return root;
}

function announceStateFile(): string {
  return process.platform === "win32"
    ? join(cliHome, "AppData", "Roaming", "grokbot-artzain", "state.json")
    : join(cliHome, ".config", "grokbot-artzain", "state.json");
}

describe("announce profiles", () => {
  it("announces the current profile and not the profile description", async () => {
    const root = sandRoot(["research-bot", "other-bot"], "research-bot");
    writeFileSync(
      join(root, "agents", "research-bot", "profile.json"),
      JSON.stringify({ description: "SECRET-PROMPT" }),
      "utf8",
    );
    const { base, announceBodies } = await origin(ALLOW, ALLOW);

    const run = await runCli(
      ["announce", "--api-key", "cnx_cli_probe", "--base-url", base, "--instance", "one-desk"],
      undefined,
      { SAND_DATA_ROOT: root },
    );

    expect(run.status, run.stderr).toBe(0);
    expect(announceBodies).toHaveLength(1);
    const body = JSON.parse(announceBodies[0] ?? "{}") as { agents?: string[]; instance?: string };
    expect(body.agents).toEqual(["research-bot"]);
    expect(body.instance).toBe("one-desk");
    expect(announceBodies[0]).not.toContain("other-bot");
    expect(announceBodies[0]).not.toContain("SECRET-PROMPT");
    expect(announceBodies[0]).not.toContain("cnx_cli_probe");
  }, 45_000);

  it("sends every profile in calls of 25", async () => {
    const ids = Array.from({ length: 26 }, (_, i) => `bot-${String(i).padStart(2, "0")}`);
    const root = sandRoot(ids);
    const { base, announceBodies } = await origin(ALLOW, ALLOW);

    const run = await runCli(
      ["announce", "--all-profiles", "--api-key", "cnx_cli_probe", "--base-url", base, "--instance", "split-desk"],
      undefined,
      { SAND_DATA_ROOT: root },
    );

    expect(run.status, run.stderr).toBe(0);
    const sent = announceBodies.map((raw) => (JSON.parse(raw) as { agents: string[] }).agents);
    expect(sent.map((agents) => agents.length)).toEqual([25, 1]);
    expect(sent.flat()).toEqual([...ids].sort((a, b) => a.localeCompare(b)));
  }, 45_000);

  it("skips an agent announced within 24 hours unless --force", async () => {
    const root = sandRoot(["skip-bot"], "skip-bot");
    const { base, announceBodies } = await origin(ALLOW, ALLOW);
    const args = ["announce", "--api-key", "cnx_cli_probe", "--base-url", base, "--instance", "skip-desk"];

    const first = await runCli(args, undefined, { SAND_DATA_ROOT: root });
    expect(first.status, first.stderr).toBe(0);
    expect(announceBodies).toHaveLength(1);

    const second = await runCli(args, undefined, { SAND_DATA_ROOT: root });
    expect(second.status, second.stderr).toBe(0);
    expect(second.stderr).toContain("skip-bot was announced within 24 hours");
    expect(announceBodies).toHaveLength(1);

    const forced = await runCli([...args, "--force"], undefined, { SAND_DATA_ROOT: root });
    expect(forced.status, forced.stderr).toBe(0);
    expect(announceBodies).toHaveLength(2);
    expect(existsSync(announceStateFile())).toBe(true);
    expect(readFileSync(announceStateFile(), "utf8")).not.toContain("cnx_cli_probe");
  }, 45_000);
});

describe("decide --queue", () => {
  it("stores an unreachable decide, and the action stays unallowed", async () => {
    const down = await origin(ALLOW, (res) => {
      res.socket?.destroy();
    });

    const run = await decide(
      down.base,
      "--queue",
      "--request-id",
      "order-8812",
      "--arg",
      "to=ops@example.com",
    );
    const sent = JSON.parse(down.bodies["/api/v1/decisions"] ?? "{}") as { request_id?: string; payload?: string };
    await closeOrigin();

    expect(run.status, run.stderr).toBe(2);
    const verdict = JSON.parse(run.stdout) as { outcome?: string };
    expect(verdict.outcome).toBe("deny");
    const stored = queuedTexts().filter((text) => text.includes("order-8812"));
    expect(stored).toHaveLength(1);
    const saved = JSON.parse(stored[0] ?? "{}") as { payload?: string; request_id?: string };
    expect(saved.request_id).toBe("order-8812");
    expect(saved.payload).toBe(sent.payload);
    expect(saved.payload).toContain("ops@example.com");
    expect(stored[0]).not.toContain("cnx_cli_probe");
    expect(sent.request_id).toBe("order-8812");

    const up = await origin(ALLOW, ALLOW);
    const retry = await cli("queue", "retry", "--api-key", "cnx_cli_probe", "--base-url", up.base);
    const again = JSON.parse(up.bodies["/api/v1/decisions"] ?? "{}") as { request_id?: string; payload?: string };
    const recorded = JSON.parse(retry.stdout) as { recorded?: string; outcome?: string; request_id?: string };

    expect(retry.status, retry.stderr).toBe(2);
    expect(recorded.recorded).toBe("allow");
    expect(recorded.outcome).toBeUndefined();
    expect(recorded.request_id).toBe("order-8812");
    expect(again.request_id).toBe("order-8812");
    expect(again.payload).toBe(saved.payload);
    expect(queuedTexts().some((text) => text.includes("order-8812"))).toBe(false);
  }, 45_000);

  it("leaves a reached allow and a reached deny out of the queue", async () => {
    const { base } = await origin(ALLOW, ALLOW);
    const allowed = await decide(base, "--queue", "--request-id", "reached-allow");
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(queuedTexts().some((text) => text.includes("reached-allow"))).toBe(false);
    await closeOrigin();

    const refused = await origin(ALLOW, DENY);
    const denied = await decide(refused.base, "--queue", "--request-id", "reached-deny");
    expect(denied.status, denied.stderr).toBe(2);
    expect(JSON.parse(denied.stdout).outcome).toBe("deny");
    expect(queuedTexts().some((text) => text.includes("reached-deny"))).toBe(false);
  }, 45_000);
});
