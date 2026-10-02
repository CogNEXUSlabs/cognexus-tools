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
import { copyFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

/**
 * A local origin that answers enroll with `enroll` and everything else with
 * `other`. `bodies` holds the last request body each path was sent.
 */
async function origin(
  enroll: Answer,
  other: Answer,
): Promise<{ base: string; seen: string[]; bodies: Record<string, string> }> {
  const seen: string[] = [];
  const bodies: Record<string, string> = {};
  server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    let body = "";
    req.setEncoding("utf8").on("data", (chunk: string) => (body += chunk));
    req.on("end", () => {
      bodies[req.url ?? ""] = body;
      (req.url === "/api/v1/registry/enroll" ? enroll : other)(res);
    });
  });
  server.keepAliveTimeout = KEEP_ALIVE_MS;
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen, bodies };
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

/** The environment a run gets: the CLI's own settings come only from its flags. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (/^(COGNEXUS_|GROKBOT_)/.test(name) || name === "MYAPP_API_KEY") delete env[name];
  }
  return env;
}

/** Runs `grokbot-artzain decide` against `base` with enroll on (no flag turns it off). */
function decide(base: string, ...more: string[]): Promise<Run> {
  return cli("decide", "--action", "send_email", "--api-key", "cnx_cli_probe", "--base-url", base, ...more);
}

/** Runs the CLI with these arguments. */
function cli(...args: string[]): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(outDir, "dist", "cli.js"), ...args],
      { env: cleanEnv(), timeout: RUN_TIMEOUT_MS, windowsHide: true },
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
      for (const command of ["decide", "announce", "enroll", "skill", "--arg", "COGNEXUS_API_KEY"]) {
        expect(run.stdout).toContain(command);
      }
    }
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
      "GROKBOT_ANNOUNCE_AGENTS", "GROKBOT_ANNOUNCE_SKILLS", "COGNEXUS_API_KEY", "COGNEXUS_API_BASE_URL",
      "--payload-file", "--request-id", "--no-enroll", "--enroll-token",
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

  it("names the setting when announce has no instance name", async () => {
    const { base, seen } = await origin(ALLOW, ALLOW);

    const run = await cli("announce", "--api-key", "cnx_cli_probe", "--base-url", base);

    expect(run.status).toBe(2);
    expect(seen).toEqual([]);
    expect(run.stderr).toContain("GROKBOT_INSTANCE");
    expect(run.stderr).toContain("--instance");
  }, 45_000);
});
