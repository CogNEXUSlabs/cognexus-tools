/**
 * The wrappers parse each command, ask for a decision, and run the real
 * binary only when the profile's mode says to. Install and uninstall are
 * checked with a real `bash -c`.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmodSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { readProfile, writeProfile } from "../profile.js";
import { setStateDirectoryForTests } from "../state.js";
import { bashProgram, installShims, uninstallShims } from "./install.js";
import { planShim, type ShimContext } from "./parse.js";
import { BLOCKED, runGuarded } from "./run.js";
import { findRealBinary, localBin } from "./which.js";

const ctx = (cwd = "/workspace/app"): ShimContext => ({ cwd, env: {}, home: "/home/bot" });

function plan(command: string, args: string[], cwd?: string) {
  return planShim(command, args, ctx(cwd)).target;
}

describe("argument parsing", () => {
  it("gates curl and wget only when the request is not a GET", () => {
    expect(plan("curl", ["https://example.com"])).toBeUndefined();
    expect(plan("curl", ["-sS", "https://example.com/a"])).toBeUndefined();
    expect(plan("curl", ["-G", "-d", "a=b", "https://example.com"])).toBeUndefined();
    expect(plan("curl", ["-X", "GET", "https://example.com"])).toBeUndefined();
    expect(plan("curl", ["-X", "POST", "https://api.example.com/v1"])).toBe("shell:host/api.example.com");
    expect(plan("curl", ["-XPOST", "https://user:secret@api.example.com/v1"])).toBe("shell:host/api.example.com");
    expect(plan("curl", ["-d", "a=b", "https://example.com/submit"])).toBe("shell:host/example.com");
    expect(plan("curl", ["-I", "https://example.com"])).toBe("shell:host/example.com");
    expect(plan("curl", ["--json", "{}", "https://files.example.com/a"])).toBe("shell:host/files.example.com");

    expect(plan("wget", ["https://example.com/file"])).toBeUndefined();
    expect(plan("wget", ["--method=GET", "https://example.com"])).toBeUndefined();
    expect(plan("wget", ["--post-data=hi", "https://files.example.com/a"])).toBe("shell:host/files.example.com");
    expect(plan("wget", ["--method", "PUT", "https://files.example.com/a"])).toBe("shell:host/files.example.com");
  });

  it("gates git push, gh writes, npm publish, and aws mutations", () => {
    expect(plan("git", ["status"])).toBeUndefined();
    expect(plan("git", ["-C", "/repo", "push"])).toBe("shell:host/origin");
    expect(plan("git", ["push", "origin", "main"])).toBe("shell:host/origin");
    expect(plan("git", ["push", "git@github.com:acme/app.git"])).toBe("shell:host/github.com");
    expect(plan("git", ["push", "https://github.com/acme/app.git", "main"])).toBe("shell:host/github.com");

    expect(plan("gh", ["pr", "view", "1"])).toBeUndefined();
    expect(plan("gh", ["pr", "create"])).toBe("shell:host/github.com");
    expect(plan("gh", ["pr", "create", "-R", "acme/app"])).toBe("shell:host/github.com/acme/app");
    expect(plan("gh", ["api", "user"])).toBeUndefined();
    expect(plan("gh", ["api", "-X", "POST", "repos/acme/app"])).toBe("shell:host/github.com");
    expect(plan("gh", ["issue", "list"])).toBeUndefined();

    expect(plan("npm", ["install", "left-pad"])).toBeUndefined();
    expect(plan("npm", ["publish"])).toBe("shell:host/registry.npmjs.org");
    expect(plan("npm", ["publish", "--registry", "https://npm.example.com"])).toBe("shell:host/npm.example.com");

    expect(plan("aws", ["s3", "ls"])).toBeUndefined();
    expect(plan("aws", ["s3", "cp", "a", "b"])).toBe("shell:host/s3");
    expect(plan("aws", ["ec2", "describe-instances"])).toBeUndefined();
    expect(plan("aws", ["ec2", "terminate-instances", "--instance-ids", "i-1"])).toBe("shell:host/ec2");
    expect(plan("aws", ["s3api", "get-object", "--bucket", "b", "--key", "k", "out"])).toBeUndefined();
    expect(plan("aws", ["s3api", "put-object", "--bucket", "b", "--key", "k"])).toBe("shell:host/s3api");
  });

  it("gates ssh, scp, and rm -rf outside /tmp and /workspace", () => {
    expect(plan("ssh", ["user@bastion.example.com"])).toBe("shell:host/bastion.example.com");
    expect(plan("ssh", ["-p", "2222", "bastion.example.com", "uname"])).toBe("shell:host/bastion.example.com");
    expect(plan("scp", ["notes.txt", "user@bastion.example.com:notes"])).toBe("shell:host/bastion.example.com");
    expect(plan("scp", ["user@bastion.example.com:notes", "."])).toBe("shell:host/bastion.example.com");

    expect(plan("rm", ["file"])).toBeUndefined();
    expect(plan("rm", ["-rf", "/tmp/cache"])).toBeUndefined();
    expect(plan("rm", ["-rf", "/workspace/app/out"])).toBeUndefined();
    expect(plan("rm", ["-rf", "cache"], "/workspace/app")).toBeUndefined();
    expect(plan("rm", ["-rf", "/var/data"])).toBe("shell:host/var/data");
    expect(plan("rm", ["-fr", "/opt"])).toBe("shell:host/opt");
    expect(plan("rm", ["-r", "-f", "/opt"])).toBe("shell:host/opt");
    expect(plan("rm", ["--recursive", "--force", "/opt"])).toBe("shell:host/opt");
    expect(plan("rm", ["-rf", "/tmp", "/etc"])).toBe("shell:host/etc");
    expect(plan("rm", ["-rf", "/tmp-secret"])).toBe("shell:host/tmp-secret");
    expect(plan("rm", ["-rf", "/tmp/../etc"])).toBe("shell:host/etc");
    expect(plan("rm", ["-rf", "x"], "/home/bot")).toBe("shell:host/home/bot/x");
  });
});

describe("log-only and enforce", () => {
  const call = ["-X", "POST", "https://secret.example/token"];

  async function run(mode: "log-only" | "enforce", decide: () => Promise<{ outcome: string; reason: string }>) {
    const spawned: string[][] = [];
    const notes: string[] = [];
    const code = await runGuarded("curl", call, ctx(), {
      mode,
      decide: async (target, argv) => {
        expect(target).toBe("shell:host/secret.example");
        expect(argv[0]).toBe("curl");
        return decide();
      },
      findBinary: () => "/usr/bin/curl",
      spawnPath: async (file, args) => {
        spawned.push([file, ...args]);
        return 0;
      },
      stderr: (line) => notes.push(line),
    });
    return { code, spawned, notes };
  }

  it("records a deny and still runs the real binary in log-only mode", async () => {
    const result = await run("log-only", async () => ({ outcome: "deny", reason: "policy denied this call" }));
    expect(result.code).toBe(0);
    expect(result.spawned).toEqual([["/usr/bin/curl", ...call]]);
    expect(result.notes.join("\n")).not.toContain("secret.example");
  });

  it("runs in log-only mode when the decision cannot be asked", async () => {
    const result = await run("log-only", async () => {
      throw new Error("down");
    });
    expect(result.code).toBe(0);
    expect(result.spawned).toHaveLength(1);
    expect(result.notes.join("\n")).not.toContain("secret.example");
  });

  it("exits 126 in enforce mode and does not run the binary", async () => {
    const result = await run("enforce", async () => ({ outcome: "deny", reason: "policy denied this call" }));
    expect(result.code).toBe(BLOCKED);
    expect(result.spawned).toEqual([]);
    expect(result.notes.join("\n")).toContain("policy denied this call");
    expect(result.notes.join("\n")).not.toContain("secret.example");
  });

  it("runs the real binary in enforce mode only after allow", async () => {
    const result = await run("enforce", async () => ({ outcome: "allow", reason: "" }));
    expect(result.code).toBe(0);
    expect(result.spawned).toEqual([["/usr/bin/curl", ...call]]);
  });

  it("records a line when the command runs, and not when enforce blocks it", async () => {
    const recorded: { decision_id: string; target: string; action: string }[] = [];
    const deps = {
      findBinary: () => "/usr/bin/curl",
      spawnPath: async () => 0,
      stderr: () => undefined,
      record: async (row: { decision_id: string; target: string; action: string }) => {
        recorded.push(row);
      },
    };
    await runGuarded("curl", call, ctx(), {
      ...deps,
      mode: "log-only",
      decide: async () => ({ outcome: "deny", reason: "policy denied this call", decisionId: "dec-1", agent: "ops-bot" }),
    });
    await runGuarded("curl", call, ctx(), {
      ...deps,
      mode: "enforce",
      decide: async () => ({ outcome: "deny", reason: "policy denied this call" }),
    });
    expect(recorded).toEqual([
      expect.objectContaining({
        agent: "ops-bot",
        action: "run_command",
        target: "shell:host/secret.example",
        decision_id: "dec-1",
      }),
    ]);
    expect(JSON.stringify(recorded)).not.toContain("token");
  });
});

describe("finding the real binary", () => {
  it("skips ~/.local/bin and a wrapper copied elsewhere", async () => {
    const home = await mkdtemp(join(tmpdir(), "shim-which-"));
    try {
      const local = localBin(home);
      const real = join(home, "usr-bin");
      const copy = join(home, "other");
      mkdirSync(local, { recursive: true });
      mkdirSync(real, { recursive: true });
      mkdirSync(copy, { recursive: true });
      writeFileSync(join(local, "curl"), "#!/usr/bin/env bash\n# grokbot-artzain-shim\n");
      writeFileSync(join(copy, "curl"), "#!/usr/bin/env bash\n# grokbot-artzain-shim\n");
      writeFileSync(join(real, "curl"), "real");
      const pathEnv = [local, copy, real].join(delimiter);
      expect(findRealBinary("curl", pathEnv, home)).toBe(join(real, "curl"));
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

describe("install and uninstall", () => {
  let home = "";
  let state = "";

  afterEach(async () => {
    setStateDirectoryForTests(undefined);
    if (home) await rm(home, { recursive: true, force: true });
    if (state) await rm(state, { recursive: true, force: true });
    home = "";
    state = "";
  });

  async function prepared(): Promise<{ bin: string; env: NodeJS.ProcessEnv }> {
    home = await mkdtemp(join(tmpdir(), "shim-home-"));
    state = await mkdtemp(join(tmpdir(), "shim-state-"));
    setStateDirectoryForTests(state);
    const written = await writeProfile("ops", { agent_id: "ops-bot", key_env: "BOT_API_KEY" });
    expect("path" in written).toBe(true);
    const bin = localBin(home);
    mkdirSync(bin, { recursive: true });
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      PATH: [bin, process.env.PATH].filter(Boolean).join(delimiter),
    };
    return { bin, env };
  }

  it("fails when bash -c command -v curl does not resolve to the shim", async () => {
    const { bin, env } = await prepared();
    const decoy = join(home, "decoy");
    mkdirSync(decoy);
    writeFileSync(join(decoy, "curl"), "#!/usr/bin/env bash\necho decoy\n");
    chmodSync(join(decoy, "curl"), 0o755);
    env.PATH = [decoy, bin, process.env.PATH].filter(Boolean).join(delimiter);
    const installed = await installShims({ home, profile: "ops", mode: "log-only", env });
    expect(installed.ok).toBe(false);
    expect(readdirSync(bin)).toEqual([]);
    expect(await readFile(join(decoy, "curl"), "utf8")).toContain("decoy");
    const profile = await readProfile("ops");
    expect(profile.shims).toBeUndefined();
  }, 20_000);

  it("installs the wrappers and uninstall removes only those files", async () => {
    const { bin, env } = await prepared();
    writeFileSync(join(bin, "grokbot-artzain"), "the command\n");
    writeFileSync(join(bin, "notes.txt"), "keep\n");
    const installed = await installShims({ home, profile: "ops", mode: "log-only", env });
    expect(installed.ok, "message" in installed ? installed.message : "").toBe(true);
    const profile = await readProfile("ops");
    expect(profile.shims).toBe("log-only");
    expect(profile.key_env).toBe("BOT_API_KEY");
    await promisify(execFile)(
      bashProgram(),
      ["--noprofile", "--norc", "-c", "p=$(command -v curl) || exit 1; grep -q grokbot-artzain-shim \"$p\" </dev/null"],
      { env, windowsHide: true, timeout: 8000 },
    );
    const removed = await uninstallShims(home);
    expect(removed.ok).toBe(true);
    expect(readdirSync(bin).sort()).toEqual(["grokbot-artzain", "notes.txt"]);
    const after = await readProfile("ops");
    expect(after.shims).toBeUndefined();
    expect(after.agent_id).toBe("ops-bot");
  }, 20_000);
});
