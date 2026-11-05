/**
 * `grokbot-artzain upgrade` prints the install command for this copy and
 * runs it only with `--yes`. These tests inject the binary path, the
 * registry answer, and the child process.
 */

import { describe, expect, it } from "vitest";

import { runUpgrade, type SpawnCall, type UpgradeInput } from "./upgrade.js";

const SENTINEL = "cnx_SENTINEL_upgrade_key_9f3a7c1e";
const LATEST = "9.9.9";
const PKG = `@cognexuslabs/grokbot-artzain@${LATEST}`;
const HOME = "/home/ada";
const SKILLS = `${HOME}/.config/grokbot-artzain/skills`;
const PACKAGED = "alpha\nbeta\n";
const INSTALLED = "alpha\nold\n";

function input(over: Partial<UpgradeInput> = {}): UpgradeInput & { calls: SpawnCall[] } {
  const calls: SpawnCall[] = [];
  const files = new Map<string, string>([
    [`${SKILLS}/SKILL.md`, INSTALLED],
  ]);
  return {
    calls,
    binPath: "/usr/local/lib/node_modules/@cognexuslabs/grokbot-artzain/dist/cli.js",
    platform: "linux",
    globalPrefix: "/usr/local",
    home: HOME,
    latest: LATEST,
    packageVersion: "0.1.10",
    packagedSkill: PACKAGED,
    skillsDir: SKILLS,
    yes: false,
    env: { COGNEXUS_API_KEY: SENTINEL, PATH: "/usr/local/bin" },
    spawn: async (call) => {
      calls.push(call);
      return { status: 0 };
    },
    readFile: (path) => {
      const text = files.get(path);
      if (text === undefined) {
        const err = new Error("missing") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      }
      return text;
    },
    writeFile: (path, text) => {
      files.set(path, text);
    },
    ...over,
  };
}

function rendered(result: { stdout: string; stderr: string }): string {
  return `${result.stdout}\n${result.stderr}`;
}

describe("grokbot-artzain upgrade", () => {
  it("prints the global install command and does not run it", async () => {
    const spec = input();
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain(`npm install -g ${PKG}`);
    expect(spec.calls).toEqual([]);
    expect(rendered(result)).not.toContain(SENTINEL);
  });

  it("runs the global install only with --yes", async () => {
    const spec = input({ yes: true });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(spec.calls).toHaveLength(1);
    expect(spec.calls[0]).toMatchObject({
      command: "npm",
      args: ["install", "-g", PKG],
      shell: false,
    });
    expect(spec.calls[0]?.env.COGNEXUS_API_KEY).toBeUndefined();
    expect(spec.calls[0]?.env.PATH).toBe("/usr/local/bin");
    expect(spec.env?.COGNEXUS_API_KEY).toBe(SENTINEL);
    expect(JSON.stringify(spec.calls)).not.toContain(SENTINEL);
  });

  it("uses npm.cmd on Windows and says to open a new shell", async () => {
    const spec = input({
      yes: true,
      platform: "win32",
      binPath: "C:\\Users\\ada\\AppData\\Roaming\\npm\\node_modules\\@cognexuslabs\\grokbot-artzain\\dist\\cli.js",
      globalPrefix: "C:\\Users\\ada\\AppData\\Roaming\\npm",
      env: { COGNEXUS_API_KEY: SENTINEL, PATH: "C:\\Users\\ada\\AppData\\Roaming\\npm" },
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain(`npm.cmd install -g ${PKG}`);
    expect(result.stdout).toContain("Open a new shell so it finds the updated command.");
    expect(spec.calls).toHaveLength(1);
    expect(spec.calls[0]).toMatchObject({
      command: "npm.cmd",
      args: ["install", "-g", PKG],
      shell: true,
    });
    expect(spec.calls[0]?.env.COGNEXUS_API_KEY).toBeUndefined();
  });

  it("installs into a user prefix such as ~/.local", async () => {
    const prefix = `${HOME}/.local`;
    const spec = input({
      yes: true,
      binPath: `${prefix}/lib/node_modules/@cognexuslabs/grokbot-artzain/dist/cli.js`,
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(result.method).toBe("prefix");
    expect(result.stdout).toContain(`npm install -g --prefix ${prefix} ${PKG}`);
    expect(spec.calls).toHaveLength(1);
    expect(spec.calls[0]).toMatchObject({
      command: "npm",
      args: ["install", "-g", "--prefix", prefix, PKG],
      shell: false,
    });
  });

  it("prints an npx command when the binary is in the npx cache", async () => {
    const spec = input({
      yes: true,
      binPath: `${HOME}/.npm/_npx/abc123/node_modules/@cognexuslabs/grokbot-artzain/dist/cli.js`,
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(result.method).toBe("npx");
    expect(result.stdout).toContain(`npx --yes ${PKG}`);
    expect(result.stdout).not.toContain("Open a new shell");
    expect(spec.calls).toHaveLength(1);
    expect(spec.calls[0]).toMatchObject({
      command: "npx",
      args: ["--yes", PKG],
      shell: false,
    });
  });

  it("uses npx.cmd on Windows and does not ask for a new shell", async () => {
    const spec = input({
      yes: true,
      platform: "win32",
      binPath: "C:\\Users\\ada\\AppData\\Local\\npm-cache\\_npx\\abc\\node_modules\\@cognexuslabs\\grokbot-artzain\\dist\\cli.js",
      globalPrefix: "C:\\Users\\ada\\AppData\\Roaming\\npm",
    });
    const result = await runUpgrade(spec);

    expect(result.method).toBe("npx");
    expect(result.stdout).toContain(`npx.cmd --yes ${PKG}`);
    expect(result.stdout).not.toContain("Open a new shell");
    expect(spec.calls[0]?.command).toBe("npx.cmd");
    expect(spec.calls[0]?.shell).toBe(true);
  });

  it("does not run a command when the install method cannot be told", async () => {
    const spec = input({ yes: true, binPath: "/opt/custom/grokbot-artzain" });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(1);
    expect(result.method).toBe("unknown");
    expect(spec.calls).toEqual([]);
    expect(result.stderr.toLowerCase()).toContain("install");
  });

  it("does not downgrade when this copy is already the latest", async () => {
    const spec = input({ yes: true, packageVersion: LATEST });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(spec.calls).toEqual([]);
    expect(result.stdout).toContain(LATEST);
  });

  it("asks the registry without sending the key", async () => {
    const seen: { url: string; headers: Record<string, string> }[] = [];
    const spec = input({
      latest: undefined,
      fetchImpl: async (url, init) => {
        seen.push({ url, headers: { ...(init.headers as Record<string, string>) } });
        expect(init.redirect).toBe("manual");
        expect(init.method).toBe("GET");
        return new Response(JSON.stringify({ version: LATEST }), { status: 200 });
      },
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(seen.map((call) => call.url)).toEqual([
      "https://registry.npmjs.org/@cognexuslabs/grokbot-artzain/latest",
    ]);
    expect(JSON.stringify(seen)).not.toContain(SENTINEL);
    expect(result.stdout).toContain(PKG);
  });

  it("copies a skill inside the expected directory only with --yes, after the summary", async () => {
    const notes: string[] = [];
    let written = "";
    const spec = input({
      yes: true,
      skillPath: `${SKILLS}/SKILL.md`,
      note: (line) => notes.push(line),
      writeFile: (path, text) => {
        expect(notes.join("\n")).toContain("SKILL.md:");
        expect(path).toBe(`${SKILLS}/SKILL.md`);
        written = text;
      },
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("SKILL.md: 1 line added, 1 line removed");
    expect(written).toBe(PACKAGED);
    expect(rendered(result)).not.toContain(SENTINEL);
  });

  it("prints the skill summary and does not write on a dry run", async () => {
    let writes = 0;
    const spec = input({
      skillPath: `${SKILLS}/SKILL.md`,
      writeFile: () => {
        writes += 1;
      },
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(0);
    expect(writes).toBe(0);
    expect(spec.calls).toEqual([]);
    expect(result.stdout).toContain("SKILL.md: 1 line added, 1 line removed");
  });

  it("refuses a skill path outside the expected directory unless --force", async () => {
    let writes = 0;
    const outside = input({
      yes: true,
      skillPath: "/tmp/SKILL.md",
      writeFile: () => {
        writes += 1;
      },
    });
    const refused = await runUpgrade(outside);

    expect(refused.code).toBe(2);
    expect(writes).toBe(0);
    expect(outside.calls).toEqual([]);
    expect(refused.stderr).toContain("--force");

    const spec = input({
      yes: true,
      force: true,
      skillPath: "/tmp/SKILL.md",
      readFile: () => INSTALLED,
      writeFile: (_path, text) => {
        writes += 1;
        expect(text).toBe(PACKAGED);
      },
    });
    const allowed = await runUpgrade(spec);

    expect(allowed.code).toBe(0);
    expect(writes).toBe(1);
  });

  it("refuses a skill path that resolves outside the expected directory", async () => {
    const spec = input({
      yes: true,
      skillPath: `${SKILLS}/../../etc/SKILL.md`,
      resolvePath: () => "/etc/SKILL.md",
    });
    const result = await runUpgrade(spec);

    expect(result.code).toBe(2);
    expect(spec.calls).toEqual([]);
  });
});
