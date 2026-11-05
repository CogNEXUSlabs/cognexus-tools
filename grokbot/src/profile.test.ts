/**
 * A profile names one Bot. The file holds an agent id, an instance, a base
 * URL, and the name of an environment variable. It does not hold a key.
 */

import { mkdirSync } from "node:fs";
import { readFile, rename, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readProfile, writeProfile } from "./profile.js";
import { setReplaceForTests, setStateDirectoryForTests } from "./state.js";

const SENTINEL = "cnx_SENTINEL_profile_key_9f3a7c1e";

let dir = "";

beforeEach(() => {
  dir = join(tmpdir(), `grokbot-profile-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  setStateDirectoryForTests(dir);
});

afterEach(() => {
  setStateDirectoryForTests(undefined);
  setReplaceForTests(undefined);
});

describe("a Bot profile", () => {
  it("writes the agent id, instance, base URL, and key env name, and not a key", async () => {
    process.env.BOT_API_KEY = SENTINEL;
    try {
      const written = await writeProfile("ops", {
        agent_id: "ops",
        instance: "ops-desk",
        base_url: "http://127.0.0.1:9",
        key_env: "BOT_API_KEY",
      });
      expect("path" in written).toBe(true);
      if (!("path" in written)) return;
      const text = await readFile(written.path, "utf8");
      expect(text).not.toContain(SENTINEL);
      expect(JSON.parse(text)).toEqual({
        agent_id: "ops",
        instance: "ops-desk",
        base_url: "http://127.0.0.1:9",
        key_env: "BOT_API_KEY",
      });
      if (process.platform !== "win32") {
        expect((await stat(written.path)).mode & 0o777).toBe(0o600);
      }
      expect(await readProfile("ops")).toEqual({
        agent_id: "ops",
        instance: "ops-desk",
        base_url: "http://127.0.0.1:9",
        key_env: "BOT_API_KEY",
      });
    } finally {
      delete process.env.BOT_API_KEY;
    }
  });

  it("retries a rename the system refuses, the same way the state file does", async () => {
    let calls = 0;
    setReplaceForTests(async (from, to) => {
      calls += 1;
      if (calls < 3) {
        const err = new Error("busy") as NodeJS.ErrnoException;
        err.code = "EPERM";
        throw err;
      }
      await rename(from, to);
    }, 1_000);

    const written = await writeProfile("ops", { agent_id: "ops" });
    expect(calls).toBe(3);
    expect("path" in written).toBe(true);
  });

  it("refuses a name that leaves the profiles directory", async () => {
    for (const name of ["../ops", "ops/east", "", ".", ".."]) {
      const written = await writeProfile(name, { agent_id: "ops" });
      expect(written).toEqual({ problem: "a profile name is letters, digits, and . _ -" });
    }
  });

  it("refuses a key env value that is not a variable name, and does not repeat it", async () => {
    const written = await writeProfile("ops", { agent_id: "ops", key_env: SENTINEL + "-not-a-name" });
    expect("problem" in written).toBe(true);
    if (!("problem" in written)) return;
    expect(written.problem).not.toContain(SENTINEL);
  });

  it("does not treat a key stored in the file as the key env name", async () => {
    const folder = join(dir, "profiles");
    mkdirSync(folder, { recursive: true });
    await writeFile(
      join(folder, "ops.json"),
      JSON.stringify({ agent_id: "ops", api_key: SENTINEL, key: SENTINEL }),
      "utf8",
    );

    const profile = await readProfile("ops");
    expect(JSON.stringify(profile)).not.toContain(SENTINEL);
    expect(profile).toEqual({ agent_id: "ops" });
  });
});
