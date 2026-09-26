/**
 * An API key goes only to the host it was issued with.
 *
 * `artzain login` writes the key and the host it logged in against to
 * `~/.artzain/credentials.toml`. The SDK resolved the key and the host
 * independently, so the profile's key could go to a host named by
 * `COGNEXUS_API_BASE_URL` or `configure({ baseUrl })`, and an environment key
 * to the profile's host. Now a key read from the profile (or equal to it) goes
 * to the profile's host, any other key to the configured or environment host
 * or the default, and a set host that disagrees with the key's refuses the
 * call before anything is sent. The error names settings, never values.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { configure, decide, DecisionError, fetchApiKeyIdentity, postSdkEvent } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const SELF_HOSTED = "https://engine.selfhosted.example";
const OTHER = "https://other.example";
const DEFAULT = "https://app.cognexuslabs.ai";
const PROFILE_KEY = "cnx_profile_key_0123456789";

const ENV = ["COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL", "COGNEXUS_CREDENTIALS_PATH"];

function profile(lines: string[]): void {
  const dir = mkdtempSync(join(tmpdir(), "artzain-pairing-"));
  const path = join(dir, "credentials.toml");
  writeFileSync(path, ["[default]", ...lines].join("\n") + "\n", "utf8");
  process.env.COGNEXUS_CREDENTIALS_PATH = path;
}

function selfHostedProfile(): void {
  profile([`api_key = "${PROFILE_KEY}"`, `base_url = "${SELF_HOSTED}"`]);
}

function recorder(calls: Array<{ url: string; key?: string }>): FetchLike {
  return async (url, init) => {
    calls.push({ url, key: init.headers["X-Api-Key"] });
    return {
      ok: true,
      status: 200,
      json: async () => ({ outcome: "allow", user_id: 1 }),
      text: async () => "{}",
    };
  };
}

beforeEach(() => {
  for (const name of ENV) delete process.env[name];
  // No profile unless a test writes one.
  process.env.COGNEXUS_CREDENTIALS_PATH = join(tmpdir(), "artzain-no-profile", "credentials.toml");
});

afterEach(() => {
  _resetConfigForTests();
  for (const name of ENV) delete process.env[name];
});

async function decideWith(fetchImpl: FetchLike) {
  return decide({ action: "send_email", target: "crm:contact:1", payload: "hello", fetchImpl });
}

describe("a key goes only to the host it was issued with", () => {
  it("refuses the profile's key for a host named by COGNEXUS_API_BASE_URL", async () => {
    selfHostedProfile();
    process.env.COGNEXUS_API_BASE_URL = OTHER;
    const calls: Array<{ url: string; key?: string }> = [];
    const err = await decideWith(recorder(calls)).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(calls).toEqual([]);
    expect(err.message).toContain("COGNEXUS_API_BASE_URL");
    expect(err.message).toContain("credentials profile");
    for (const value of [SELF_HOSTED, OTHER, PROFILE_KEY]) expect(err.message).not.toContain(value);
  });

  it("refuses the profile's key for a host set with configure()", async () => {
    selfHostedProfile();
    configure({ baseUrl: OTHER });
    const calls: Array<{ url: string; key?: string }> = [];
    const err = await decideWith(recorder(calls)).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(calls).toEqual([]);
  });

  it("sends an environment key to the default host, not the profile's", async () => {
    selfHostedProfile();
    process.env.COGNEXUS_API_KEY = "cnx_env_key_0123456789";
    const calls: Array<{ url: string; key?: string }> = [];
    await decideWith(recorder(calls));
    expect(calls).toEqual([{ url: `${DEFAULT}/api/v1/decisions`, key: "cnx_env_key_0123456789" }]);
  });

  it("sends the profile's key, exported to the environment, to the profile's host", async () => {
    selfHostedProfile();
    process.env.COGNEXUS_API_KEY = PROFILE_KEY;
    const calls: Array<{ url: string; key?: string }> = [];
    await decideWith(recorder(calls));
    expect(calls).toEqual([{ url: `${SELF_HOSTED}/api/v1/decisions`, key: PROFILE_KEY }]);
  });

  it("sends the profile's key to the profile's host", async () => {
    selfHostedProfile();
    const calls: Array<{ url: string; key?: string }> = [];
    await decideWith(recorder(calls));
    expect(calls).toEqual([{ url: `${SELF_HOSTED}/api/v1/decisions`, key: PROFILE_KEY }]);
  });

  it("pairs a configured key with the configured host", async () => {
    selfHostedProfile();
    configure({ apiKey: "cnx_configured_key_0123", baseUrl: OTHER });
    const calls: Array<{ url: string; key?: string }> = [];
    await decideWith(recorder(calls));
    expect(calls).toEqual([{ url: `${OTHER}/api/v1/decisions`, key: "cnx_configured_key_0123" }]);
  });

  it("keeps the named host for a profile that records none", async () => {
    profile([`api_key = "${PROFILE_KEY}"`]);
    process.env.COGNEXUS_API_BASE_URL = OTHER;
    const calls: Array<{ url: string; key?: string }> = [];
    await decideWith(recorder(calls));
    expect(calls).toEqual([{ url: `${OTHER}/api/v1/decisions`, key: PROFILE_KEY }]);
  });

  it("postSdkEvent sends nothing on a conflict and returns false", async () => {
    selfHostedProfile();
    process.env.COGNEXUS_API_BASE_URL = OTHER;
    const calls: Array<{ url: string; key?: string }> = [];
    expect(await postSdkEvent({ eventType: "guard.block", fetchImpl: recorder(calls) })).toBe(false);
    expect(calls).toEqual([]);
  });

  it("fetchApiKeyIdentity refuses a conflict with DecisionError", async () => {
    selfHostedProfile();
    process.env.COGNEXUS_API_BASE_URL = OTHER;
    const calls: Array<{ url: string; key?: string }> = [];
    const err = await fetchApiKeyIdentity({ fetchImpl: recorder(calls) }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(calls).toEqual([]);
  });
});
