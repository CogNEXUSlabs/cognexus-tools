import { afterEach, describe, expect, it } from "vitest";

import {
  configure,
  decide,
  DecisionError,
  fetchApiKeyIdentity,
  hasApiKey,
  postSdkEvent,
} from "../src/index.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { _resetConfigForTests, effectiveBaseUrl, readProfile } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const ALLOW = {
  outcome: "allow",
  decision_id: "01JZDECISIONXXXXXXXXXXXXXX",
  audit_block_id: "01JZBLOCKXXXXXXXXXXXXXXXXX",
  contributing_agents: [{ agent: "security-sentinel", verdict: "allow" }],
  policy_bundle_version: "builtin:v0",
  resolution_policy: "builtin/strict-v0",
  latency_ms: 12,
  reasons: [],
};

function fakeFetch(
  status: number,
  body: unknown,
  capture?: { url?: string; init?: unknown },
): FetchLike {
  return async (url, init) => {
    if (capture) {
      capture.url = url;
      capture.init = init;
    }
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

/** A 2xx whose body is not JSON — `json()` rejects the way undici's does. */
function htmlFetch(status: number, capture?: { init?: unknown }): FetchLike {
  return async (_url, init) => {
    if (capture) capture.init = init;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => JSON.parse("<!doctype html>"),
      text: async () => "<!doctype html>",
    };
  };
}

afterEach(() => {
  _resetConfigForTests();
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
  delete process.env.COGNEXUS_CREDENTIALS_PATH;
});

function writeProfile(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "artzain-creds-"));
  const path = join(dir, "credentials.toml");
  writeFileSync(path, body, "utf8");
  return path;
}

describe("credentials profile (§9.54)", () => {
  it("is read after the env vars, the way the Python SDK does it", () => {
    process.env.COGNEXUS_CREDENTIALS_PATH = writeProfile(
      [
        "# CogNEXUS CLI credentials — do not commit",
        "[default]",
        'api_key = "cnx_profile_key"',
        'base_url = "https://engine.example.com/"',
        'email = "someone@example.com"',
      ].join("\n") + "\n",
    );
    expect(readProfile()).toEqual({
      api_key: "cnx_profile_key",
      base_url: "https://engine.example.com/",
      email: "someone@example.com",
    });
    expect(hasApiKey()).toBe(true);
    expect(effectiveBaseUrl()).toBe("https://engine.example.com");

    process.env.COGNEXUS_API_KEY = "env-cnx";
    process.env.COGNEXUS_API_BASE_URL = "https://env.example.com";
    expect(effectiveBaseUrl()).toBe("https://env.example.com");
    configure({ apiKey: "explicit", baseUrl: "https://explicit.example.com" });
    expect(effectiveBaseUrl()).toBe("https://explicit.example.com");
  });

  it("ignores a missing file, a foreign table and malformed lines", () => {
    process.env.COGNEXUS_CREDENTIALS_PATH = join(tmpdir(), "artzain-does-not-exist", "c.toml");
    expect(readProfile()).toEqual({});
    expect(hasApiKey()).toBe(false);

    process.env.COGNEXUS_CREDENTIALS_PATH = writeProfile(
      ["[other]", 'api_key = "not-default"', "garbage line", "[default]", "api_key = ''"].join("\n"),
    );
    expect(readProfile()).toEqual({ api_key: "" });
    expect(hasApiKey()).toBe(false);
  });
});

describe("config", () => {
  it("configure() wins over env; env fallback order holds", () => {
    process.env.MYAPP_API_KEY = "env-myapp";
    expect(hasApiKey()).toBe(true);
    process.env.COGNEXUS_API_KEY = "env-cnx";
    configure({ baseUrl: "https://engine.example.com/" });
    expect(effectiveBaseUrl()).toBe("https://engine.example.com");
  });

  it("strips every trailing slash without backtracking", () => {
    configure({ baseUrl: "https://engine.example.com///" });
    expect(effectiveBaseUrl()).toBe("https://engine.example.com");

    configure({ baseUrl: "/".repeat(50_000) });
    expect(effectiveBaseUrl()).toBe("");

    // Quadratic on the old /\/+$/ trim; linear now.
    const started = performance.now();
    configure({ baseUrl: `${"/".repeat(50_000)}x` });
    expect(effectiveBaseUrl()).toBe(`${"/".repeat(50_000)}x`);
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it("defaults to the production host", () => {
    expect(effectiveBaseUrl()).toBe("https://app.cognexuslabs.ai");
  });
});

describe("decide", () => {
  it("posts the Decision API contract and returns the response", async () => {
    configure({ apiKey: "cnx_test", baseUrl: "https://engine.example.com" });
    const capture: { url?: string; init?: { headers: Record<string, string>; body: string } } = {};
    const result = await decide({
      action: "send_email",
      target: "crm:contact:123",
      payload: "Hello!",
      requestId: "req-1",
      fetchImpl: fakeFetch(200, ALLOW, capture),
    });
    expect(result.outcome).toBe("allow");
    expect(result.decision_id).toMatch(/^01JZ/);
    expect(capture.url).toBe("https://engine.example.com/api/v1/decisions");
    expect(capture.init!.headers["X-Api-Key"]).toBe("cnx_test");
    const sent = JSON.parse(capture.init!.body);
    expect(sent).toMatchObject({
      agent_did: "cognexus-sdk-ts",
      action: "send_email",
      target: "crm:contact:123",
      payload_kind: "user_input",
      surface: "sdk",
      request_id: "req-1",
    });
  });

  it("deny outcomes are returned, not thrown", async () => {
    configure({ apiKey: "cnx_test" });
    const result = await decide({
      action: "delete_all",
      target: "db:*",
      payload: "rm -rf",
      fetchImpl: fakeFetch(200, { ...ALLOW, outcome: "deny", reasons: ["destructive"] }),
    });
    expect(result.outcome).toBe("deny");
    expect(result.reasons).toContain("destructive");
  });

  it("throws a typed DecisionError on engine refusal (503)", async () => {
    configure({ apiKey: "cnx_test" });
    const err = await decide({
      action: "a",
      target: "t",
      payload: "p",
      fetchImpl: fakeFetch(503, { detail: { error: "kill_switch_active" } }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(503);
    expect(err.detail).toMatchObject({ error: "kill_switch_active" });
    expect(err.message).toContain("kill_switch_active");
  });

  it("throws immediately without an API key (remote-only, no offline fallback)", async () => {
    const err = await decide({
      action: "a",
      target: "t",
      payload: "p",
      fetchImpl: fakeFetch(200, ALLOW),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.message).toContain("No API key configured");
  });

  it("wraps transport failures", async () => {
    configure({ apiKey: "cnx_test" });
    const boom: FetchLike = async () => {
      throw new Error("ECONNREFUSED");
    };
    const err = await decide({ action: "a", target: "t", payload: "p", fetchImpl: boom })
      .catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.message).toContain("unreachable");
  });

  it("wraps a non-JSON 2xx body in DecisionError (§9.85)", async () => {
    configure({ apiKey: "cnx_test" });
    // A proxy or captive portal answering 200 text/html: resp.json() rejects
    // with a SyntaxError, which callers filtering on DecisionError never saw.
    const err = await decide({ action: "a", target: "t", payload: "p", fetchImpl: htmlFetch(200) })
      .catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.detail).toBeUndefined();
    expect(err.message).toContain("HTTP 200");
    expect(err.message).toContain("non-JSON");
  });
});

describe("postSdkEvent", () => {
  it("returns true on 2xx and never throws on failure", async () => {
    configure({ apiKey: "cnx_test" });
    expect(await postSdkEvent({ eventType: "guard.block", fetchImpl: fakeFetch(200, {}) }))
      .toBe(true);
    const boom: FetchLike = async () => {
      throw new Error("down");
    };
    expect(await postSdkEvent({ eventType: "guard.block", fetchImpl: boom })).toBe(false);
  });

  it("no key -> false, no network call", async () => {
    expect(await postSdkEvent({ eventType: "x" })).toBe(false);
  });
});

describe("fetchApiKeyIdentity", () => {
  it("returns the identity payload", async () => {
    configure({ apiKey: "cnx_test" });
    const id = await fetchApiKeyIdentity({
      fetchImpl: fakeFetch(200, { user_id: 7, email: "dev@example.com" }),
    });
    expect(id.user_id).toBe(7);
  });

  it("throws on invalid key", async () => {
    configure({ apiKey: "cnx_bad" });
    const err = await fetchApiKeyIdentity({ fetchImpl: fakeFetch(401, {}) }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(401);
  });

  it("sends a GET with no body key, and wraps a non-JSON 2xx (§9.85)", async () => {
    configure({ apiKey: "cnx_test" });
    const capture: { init?: unknown } = {};
    const err = await fetchApiKeyIdentity({ fetchImpl: htmlFetch(200, capture) }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(200);
    expect(err.message).toContain("non-JSON");
    // `body: undefined as unknown as string` used to leave an explicit
    // undefined body on the init; a GET simply has none.
    expect(Object.prototype.hasOwnProperty.call(capture.init, "body")).toBe(false);
  });
});
