import { beforeEach, describe, expect, it } from "vitest";

import { enrollInstance } from "./enroll.js";
import { gateToolCall, resetAnnounceForTests, type SkillConfig } from "./gate.js";
import type { FetchLike } from "./client.js";

type Captured = { url: string; init: Parameters<FetchLike>[1] };

function fakeFetch(
  status = 200,
  body: unknown = {
    ok: true,
    adapter: { primary: "tool_gate", pattern: "C" },
    decision: { base_url: "https://engine.example/api/v1/decisions", already_have_key: true },
    envelope: null,
  },
): { impl: FetchLike; calls: Captured[] } {
  const calls: Captured[] = [];
  const impl: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
  return { impl, calls };
}

const CFG: SkillConfig = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  instance: "ops-desk",
  announceAgents: ["bot-ops"],
  announceSkills: ["artzain"],
};

beforeEach(() => resetAnnounceForTests());

describe("enrollInstance", () => {
  it("POSTs announce-shape identity with source grokbot", async () => {
    const { impl, calls } = fakeFetch();
    const out = await enrollInstance(CFG, impl);
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://engine.example/api/v1/registry/enroll");
    expect(calls[0].init.headers["X-Api-Key"]).toBe("cnx_test");
    expect(JSON.parse(calls[0].init.body as string)).toEqual({
      source: "grokbot",
      instance: "ops-desk",
      agents: ["bot-ops"],
      skills: ["artzain"],
    });
    expect(out.adapter).toEqual({ primary: "tool_gate", pattern: "C" });
    expect(out.envelope).toBeNull();
  });

  it("does nothing when enroll is exactly false", async () => {
    const { impl, calls } = fakeFetch();
    expect((await enrollInstance({ ...CFG, enroll: false }, impl)).ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("fires by default when enroll is omitted", async () => {
    const { impl, calls } = fakeFetch();
    expect((await enrollInstance(CFG, impl)).ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("includes enroll_token when set, never logs cnxe_", async () => {
    const { impl, calls } = fakeFetch(200, {
      ok: true,
      adapter: { primary: "tool_gate", pattern: "C" },
      envelope: { envelope_key: "cnxe_deadbeef", install: "OPENAI_API_KEY=cnxe_deadbeef" },
    });
    const logs: string[] = [];
    const out = await enrollInstance(
      { ...CFG, enrollToken: "tok_once" },
      impl,
      (m) => logs.push(m),
    );
    expect(JSON.parse(calls[0].init.body as string).enroll_token).toBe("tok_once");
    expect(out.envelope?.envelope_key).toBe("cnxe_deadbeef");
    expect(logs.join("\n")).not.toContain("cnxe_");
    expect(logs.join("\n")).not.toContain("tok_once");
  });

  it("classifies transience: network/5xx/429 retryable, 4xx not", async () => {
    expect((await enrollInstance(CFG, fakeFetch(503).impl)).retryable).toBe(true);
    expect((await enrollInstance(CFG, fakeFetch(404).impl)).retryable).toBe(false);
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    expect((await enrollInstance(CFG, failing)).retryable).toBe(true);
  });
});

describe("gateToolCall enroll", () => {
  function routed(): { impl: FetchLike; calls: Captured[] } {
    const calls: Captured[] = [];
    const impl: FetchLike = async (url, init) => {
      calls.push({ url, init });
      const enroll = url.endsWith("/registry/enroll");
      const body = enroll
        ? {
            ok: true,
            adapter: { primary: "tool_gate", pattern: "C" },
            decision: { already_have_key: true },
            envelope: null,
          }
        : { outcome: "allow", decision_id: "d1", reasons: [] };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    };
    return { impl, calls };
  }

  it("fires enroll once by default and never blocks gating", async () => {
    const { impl, calls } = routed();
    const cfg = { ...CFG, announce: false };
    const r1 = await gateToolCall(cfg, { toolName: "exec" }, impl);
    const r2 = await gateToolCall(cfg, { toolName: "exec" }, impl);
    expect(r1.allow).toBe(true);
    expect(r2.allow).toBe(true);
    expect(calls.filter((c) => c.url.endsWith("/registry/enroll"))).toHaveLength(1);
    expect(calls.filter((c) => c.url.endsWith("/registry/announce"))).toHaveLength(0);
    expect(calls.filter((c) => c.url.endsWith("/decisions"))).toHaveLength(2);
    expect(JSON.parse(
      calls.filter((c) => c.url.endsWith("/registry/enroll"))[0].init.body as string,
    ).source).toBe("grokbot");
  });

  it("skips enroll when enroll is false", async () => {
    const { impl, calls } = routed();
    await gateToolCall({ ...CFG, enroll: false, announce: false }, { toolName: "exec" }, impl);
    expect(calls.filter((c) => c.url.endsWith("/registry/enroll"))).toHaveLength(0);
  });

  it("a failing enroll leaves the decision gate untouched", async () => {
    const impl: FetchLike = async (url, init) => {
      if (url.endsWith("/registry/enroll")) {
        throw new Error("enroll endpoint down");
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
        text: async () => "{}",
      };
    };
    const result = await gateToolCall(
      { ...CFG, announce: false },
      { toolName: "exec" },
      impl,
    );
    expect(result.allow).toBe(true);
  });
});
