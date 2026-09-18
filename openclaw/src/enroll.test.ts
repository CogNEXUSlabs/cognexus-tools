import { beforeEach, describe, expect, it } from "vitest";

import { enrollInstance } from "./enroll.js";
import {
  handleBeforeToolCall,
  resetAnnounceForTests,
  type PluginConfig,
} from "./gate.js";
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

const CFG: PluginConfig = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  instance: "jeans-laptop",
  announceAgents: ["main"],
  announceSkills: ["artzain"],
};

beforeEach(() => resetAnnounceForTests());

describe("enrollInstance", () => {
  it("POSTs announce-shape identity without source", async () => {
    const { impl, calls } = fakeFetch();
    const out = await enrollInstance(CFG, impl);
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://engine.example/api/v1/registry/enroll");
    expect(calls[0].init.headers["X-Api-Key"]).toBe("cnx_test");
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.source).toBeUndefined();
    expect(body.instance).toBe("jeans-laptop");
    expect(body.agents).toEqual(["main"]);
    expect(body.skills).toEqual(["artzain"]);
    expect(body.enroll_token).toBeUndefined();
    expect(out.adapter).toEqual({ primary: "tool_gate", pattern: "C" });
    expect(out.envelope).toBeNull();
  });

  it("does nothing when enroll is exactly false", async () => {
    const { impl, calls } = fakeFetch();
    const out = await enrollInstance({ ...CFG, enroll: false }, impl);
    expect(out.ok).toBe(false);
    expect(out.reason).toBe("enroll disabled");
    expect(calls).toHaveLength(0);
  });

  it("fires by default when enroll is omitted", async () => {
    const { impl, calls } = fakeFetch();
    const out = await enrollInstance({ ...CFG }, impl);
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("includes enroll_token when set, never logs cnxe_", async () => {
    const { impl, calls } = fakeFetch(200, {
      ok: true,
      adapter: { primary: "tool_gate", pattern: "C" },
      decision: { already_have_key: true },
      envelope: {
        base_url: "https://engine.example/api/v1/envelope/v1",
        envelope_key: "cnxe_deadbeef",
        install: "set OPENAI_BASE_URL=… OPENAI_API_KEY=cnxe_deadbeef",
      },
    });
    const logs: string[] = [];
    const out = await enrollInstance(
      { ...CFG, enrollToken: "tok_once" },
      impl,
      (m) => logs.push(m),
    );
    expect(out.ok).toBe(true);
    expect(JSON.parse(calls[0].init.body as string).enroll_token).toBe("tok_once");
    expect(out.envelope?.envelope_key).toBe("cnxe_deadbeef");
    expect(logs.join("\n")).toContain("envelope material received");
    expect(logs.join("\n")).not.toContain("cnxe_");
    expect(logs.join("\n")).not.toContain("tok_once");
  });

  it("classifies transience: network/5xx/429 retryable, 4xx not", async () => {
    expect((await enrollInstance(CFG, fakeFetch(503).impl)).retryable).toBe(true);
    expect((await enrollInstance(CFG, fakeFetch(429).impl)).retryable).toBe(true);
    expect((await enrollInstance(CFG, fakeFetch(422).impl)).retryable).toBe(false);
    expect((await enrollInstance(CFG, fakeFetch(404).impl)).retryable).toBe(false);
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    expect((await enrollInstance(CFG, failing)).retryable).toBe(true);
  });
});

describe("gate integration", () => {
  const EVENT = { toolName: "exec", toolCallId: "t1" };

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
    const ctx = { pluginConfig: { ...CFG, announce: false } };
    const r1 = await handleBeforeToolCall(EVENT, ctx, impl);
    const r2 = await handleBeforeToolCall(EVENT, ctx, impl);
    expect(r1).toBeUndefined();
    expect(r2).toBeUndefined();
    const enrollCalls = calls.filter((c) => c.url.endsWith("/registry/enroll"));
    const announceCalls = calls.filter((c) => c.url.endsWith("/registry/announce"));
    const decisionCalls = calls.filter((c) => c.url.endsWith("/decisions"));
    expect(enrollCalls).toHaveLength(1);
    expect(announceCalls).toHaveLength(0);
    expect(decisionCalls).toHaveLength(2);
  });

  it("skips enroll when enroll is false", async () => {
    const { impl, calls } = routed();
    await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { ...CFG, enroll: false } },
      impl,
    );
    expect(calls.filter((c) => c.url.endsWith("/registry/enroll"))).toHaveLength(0);
  });

  it("a failing enroll endpoint leaves the decision gate untouched", async () => {
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
    const result = await handleBeforeToolCall(
      EVENT,
      { pluginConfig: { ...CFG, enroll: true } },
      impl,
    );
    expect(result).toBeUndefined();
  });

  it("retries enroll on a later call after a transient failure only", async () => {
    let enrollAttempts = 0;
    let failFirst = true;
    const impl: FetchLike = async (url, init) => {
      if (url.endsWith("/registry/enroll")) {
        enrollAttempts += 1;
        if (failFirst) {
          failFirst = false;
          throw new Error("offline");
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ adapter: { primary: "tool_gate" }, envelope: null }),
          text: async () => "{}",
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
        text: async () => "{}",
      };
    };
    const ctx = { pluginConfig: { ...CFG, enroll: true } };
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0));
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0));
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0));
    expect(enrollAttempts).toBe(2);
  });
});
