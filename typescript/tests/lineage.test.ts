/**
 * The lineage a decision is sealed with: the decisions it follows, its
 * session, its trace and span, the tool call it screens, and who it acts
 * for. The engine signs these into leaf version 2, and a decision trace is
 * built from them. The Python SDK has sent them since 0.6.64; this file pins
 * the TypeScript side of the same contract.
 */
import { afterEach, describe, expect, it } from "vitest";

import { configure, decide, DecisionError } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const PARENT = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const OTHER = "01BX5ZZKBKACTAV9WEVGEMMVRZ";

interface Capture {
  init?: { body?: string };
  calls: number;
}

function fakeFetch(seen: Capture): FetchLike {
  return async (_url, init) => {
    seen.init = init;
    seen.calls += 1;
    return { ok: true, status: 200, json: async () => ({ outcome: "allow" }), text: async () => "{}" };
  };
}

function sent(seen: Capture): Record<string, any> {
  return JSON.parse(seen.init!.body!);
}

const base = { action: "send_email", target: "crm:contact:123", payload: "Hello!" };
const LINEAGE_KEYS = [
  "parent_decision_ids", "session_id", "trace_id", "span_id", "tool_call_id", "on_behalf_of", "approver_did",
];

afterEach(() => {
  _resetConfigForTests();
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
  delete process.env.COGNEXUS_CREDENTIALS_PATH;
});

describe("decide: lineage", () => {
  it("sends each lineage field under the name the Decision API takes", async () => {
    configure({ apiKey: "cnx_test", baseUrl: "https://engine.example.com" });
    const seen: Capture = { calls: 0 };
    await decide({
      ...base,
      parentDecisionIds: [PARENT],
      sessionId: " run-42 ",
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
      toolCallId: "call_abc",
      onBehalfOf: "user:ana",
      approverDid: "did:example:reviewer",
      fetchImpl: fakeFetch(seen),
    });
    expect(sent(seen)).toMatchObject({
      parent_decision_ids: [PARENT],
      session_id: "run-42",
      trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
      span_id: "00f067aa0ba902b7",
      tool_call_id: "call_abc",
      on_behalf_of: "user:ana",
      approver_did: "did:example:reviewer",
    });
  });

  it("leaves every lineage field out of the body when none is given", async () => {
    // An engine older than the fields never sees them.
    configure({ apiKey: "cnx_test" });
    const seen: Capture = { calls: 0 };
    await decide({ ...base, fetchImpl: fakeFetch(seen) });
    for (const key of LINEAGE_KEYS) expect(sent(seen)).not.toHaveProperty(key);
    await decide({
      ...base, parentDecisionIds: [], sessionId: "  ", traceId: "", toolCallId: " ", fetchImpl: fakeFetch(seen),
    });
    for (const key of LINEAGE_KEYS) expect(sent(seen)).not.toHaveProperty(key);
  });

  it("drops empty and repeated parents and keeps at most 16, in order", async () => {
    configure({ apiKey: "cnx_test" });
    const seen: Capture = { calls: 0 };
    await decide({
      ...base, parentDecisionIds: [PARENT, " ", OTHER, ` ${PARENT} `], fetchImpl: fakeFetch(seen),
    });
    expect(sent(seen).parent_decision_ids).toEqual([PARENT, OTHER]);
    const many = Array.from({ length: 20 }, (_, i) => `parent-${i}`);
    await decide({ ...base, parentDecisionIds: many, fetchImpl: fakeFetch(seen) });
    expect(sent(seen).parent_decision_ids).toEqual(many.slice(0, 16));
  });

  it("cuts each field to the width the server keeps", async () => {
    configure({ apiKey: "cnx_test" });
    const seen: Capture = { calls: 0 };
    const long = "x".repeat(300);
    await decide({
      ...base,
      parentDecisionIds: [long],
      sessionId: long,
      traceId: long,
      spanId: long,
      toolCallId: long,
      onBehalfOf: long,
      approverDid: long,
      fetchImpl: fakeFetch(seen),
    });
    const body = sent(seen);
    expect(body.parent_decision_ids[0]).toHaveLength(64);
    expect(body.session_id).toHaveLength(128);
    expect(body.trace_id).toHaveLength(64);
    expect(body.span_id).toHaveLength(32);
    expect(body.tool_call_id).toHaveLength(128);
    expect(body.on_behalf_of).toHaveLength(160);
    expect(body.approver_did).toHaveLength(160);
  });

  it("refuses a control character before anything is sent, naming the field", async () => {
    configure({ apiKey: "cnx_test" });
    const seen: Capture = { calls: 0 };
    const fetchImpl = fakeFetch(seen);
    const bad: [Record<string, unknown>, string][] = [
      [{ parentDecisionIds: [PARENT, "a\nb"] }, "parentDecisionIds"],
      [{ sessionId: "run\u0007" }, "sessionId"],
      [{ traceId: "t\tx" }, "traceId"],
      [{ spanId: "s\u0000" }, "spanId"],
      [{ toolCallId: "c\rd" }, "toolCallId"],
      [{ onBehalfOf: "u\n" + "x" }, "onBehalfOf"],
      [{ approverDid: "d\u001f" }, "approverDid"],
    ];
    for (const [options, name] of bad) {
      const err = await decide({ ...base, ...options, fetchImpl }).catch((e) => e);
      expect(err).toBeInstanceOf(DecisionError);
      expect(err.message).toBe(`Decision request not sent: ${name} cannot include control characters.`);
    }
    expect(seen.calls).toBe(0);
  });

  it("sends the fields beside the context, which is left as given", async () => {
    // The engine reads context.session and context.parent only when the
    // request does not set the fields; the SDK does not move one to the other.
    configure({ apiKey: "cnx_test" });
    const seen: Capture = { calls: 0 };
    await decide({
      ...base, sessionId: "run-42", context: { session: "older", note: 1 }, fetchImpl: fakeFetch(seen),
    });
    expect(sent(seen).session_id).toBe("run-42");
    expect(sent(seen).context).toEqual({ session: "older", note: 1 });
  });
});
