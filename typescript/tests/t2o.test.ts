/**
 * What Tokens-to-Outcomes needs from a client: the workload and model a
 * decision belongs to, the tokens its model call cost, and the business
 * result posted against it. The Python SDK has sent these since 0.6.4x; this
 * file pins the TypeScript side of the same contract.
 */
import { afterEach, describe, expect, it } from "vitest";

import {
  configure,
  decide,
  DecisionError,
  postDecisionResult,
  postGenerationOutcome,
  postSdkEvent,
} from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

const DECISION = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

interface Capture {
  url?: string;
  init?: { method: string; headers: Record<string, string>; body?: string; redirect: string };
  calls: number;
}

function capture(): Capture {
  return { calls: 0 };
}

function fakeFetch(status: number, body: unknown, seen?: Capture): FetchLike {
  return async (url, init) => {
    if (seen) {
      seen.url = url;
      seen.init = init;
      seen.calls += 1;
    }
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

function sent(seen: Capture): Record<string, any> {
  return JSON.parse(seen.init!.body!);
}

afterEach(() => {
  _resetConfigForTests();
  delete process.env.COGNEXUS_API_KEY;
  delete process.env.MYAPP_API_KEY;
  delete process.env.COGNEXUS_API_BASE_URL;
  delete process.env.COGNEXUS_CREDENTIALS_PATH;
});

describe("decide: workload and model", () => {
  const base = { action: "send_email", target: "crm:contact:123", payload: "Hello!" };

  it("sends the workload and the model the decision belongs to", async () => {
    configure({ apiKey: "cnx_test", baseUrl: "https://engine.example.com" });
    const seen = capture();
    await decide({
      ...base,
      workloadId: " invoice-approval ",
      modelId: "model-a",
      fetchImpl: fakeFetch(200, { outcome: "allow" }, seen),
    });
    expect(sent(seen)).toMatchObject({ workload_id: "invoice-approval", model_id: "model-a" });
  });

  it("leaves both out of the body when they are not given", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    await decide({ ...base, workloadId: "  ", fetchImpl: fakeFetch(200, { outcome: "allow" }, seen) });
    expect(sent(seen)).not.toHaveProperty("workload_id");
    expect(sent(seen)).not.toHaveProperty("model_id");
  });

  it("refuses a control character before anything is sent, and cuts a long id", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    const fetchImpl = fakeFetch(200, { outcome: "allow" }, seen);
    for (const bad of [{ workloadId: "a\nb" }, { modelId: "m\u0007" }]) {
      const err = await decide({ ...base, ...bad, fetchImpl }).catch((e) => e);
      expect(err).toBeInstanceOf(DecisionError);
      expect(err.message).toContain("workloadId and modelId");
    }
    expect(seen.calls).toBe(0);
    // The server's limit is 80 characters, and the Python SDK cuts to it.
    await decide({ ...base, modelId: "x".repeat(81), fetchImpl });
    expect(sent(seen).model_id).toBe("x".repeat(80));
  });
});

describe("postSdkEvent: token counts", () => {
  it("puts the counts in the payload, over any the payload already had", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    await postSdkEvent({
      eventType: "generation",
      payload: { tokens_in: 1, reason: "ok" },
      tokensIn: 40,
      tokensOut: 12.9,
      fetchImpl: fakeFetch(200, {}, seen),
    });
    expect(sent(seen).payload).toEqual({ tokens_in: 40, tokens_out: 12, reason: "ok" });
  });

  it("sends a count that is not a count as nothing, and a negative one as zero", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    await postSdkEvent({
      eventType: "generation",
      tokensIn: Number.NaN,
      tokensOut: -5,
      fetchImpl: fakeFetch(200, {}, seen),
    });
    expect(sent(seen).payload).toEqual({ tokens_out: 0 });
  });
});

describe("postGenerationOutcome", () => {
  it("posts a generation event with its tokens under the decision id", async () => {
    configure({ apiKey: "cnx_test", baseUrl: "https://engine.example.com" });
    const seen = capture();
    const ok = await postGenerationOutcome({
      outcome: "Passed",
      reason: "answered",
      modelId: "model-a",
      requestId: ` ${DECISION.toLowerCase()} `,
      tokensIn: 40,
      tokensOut: 12,
      latencyMs: 250,
      fetchImpl: fakeFetch(200, {}, seen),
    });
    expect(ok).toBe(true);
    expect(seen.url).toBe("https://engine.example.com/api/events");
    const body = sent(seen);
    expect(body).toMatchObject({ event_type: "generation", level: "success", source: "npm_sdk" });
    expect(body.payload).toEqual({
      outcome: "passed",
      reason: "answered",
      // The server stores a decision id in upper case; the tokens join on it.
      request_id: DECISION,
      model_id: "model-a",
      latency_ms: 250,
      tokens_in: 40,
      tokens_out: 12,
    });
  });

  it("lower-cases any other id and makes one up when none is given", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    const fetchImpl = fakeFetch(200, {}, seen);
    await postGenerationOutcome({ outcome: "failed", reason: "timeout", requestId: "Order-8812", fetchImpl });
    expect(sent(seen).payload.request_id).toBe("order-8812");
    expect(sent(seen).level).toBe("error");
    await postGenerationOutcome({ outcome: "passed", reason: "ok", fetchImpl });
    expect(sent(seen).payload.request_id).toMatch(/^[0-9a-f]{32}$/);
  });

  it("never throws, as postSdkEvent does not", async () => {
    configure({ apiKey: "cnx_test" });
    const boom: FetchLike = async () => {
      throw new Error("down");
    };
    expect(await postGenerationOutcome({ outcome: "passed", reason: "ok", fetchImpl: boom })).toBe(false);
  });
});

describe("postDecisionResult", () => {
  const POSTED = {
    decision_id: DECISION,
    result_ref: "invoice-9",
    result_posted_at: "2026-10-14T16:00:00Z",
  };

  it("posts the result against the decision, in the case the server stores", async () => {
    configure({ apiKey: "cnx_test", baseUrl: "https://engine.example.com" });
    const seen = capture();
    const out = await postDecisionResult(` ${DECISION.toLowerCase()} `, " invoice-9 ", {
      fetchImpl: fakeFetch(200, POSTED, seen),
    });
    expect(out).toEqual(POSTED);
    expect(seen.url).toBe(`https://engine.example.com/api/v1/decisions/${DECISION}/result`);
    expect(seen.init!.method).toBe("POST");
    expect(seen.init!.redirect).toBe("manual");
    expect(seen.init!.headers["X-Api-Key"]).toBe("cnx_test");
    expect(sent(seen)).toEqual({ result_ref: "invoice-9" });
  });

  it("refuses an id or a result the server would refuse, before anything is sent", async () => {
    configure({ apiKey: "cnx_test" });
    const seen = capture();
    const fetchImpl = fakeFetch(200, POSTED, seen);
    const cases: [string, string, string][] = [
      ["not-a-decision", "invoice-9", "decisionId must be 26 characters"],
      [DECISION, "   ", "resultRef is required"],
      [DECISION, "x".repeat(201), "resultRef is required"],
      [DECISION, "a\u0007b", "resultRef is required"],
    ];
    for (const [id, ref, message] of cases) {
      const err = await postDecisionResult(id, ref, { fetchImpl }).catch((e) => e);
      expect(err).toBeInstanceOf(DecisionError);
      expect(err.message).toContain(message);
    }
    expect(seen.calls).toBe(0);
  });

  it("throws without an API key", async () => {
    const err = await postDecisionResult(DECISION, "invoice-9").catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.message).toContain("no API key");
  });

  it("reports a refusal with its status and the server's detail", async () => {
    configure({ apiKey: "cnx_test" });
    const err = await postDecisionResult(DECISION, "invoice-10", {
      fetchImpl: fakeFetch(409, { detail: "A result is already posted for this decision." }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(409);
    expect(err.message).toBe(
      "Decision API returned HTTP 409: A result is already posted for this decision.",
    );
  });

  it("does not follow a redirect", async () => {
    configure({ apiKey: "cnx_test" });
    const err = await postDecisionResult(DECISION, "invoice-9", {
      fetchImpl: fakeFetch(307, {}),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBe(307);
    expect(err.message).toContain("a redirect, which is not followed");
  });

  it("names a transport failure by its kind, not its text", async () => {
    configure({ apiKey: "cnx_test" });
    const boom: FetchLike = async () => {
      throw Object.assign(new Error("connect to secret-host refused"), { code: "ECONNREFUSED" });
    };
    const err = await postDecisionResult(DECISION, "invoice-9", { fetchImpl: boom }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.message).toContain("Error [ECONNREFUSED]");
    expect(err.message).not.toContain("secret-host");
  });
});
