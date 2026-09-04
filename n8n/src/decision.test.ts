import { describe, expect, it } from "vitest";

import {
  REQUEST_ID_MAX_LENGTH,
  buildDecisionBody,
  decisionsUrl,
  fallbackRequestId,
  routeHttpDecision,
} from "./decision.js";

describe("decisionsUrl", () => {
  it("hits the Decision API, not the envelope", () => {
    expect(decisionsUrl("https://app.cognexuslabs.ai/")).toBe(
      "https://app.cognexuslabs.ai/api/v1/decisions",
    );
    expect(decisionsUrl("https://app.cognexuslabs.ai/")).not.toContain("envelope");
  });
});

describe("buildDecisionBody", () => {
  it("is a tool_call surface n8n body without a JWT", () => {
    const body = buildDecisionBody({
      agentDid: "n8n-order-bot",
      action: "charge_customer",
      target: "stripe:cus_demo",
      payload: '{"tool":"charge_customer","arguments":{"amount":1}}',
      payloadKind: "tool_call",
      requestId: "abc-charge",
    });
    expect(body.payload_kind).toBe("tool_call");
    expect(body.surface).toBe("n8n");
    expect(JSON.stringify(body)).not.toMatch(/eyJ/);
  });
});

describe("routeHttpDecision", () => {
  it("splits allow / review / deny on HTTP 200", () => {
    expect(routeHttpDecision(200, { outcome: "allow", decision_id: "a" }).branch).toBe(
      "allow",
    );
    expect(routeHttpDecision(200, { outcome: "review", decision_id: "r" }).branch).toBe(
      "review",
    );
    expect(routeHttpDecision(200, { outcome: "deny", decision_id: "d" }).branch).toBe(
      "deny",
    );
  });

  it("fails closed on 503 and other errors", () => {
    const closed = routeHttpDecision(503, { detail: "audit_unavailable" });
    expect(closed.branch).toBe("deny");
    expect(String(closed.json.reasons)).toContain("failing closed");
    expect(routeHttpDecision(401, {}).branch).toBe("deny");
    expect(routeHttpDecision(422, {}).branch).toBe("deny");
  });
});

describe("fallbackRequestId", () => {
  it("differs across executions for the same item index", () => {
    // The old fallback was `n8n-${i}-${action}` — identical for item 0 of
    // every execution, so the server's 48 h idempotency ledger replayed the
    // first customer's sealed verdict for the second one.
    expect(fallbackRequestId("exec-1", 0)).not.toBe(fallbackRequestId("exec-2", 0));
  });

  it("differs across items within one execution", () => {
    expect(fallbackRequestId("exec-1", 0)).not.toBe(fallbackRequestId("exec-1", 1));
  });

  it("is stable for the same execution id and index", () => {
    expect(fallbackRequestId("exec-1", 3)).toBe("n8n-exec-1-3");
  });

  it("falls back to a random id when no execution id is available", () => {
    expect(fallbackRequestId(undefined, 0)).not.toBe(fallbackRequestId(undefined, 0));
    expect(fallbackRequestId("", 0)).not.toBe(fallbackRequestId("", 0));
    expect(fallbackRequestId("   ", 0)).not.toBe(fallbackRequestId("   ", 0));
    expect(fallbackRequestId(undefined, 0)).toMatch(/^n8n-[0-9a-f-]{36}-0$/);
  });

  it("never exceeds the server's 64-char cap", () => {
    expect(REQUEST_ID_MAX_LENGTH).toBe(64);
    expect(fallbackRequestId("x".repeat(200), 12).length).toBeLessThanOrEqual(64);
    expect(fallbackRequestId(undefined, 999_999).length).toBeLessThanOrEqual(64);
    expect(fallbackRequestId("exec-1", 0).length).toBeLessThanOrEqual(64);
  });
});
