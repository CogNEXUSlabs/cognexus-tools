import { describe, expect, it } from "vitest";

import {
  buildDecisionBody,
  decisionsUrl,
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
