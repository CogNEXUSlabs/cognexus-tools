import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeConnectionTypes, NodeOperationError } from "n8n-workflow";

import {
  buildDecisionBody,
  decisionsUrl,
  fallbackRequestId,
  routeHttpDecision,
} from "../../decision.js";

export class ArtzainDecision implements INodeType {
  description: INodeTypeDescription = {
    displayName: "CogNEXUS Decision",
    name: "artzainDecision",
    icon: { light: "file:artzain.svg", dark: "file:artzain.svg" },
    group: ["transform"],
    version: 1,
    description:
      "POST /api/v1/decisions. Allow / review / deny outputs. HTTP 503 fails closed onto Deny. review does not wait inside n8n.",
    defaults: { name: "CogNEXUS Decision" },
    inputs: [NodeConnectionTypes.Main],
    outputs: [NodeConnectionTypes.Main, NodeConnectionTypes.Main, NodeConnectionTypes.Main],
    outputNames: ["Allow", "Review", "Deny"],
    credentials: [{ name: "artzainApi", required: true }],
    properties: [
      {
        displayName: "Action",
        name: "action",
        type: "string",
        default: "charge_customer",
        required: true,
      },
      {
        displayName: "Target",
        name: "target",
        type: "string",
        default: "stripe:cus_demo",
        required: true,
      },
      {
        displayName: "Payload",
        name: "payload",
        type: "string",
        default: '{"tool":"charge_customer","arguments":{}}',
        description: "JSON object string for payload_kind=tool_call, or prose for other kinds.",
      },
      {
        displayName: "Payload Kind",
        name: "payloadKind",
        type: "options",
        options: [
          { name: "tool_call", value: "tool_call" },
          { name: "user_input", value: "user_input" },
          { name: "model_output", value: "model_output" },
          { name: "external_content", value: "external_content" },
        ],
        default: "tool_call",
      },
      {
        displayName: "Agent DID",
        name: "agentDid",
        type: "string",
        default: "n8n-order-bot",
      },
      {
        displayName: "Request ID",
        name: "requestId",
        type: "string",
        default: "",
        description:
          "Idempotency key (max 64). The server replays a prior decision for the same key for 48 h. Empty derives n8n-<executionId>-<item>, unique per execution.",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const allow: INodeExecutionData[] = [];
    const review: INodeExecutionData[] = [];
    const deny: INodeExecutionData[] = [];
    const creds = await this.getCredentials("artzainApi");
    const apiKey = creds.apiKey || "";
    const baseUrl = creds.baseUrl || "https://app.cognexuslabs.ai";
    // Unique per execution so an empty Request ID never replays another
    // run's decision from the server's 48 h idempotency ledger.
    const executionId =
      typeof this.getExecutionId === "function" ? this.getExecutionId() : undefined;

    for (let i = 0; i < items.length; i++) {
      try {
        const action = String(this.getNodeParameter("action", i));
        const target = String(this.getNodeParameter("target", i));
        const payload = String(this.getNodeParameter("payload", i, "{}"));
        const payloadKind = String(
          this.getNodeParameter("payloadKind", i, "tool_call"),
        );
        const agentDid = String(this.getNodeParameter("agentDid", i, "n8n-order-bot"));
        const requestIdRaw = String(this.getNodeParameter("requestId", i, ""));
        const requestId = requestIdRaw || fallbackRequestId(executionId, i);
        const body = buildDecisionBody({
          agentDid,
          action,
          target,
          payload,
          payloadKind,
          requestId,
        });
        const resp = await fetch(decisionsUrl(baseUrl), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Api-Key": apiKey,
          },
          body: JSON.stringify(body),
        });
        let parsed: unknown;
        try {
          parsed = await resp.json();
        } catch {
          parsed = { detail: await resp.text() };
        }
        const routed = routeHttpDecision(resp.status, parsed);
        const out: INodeExecutionData = {
          json: routed.json,
          pairedItem: { item: i },
        };
        if (routed.branch === "allow") allow.push(out);
        else if (routed.branch === "review") review.push(out);
        else deny.push(out);
      } catch (error) {
        if (this.continueOnFail()) {
          deny.push({
            json: {
              outcome: "deny",
              reasons: [`${(error as Error).message} — failing closed`],
              decision_id: "",
            },
            pairedItem: { item: i },
            error,
          });
          continue;
        }
        throw new NodeOperationError(this.getNode(), error, { itemIndex: i });
      }
    }

    return [allow, review, deny];
  }
}
