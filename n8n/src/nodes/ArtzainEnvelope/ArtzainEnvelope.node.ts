import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeConnectionTypes, NodeOperationError } from "n8n-workflow";

import {
  envelopeAuthHeader,
  envelopeCompletionsUrl,
  envelopeFailedClosed,
} from "../../envelope.js";

export class ArtzainEnvelope implements INodeType {
  description: INodeTypeDescription = {
    displayName: "CogNEXUS Envelope",
    name: "artzainEnvelope",
    icon: { light: "file:artzain.svg", dark: "file:artzain.svg" },
    group: ["transform"],
    version: 1,
    description:
      "POST /api/v1/envelope/v1/chat/completions with a cnxe_ key. Screens model traffic only — it does not gate later side effects. HTTP 403/503 fail closed.",
    defaults: { name: "CogNEXUS Envelope" },
    inputs: [NodeConnectionTypes.Main],
    outputs: [NodeConnectionTypes.Main],
    credentials: [{ name: "artzainEnvelopeApi", required: true }],
    properties: [
      {
        displayName: "Model",
        name: "model",
        type: "string",
        default: "gpt-4.1",
        description: "Upstream model id the envelope passthrough expects.",
      },
      {
        displayName: "User Message",
        name: "userMessage",
        type: "string",
        default: "={{$json.message}}",
        typeOptions: { rows: 4 },
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const creds = await this.getCredentials("artzainEnvelopeApi");
    const apiKey = creds.apiKey || "";
    const baseUrl = creds.baseUrl || "https://app.cognexuslabs.ai";
    const out: INodeExecutionData[] = [];

    for (let i = 0; i < items.length; i++) {
      try {
        const model = String(this.getNodeParameter("model", i, "gpt-4.1"));
        const userMessage = String(this.getNodeParameter("userMessage", i, ""));
        const resp = await fetch(envelopeCompletionsUrl(baseUrl), {
          method: "POST",
          headers: envelopeAuthHeader(apiKey),
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: userMessage }],
          }),
        });
        if (envelopeFailedClosed(resp.status)) {
          const detail = await resp.text();
          throw new Error(`envelope HTTP ${resp.status}: ${detail} — failing closed`);
        }
        const json = (await resp.json()) as Record<string, unknown>;
        out.push({ json, pairedItem: { item: i } });
      } catch (error) {
        if (this.continueOnFail()) {
          out.push({
            json: {
              error: (error as Error).message,
              outcome: "deny",
            },
            pairedItem: { item: i },
            error,
          });
          continue;
        }
        throw new NodeOperationError(this.getNode(), error, { itemIndex: i });
      }
    }

    return [out];
  }
}
