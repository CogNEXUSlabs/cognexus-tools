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
import { DEFAULT_TIMEOUT_MS, fetchWithTimeout, resolveTimeoutMs } from "../../timeout.js";

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
      {
        displayName: "Timeout (ms)",
        name: "timeoutMs",
        type: "number",
        default: DEFAULT_TIMEOUT_MS,
        description:
          "Abort the envelope request after this many milliseconds. A timed-out item fails closed.",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const creds = await this.getCredentials("artzainEnvelopeApi");
    const apiKey = creds.apiKey || "";
    const baseUrl = creds.baseUrl || "https://app.cognexuslabs.ai";
    const label = {
      what: "envelope",
      baseSource: creds.baseUrl ? "the credential's Base URL" : "default",
    };
    const out: INodeExecutionData[] = [];

    for (let i = 0; i < items.length; i++) {
      try {
        const model = String(this.getNodeParameter("model", i, "gpt-4.1"));
        const userMessage = String(this.getNodeParameter("userMessage", i, ""));
        const timeoutMs = resolveTimeoutMs(
          this.getNodeParameter("timeoutMs", i, DEFAULT_TIMEOUT_MS),
        );
        const { status, text } = await fetchWithTimeout(
          envelopeCompletionsUrl(baseUrl),
          {
            method: "POST",
            headers: envelopeAuthHeader(apiKey),
            body: JSON.stringify({
              model,
              messages: [{ role: "user", content: userMessage }],
            }),
          },
          timeoutMs,
          label,
        );
        // A redirect is not followed (fetchWithTimeout), and its page is not
        // the envelope's answer: the error names the status alone.
        if (status >= 300 && status < 400) {
          throw new Error(
            `envelope HTTP ${status}, a redirect, which is not followed: ` +
              "check the credential's Base URL — failing closed",
          );
        }
        if (envelopeFailedClosed(status)) {
          throw new Error(`envelope HTTP ${status}: ${text} — failing closed`);
        }
        const json = JSON.parse(text) as Record<string, unknown>;
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
