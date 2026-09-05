import type {
  ICredentialType,
  INodeProperties,
} from "n8n-workflow";

export class ArtzainApi implements ICredentialType {
  name = "artzainApi";
  displayName = "CogNEXUS Decision API";
  documentationUrl = "https://docs.cognexuslabs.ai";
  properties: INodeProperties[] = [
    {
      displayName: "API Key",
      name: "apiKey",
      type: "string",
      typeOptions: { password: true },
      default: "",
      required: true,
      description:
        "Sandbox or production Decision API key from /get-a-key. Not a dashboard JWT.",
    },
    {
      displayName: "Base URL",
      name: "baseUrl",
      type: "string",
      default: "https://app.cognexuslabs.ai",
      description: "Decision API origin. Do not point this at the envelope path.",
    },
  ];

  authenticate = {
    type: "generic",
    properties: {
      headers: {
        "X-Api-Key": "={{$credentials.apiKey}}",
      },
    },
  };

  test = {
    request: {
      baseURL: "={{$credentials.baseUrl}}",
      url: "/health",
    },
  };
}
