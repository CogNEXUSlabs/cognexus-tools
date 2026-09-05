import type {
  ICredentialType,
  INodeProperties,
} from "n8n-workflow";

export class ArtzainEnvelopeApi implements ICredentialType {
  name = "artzainEnvelopeApi";
  displayName = "CogNEXUS Envelope";
  documentationUrl = "https://docs.cognexuslabs.ai";
  properties: INodeProperties[] = [
    {
      displayName: "Envelope Key",
      name: "apiKey",
      type: "string",
      typeOptions: { password: true },
      default: "",
      required: true,
      description:
        "Envelope credential (cnxe_…), shown once at mint. Not a Decision API key and not a dashboard JWT.",
    },
    {
      displayName: "Base URL",
      name: "baseUrl",
      type: "string",
      default: "https://app.cognexuslabs.ai",
      description: "Engine origin. The node appends /api/v1/envelope/v1/chat/completions.",
    },
  ];

  authenticate = {
    type: "generic",
    properties: {
      headers: {
        Authorization: "=Bearer {{$credentials.apiKey}}",
      },
    },
  };
}
