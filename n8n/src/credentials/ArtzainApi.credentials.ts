import type {
  ICredentialType,
  INodeProperties,
} from "n8n-workflow";

/**
 * The 3xx statuses, the redirection class. The Test request follows none of
 * them (`disableFollowRedirect`), and each gets a message that names it.
 */
const REDIRECT_STATUSES = [300, 301, 302, 303, 304, 305, 306, 307, 308];

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

  // n8n sends the Test request through its own request helper, which follows
  // redirects and keeps X-Api-Key on them, to any host. Here a 3xx fails the
  // test and names the status.
  test = {
    request: {
      baseURL: "={{$credentials.baseUrl}}",
      url: "/health",
      disableFollowRedirect: true,
    },
    rules: REDIRECT_STATUSES.map((value) => ({
      type: "responseCode",
      properties: {
        value,
        message:
          `The Base URL answered HTTP ${value}, a redirect, which is not followed, ` +
          "so the key goes no further: set Base URL to the address the Decision " +
          "API answers on.",
      },
    })),
  };
}
