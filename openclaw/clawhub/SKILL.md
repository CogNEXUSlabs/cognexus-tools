---
name: ArtzAIn Tool Gate
description: Put this OpenClaw instance under ArtzAIn governance — every host tool call is checked against your own CogNEXUS Decision API before it runs, failing closed on deny, review, or any engine error.
---

# ArtzAIn Tool Gate

This is the **official ArtzAIn / CogNEXUS listing**. It is a pointer, not a
code bundle: the integration itself is the npm package
[`@cognexuslabs/openclaw-artzain`](https://www.npmjs.com/package/@cognexuslabs/openclaw-artzain)
(published with provenance attestation; source at
[CogNEXUSlabs/cognexus-tools](https://github.com/CogNEXUSlabs/cognexus-tools)).
If a listing under any other account offers "artzain", treat it as
unaffiliated.

Licensing: this listing text is MIT-0, as ClawHub requires for everything
published there. The plugin itself — the npm package and its source — is
**Apache-2.0**; installing via the command below gets you the Apache-2.0
package, not a ClawHub bundle.

## What it does

The plugin registers `before_tool_call` on the Gateway and asks your
CogNEXUS deployment for a sealed decision before any host tool runs:

| Decision | Result |
|---|---|
| `allow` | tool runs |
| `deny` | blocked, with the engine's reason |
| `review` | blocked — a human resolves it in the CogNEXUS Review Queue |
| HTTP 503 / 401 / 422 / missing key | blocked (fail closed) |

## Set up

1. Install the plugin from npm:

   ```
   openclaw plugins install @cognexuslabs/openclaw-artzain
   ```

2. Give the Gateway a Decision API key — `COGNEXUS_API_KEY`, or plugin
   config. The key is a sandbox/Decision key, **not** a dashboard JWT and
   **not** an envelope `cnxe_…` key:

   ```json5
   {
     plugins: {
       entries: {
         "artzain-tool-gate": {
           enabled: true,
           config: {
             // apiKey: "cgnx_…",        // or COGNEXUS_API_KEY on the Gateway
             // baseUrl: "https://your-cognexus-deployment.example",
             // agentDid: "did:…",       // optional identity override
           },
         },
       },
     },
   }
   ```

3. Restart the Gateway. Tool calls now appear as sealed decisions in your
   CogNEXUS audit trail, and this instance becomes visible to the Agent
   registry.

## Security notes

- `baseUrl` is **your own** CogNEXUS deployment. ArtzAIn is VPC-first; there
  is no shared SaaS endpoint to configure here, and we never ask for keys
  outside your own Gateway config.
- Verify what you install: the npm package ships signed provenance
  (`npm audit signatures`).
- The gate fails closed by design — a misconfigured key blocks tools rather
  than silently allowing them.
