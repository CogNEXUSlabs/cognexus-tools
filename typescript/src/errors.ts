// Copied verbatim into sdk/openclaw/src/client.ts and
// sdk/grokbot/src/client.ts; lockstep.test.ts there fails when a copy drifts.
// lockstep:begin DecisionError
/** Raised when the Decision API cannot return a decision. */
export class DecisionError extends Error {
  /** HTTP status when the server answered; undefined on transport failure. */
  readonly status?: number;
  /** Parsed `detail` from the server's error body, when present. */
  readonly detail?: unknown;

  constructor(message: string, options?: { status?: number; detail?: unknown }) {
    super(message);
    this.name = "DecisionError";
    this.status = options?.status;
    this.detail = options?.detail;
  }
}
// lockstep:end DecisionError

// Copied verbatim into sdk/openclaw/src/client.ts, sdk/grokbot/src/client.ts
// and sdk/n8n/src/failure.ts; lockstep.test.ts there fails when a copy drifts.
// lockstep:begin failure-kind
/**
 * The kind of error a request failed with, for a message: its name, and its
 * code when it has one (`TypeError`, `Error [ECONNREFUSED]`). A TypeError
 * with a cause, such as fetch's "fetch failed", is named by its cause. The
 * error's text is left out, and so is a name or code that is not an
 * identifier: fetch quotes a header value it refuses, an API key among them,
 * and a certificate issued for another name puts the host in the text.
 *
 * Once `deadline`, the call's own timeout signal, has fired, the failure is
 * that timeout, whatever the transport rejected with.
 */
export function failureKind(err: unknown, deadline?: AbortSignal): string {
  if (deadline?.aborted) return "TimeoutError, aborted when the timeout passed";
  try {
    let failure = err as { name?: unknown; code?: unknown; cause?: unknown } | null | undefined;
    if (failure?.name === "TypeError" && typeof failure.cause === "object" && failure.cause) {
      failure = failure.cause as typeof failure;
    }
    const name = failure?.name;
    const code = failure?.code;
    const kind = typeof name === "string" && /^[A-Z][A-Za-z0-9_]{0,63}$/.test(name) ? name : "Error";
    return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? `${kind} [${code}]` : kind;
  } catch {
    // A property that throws when read (a proxy, a getter) names nothing.
    return "Error";
  }
}
// lockstep:end failure-kind
