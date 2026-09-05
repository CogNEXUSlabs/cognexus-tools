// Copied verbatim into sdk/openclaw/src/client.ts; lockstep.test.ts there
// fails when the two drift.
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
