import { afterEach, describe, expect, it } from "vitest";

import { configure, DecisionError, fetchApiKeyIdentity, postSdkEvent } from "../src/index.js";
import { _resetConfigForTests } from "../src/config.js";
import type { FetchLike } from "../src/decide.js";

// Settles only when the caller's AbortSignal fires; hangs forever otherwise —
// exactly what a stalled server looks like to the SDK.
const hang: FetchLike = (_url, init) =>
  new Promise((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
  });

function capturingFetch(
  status: number,
  body: unknown,
  capture: { init?: { signal?: AbortSignal } },
): FetchLike {
  return async (_url, init) => {
    capture.init = init;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

afterEach(() => {
  _resetConfigForTests();
});

describe("request timeouts", () => {
  it("postSdkEvent aborts a never-resolving fetch and returns false", async () => {
    configure({ apiKey: "cnx_test" });
    expect(await postSdkEvent({ eventType: "x", timeoutMs: 20, fetchImpl: hang })).toBe(false);
  }, 2_000);

  it("fetchApiKeyIdentity aborts a never-resolving fetch and throws DecisionError", async () => {
    configure({ apiKey: "cnx_test" });
    const err = await fetchApiKeyIdentity({ timeoutMs: 20, fetchImpl: hang }).catch((e) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(err.status).toBeUndefined();
    expect(err.message).toContain("aborted");
  }, 2_000);

  it("both calls pass a live AbortSignal by default", async () => {
    configure({ apiKey: "cnx_test" });
    const capture: { init?: { signal?: AbortSignal } } = {};
    await postSdkEvent({ eventType: "x", fetchImpl: capturingFetch(200, {}, capture) });
    expect(capture.init!.signal).toBeInstanceOf(AbortSignal);
    expect(capture.init!.signal!.aborted).toBe(false);
    await fetchApiKeyIdentity({ fetchImpl: capturingFetch(200, { user_id: 1 }, capture) });
    expect(capture.init!.signal).toBeInstanceOf(AbortSignal);
    expect(capture.init!.signal!.aborted).toBe(false);
  });
});
