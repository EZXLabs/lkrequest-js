import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ConnectionError, HttpStatusError, ResourceLimitError } from "../src/index.js";
import { serverUrl, testClient } from "./support/clients.js";
import { closedPort, expectInvalidConfig } from "./support/helpers.js";

/** A `/flaky` URL that answers 503 to its first `fail` requests, then 200. */
function flaky(fail: number): string {
  return serverUrl(`/flaky?key=${randomUUID()}&fail=${fail}&status=503`);
}

describe("attemptSummary", () => {
  it("counts the submissions and connections of a request", async () => {
    const session = testClient().session();
    const first = await session.get(serverUrl("/get"));
    expect(first.attemptSummary).toMatchObject({
      started: true,
      httpSubmissions: 1,
      extraHttpSubmissions: 0,
      redirects: 0,
      recoveries: 0,
      connectInitiations: 1,
      probeSuppressedByConnectLimit: false,
      outcome: "succeeded",
    });
    expect(first.attemptSummary.denialReason).toBeUndefined();
    // The second request reuses the pooled connection.
    const second = await session.get(serverUrl("/get"));
    expect(second.attemptSummary).toMatchObject({ httpSubmissions: 1, connectInitiations: 0 });
  });

  it("counts the redirects among the submissions", async () => {
    const res = await testClient().session().get(serverUrl("/redirect/2"));
    expect(res.attemptSummary).toMatchObject({
      httpSubmissions: 3,
      extraHttpSubmissions: 0,
      redirects: 2,
    });
  });

  it("is on a streamed response, as of its headers", async () => {
    const res = await testClient().session().stream(serverUrl("/get"));
    expect(res.attemptSummary).toMatchObject({ httpSubmissions: 1, outcome: "succeeded" });
    await res.bytes();
  });

  it("comes with the error of a failed request", async () => {
    const url = `http://127.0.0.1:${await closedPort()}/`;
    const error = await testClient()
      .session()
      .get(url)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect((error as ConnectionError).attemptSummary).toMatchObject({
      outcome: "failed",
      connectInitiations: 1,
    });
  });

  it("comes with the error of throwForStatus()", async () => {
    const res = await testClient().session().get(serverUrl("/status/404"));
    expect(() => res.throwForStatus()).toThrow(HttpStatusError);
    try {
      res.throwForStatus();
    } catch (error) {
      expect((error as HttpStatusError).attemptSummary).toEqual(res.attemptSummary);
    }
  });
});

describe("attemptLimits", () => {
  it("are unset by default", () => {
    const client = testClient();
    expect(client.effectiveAttemptLimits).toEqual({});
    expect(client.session().effectiveAttemptLimits).toEqual({});
  });

  it("cap the retries of a request with extraHttpAttempts", async () => {
    const session = testClient().session({
      retry: { strategy: "fixed", interval: 10 },
      attemptLimits: { extraHttpAttempts: 1 },
    });
    const res = await session.get(flaky(3));
    expect(res.status).toBe(503);
    expect(res.attemptSummary).toMatchObject({
      httpSubmissions: 2,
      extraHttpSubmissions: 1,
      denialReason: "extra_http_limit",
      effectiveLimits: { extraHttpAttempts: 1, extraHttpScope: "session" },
    });
  });

  it("fail a request that needs a connection with connectAttempts: 0, but reuse one", async () => {
    const session = testClient().session();
    const error = await session
      .get(serverUrl("/get"), { attemptLimits: { connectAttempts: 0 } })
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ResourceLimitError);
    expect((error as ResourceLimitError).attemptSummary).toMatchObject({
      connectInitiations: 0,
      denialReason: "connect_limit",
    });
    await session.get(serverUrl("/get"));
    const reused = await session.get(serverUrl("/get"), { attemptLimits: { connectAttempts: 0 } });
    expect(reused.attemptSummary).toMatchObject({ connectInitiations: 0, outcome: "succeeded" });
  });

  it("let a session and a request lower the client's caps, but not raise them", async () => {
    const client = testClient({ attemptLimits: { extraHttpAttempts: 2 } });
    expect(client.effectiveAttemptLimits).toEqual({
      extraHttpAttempts: 2,
      extraHttpScope: "client",
    });
    expectInvalidConfig(() => client.session({ attemptLimits: { extraHttpAttempts: 3 } }));
    // A cap equal to the one above keeps the scope that set it.
    expect(
      client.session({ attemptLimits: { extraHttpAttempts: 2 } }).effectiveAttemptLimits,
    ).toEqual({ extraHttpAttempts: 2, extraHttpScope: "client" });

    const session = client.session({ attemptLimits: { extraHttpAttempts: 1, connectAttempts: 4 } });
    expect(session.effectiveAttemptLimits).toEqual({
      extraHttpAttempts: 1,
      extraHttpScope: "session",
      connectAttempts: 4,
      connectScope: "session",
    });
    await expect(
      session.get(serverUrl("/get"), { attemptLimits: { extraHttpAttempts: 2 } }),
    ).rejects.toBeInstanceOf(TypeError);
    const res = await session.get(serverUrl("/get"), { attemptLimits: { extraHttpAttempts: 0 } });
    expect(res.attemptSummary.effectiveLimits).toEqual({
      extraHttpAttempts: 0,
      extraHttpScope: "request",
      connectAttempts: 4,
      connectScope: "session",
    });
  });

  it("refuse a cap that is not a non-negative integer", () => {
    expectInvalidConfig(() => testClient({ attemptLimits: { extraHttpAttempts: -1 } }));
    expectInvalidConfig(() => testClient({ attemptLimits: { connectAttempts: 1.5 } }));
  });
});
