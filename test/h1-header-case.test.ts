import { createHash } from "node:crypto";
import { describe, expect, it, onTestFinished } from "vitest";
import { Client, type ClientOptions } from "../src/index.js";
import { server, serverUrl, testClient } from "./support/clients.js";
import { type RawHttpServer, rawResponse, startRawHttpServer } from "./support/raw-http.js";

// HTTP/1.1 header names go out in Title-Case unless `h1.titleCaseHeaders` is false, on every
// path that opens an HTTP/1.1 connection; `Host` keeps its capital either way. The raw server
// records each name as it arrived.

/** `name` with each dash-separated part capitalized, as HTTP/1.1 sends it by default. */
function titleCase(name: string): string {
  return name.replace(/(^|-)([a-z])/g, (_match, dash: string, letter: string) => {
    return dash + letter.toUpperCase();
  });
}

/** Client options for a setting; `undefined` keeps the default. */
function withSetting(titleCaseHeaders: boolean | undefined): ClientOptions {
  return titleCaseHeaders === undefined ? {} : { h1: { titleCaseHeaders } };
}

/** Starts a raw server for the current test, over TLS when `secure` is set. */
async function rawServer(secure: boolean, response: Buffer): Promise<RawHttpServer> {
  const raw = await startRawHttpServer(
    () => response,
    secure ? { tls: { key: server.key, cert: server.ca } } : {},
  );
  onTestFinished(() => raw.close());
  return raw;
}

/**
 * Asserts the first request's names are all Title-Case, or all lowercase but `Host`; that `Host`
 * was sent once; and that `expected` are among them.
 */
function expectNames(
  raw: RawHttpServer,
  titleCaseHeaders: boolean | undefined,
  expected: readonly string[],
): void {
  const spell = (name: string): string =>
    titleCaseHeaders !== false || name === "host" ? titleCase(name) : name;
  const names = raw.requests[0]?.names ?? [];
  expect(names).toEqual(names.map((name) => spell(name.toLowerCase())));
  expect(names.filter((name) => name.toLowerCase() === "host")).toEqual(["Host"]);
  expect(names).toEqual(expect.arrayContaining(expected.map(spell)));
}

const sent = { headers: { "x-demo": "1" }, body: "hi" };
const ok = rawResponse("200 OK", [], "ok");

describe.each(["http", "https"])("HTTP/1.1 header names over %s", (scheme) => {
  const secure = scheme === "https";

  describe.each([undefined, true, false])("with titleCaseHeaders %s", (setting) => {
    it("follow the setting in a request", async () => {
      const raw = await rawServer(secure, ok);
      const res = await testClient(withSetting(setting)).session().post(raw.url, sent);
      await res.text();
      expectNames(raw, setting, ["host", "content-length", "x-demo"]);
    });

    it("follow the setting in a streamed request", async () => {
      const raw = await rawServer(secure, ok);
      const session = testClient(withSetting(setting)).session();
      const res = await session.stream(raw.url, { ...sent, method: "POST" });
      await res.text();
      expectNames(raw, setting, ["host", "content-length", "x-demo"]);
    });

    it("follow the setting over a preconnected connection", async () => {
      const raw = await rawServer(secure, ok);
      const session = testClient(withSetting(setting)).session();
      await session.preconnect(raw.url);
      await (await session.post(raw.url, sent)).text();
      expect(raw.connections).toBe(1);
      expectNames(raw, setting, ["host", "content-length", "x-demo"]);
    });
  });
});

describe("HTTP/1.1 header names in a WebSocket handshake", () => {
  // Upstream opens WebSockets over TLS only (`wss://`).
  it.each([undefined, true, false])("follow titleCaseHeaders %s", async (setting) => {
    const raw = await rawServer(true, rawResponse("400 Bad Request"));
    const session = testClient(withSetting(setting)).session();
    const url = raw.url.replace(/^https/, "wss");
    await expect(session.websocket(url)).rejects.toThrow(/WebSocket upgrade failed/);
    expectNames(raw, setting, ["host", "upgrade", "sec-websocket-key"]);
  });
});

// Upstream keeps `Host` capitalized in lowercase mode by rewriting the request head as it is
// written, so header-like bytes after the head, in a body or a WebSocket frame, must go out as is.
const LOOKALIKE_BODY = "host: body\r\n\r\nPOST / HTTP/1.1\r\nhost: body\r\n\r\n";
const LOOKALIKE_FRAME = Buffer.from("GET / HTTP/1.1\r\nhost: frame\r\n\r\n");

/** What `/upload-echo` reports about the body it received. */
interface UploadEcho {
  length: number;
  sha256: string;
  content_length: string | null;
  transfer_encoding: string | null;
  http_version: string;
}

/** The lookalike body in two chunks, so that it goes out chunked. */
async function* chunkedBody(): AsyncGenerator<string> {
  yield LOOKALIKE_BODY.slice(0, 7);
  yield LOOKALIKE_BODY.slice(7);
}

const received = {
  length: Buffer.byteLength(LOOKALIKE_BODY),
  sha256: createHash("sha256").update(LOOKALIKE_BODY).digest("hex"),
  http_version: "1.1",
};

describe.each(["request", "stream"] as const)("Lowercase header names with %s()", (method) => {
  const session = testClient({ h1: { titleCaseHeaders: false } }).session({
    preferredHttpVersion: "http1_only",
  });

  /** POSTs `body` to `/upload-echo` and returns what the server received. */
  async function upload(body: string | AsyncIterable<string>): Promise<UploadEcho> {
    const url = serverUrl("/upload-echo");
    const options = { method: "POST", body };
    const res =
      method === "request"
        ? await session.request(url, options)
        : await session.stream(url, options);
    return res.json<UploadEcho>();
  }

  it("leave a fixed-length body untouched", async () => {
    await expect(upload(LOOKALIKE_BODY)).resolves.toMatchObject({
      ...received,
      content_length: String(received.length),
    });
  });

  it("leave a chunked body untouched", async () => {
    await expect(upload(chunkedBody())).resolves.toMatchObject({
      ...received,
      transfer_encoding: "chunked",
    });
  });
});

describe("Lowercase header names in a WebSocket connection", () => {
  it("leave the frames untouched", async () => {
    const session = testClient({ h1: { titleCaseHeaders: false } }).session();
    const ws = await session.websocket(`${server.url.replace("https://", "wss://")}/ws-echo`);
    await ws.send(LOOKALIKE_FRAME);
    const echoed = await ws.receive();
    await ws.close();
    expect(echoed.type).toBe("binary");
    expect((echoed as { data: Buffer }).data.equals(LOOKALIKE_FRAME)).toBe(true);
  });
});

describe("Client#h1TitleCaseHeaders", () => {
  it("reports the setting, which defaults to Title-Case", () => {
    const settings = [undefined, true, false].map(
      (setting) => new Client(withSetting(setting)).h1TitleCaseHeaders,
    );
    expect(settings).toEqual([true, true, false]);
  });
});
