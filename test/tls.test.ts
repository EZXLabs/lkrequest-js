import { mkdtempSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTlsServer } from "node:tls";
import { describe, expect, it } from "vitest";
import {
  Client,
  type LogRecord,
  onLog,
  ResourceLimitError,
  setLogLevel,
  TlsError,
} from "../src/index.js";
import { server, serverUrl, testClient } from "./support/clients.js";
import { expectInvalidConfig, waitFor } from "./support/helpers.js";

/** The DER bytes inside a PEM certificate. */
function pemToDer(pem: string): Uint8Array {
  const base64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  return Buffer.from(base64, "base64");
}

/** Resolves with the status of a GET to the test server. */
async function statusWith(client: Client): Promise<number> {
  return (await client.session().get(serverUrl("/get"))).status;
}

describe("TLS options", () => {
  it("rejects a certificate it does not trust", async () => {
    await expect(statusWith(new Client())).rejects.toThrow(TlsError);
    await expect(statusWith(new Client({ tls: { useNativeCerts: true } }))).rejects.toThrow(
      TlsError,
    );
  });

  it.each([
    ["a PEM string", { ca: server.ca }],
    ["PEM bytes", { ca: Buffer.from(server.ca) }],
    ["a list of PEM documents", { ca: [server.ca] }],
    ["a DER certificate", { caDer: pemToDer(server.ca) }],
  ])("trusts an extra anchor given as %s", async (_, tls) => {
    await expect(statusWith(new Client({ tls }))).resolves.toBe(200);
  });

  it("skips verification with rejectUnauthorized: false", async () => {
    await expect(statusWith(new Client({ tls: { rejectUnauthorized: false } }))).resolves.toBe(200);
  });

  it("writes TLS secrets to the keylog file", async () => {
    const keylog = join(mkdtempSync(join(tmpdir(), "lkrequest-keylog-")), "keys.log");
    await statusWith(testClient({ tls: { keylog } }));
    expect(readFileSync(keylog, "utf8")).toMatch(/^CLIENT_HANDSHAKE_TRAFFIC_SECRET [0-9a-f]+ /m);
  });

  it("hands TLS secrets to a keylog function, one line at a time", async () => {
    const lines: string[] = [];
    await statusWith(testClient({ tls: { keylog: (line) => lines.push(line) } }));
    await waitFor(() => lines.some((line) => line.startsWith("SERVER_TRAFFIC_SECRET_0")));
    expect(lines).toContainEqual(
      expect.stringMatching(/^CLIENT_HANDSHAKE_TRAFFIC_SECRET [0-9a-f]{64} [0-9a-f]+$/),
    );
    expect(lines.some((line) => line.includes("\n"))).toBe(false);
  });

  it("logs a keylog function that throws and finishes the request", async () => {
    const records: LogRecord[] = [];
    const unsubscribe = onLog((record) => records.push(record));
    setLogLevel("lkrequest_napi=warn");
    try {
      const keylog = (): void => {
        throw new Error("sink is full");
      };
      await expect(statusWith(testClient({ tls: { keylog } }))).resolves.toBe(200);
      await waitFor(() =>
        records.some((record) => /tls\.keylog function failed/.test(record.message)),
      );
      expect(records.find((record) => /sink is full/.test(record.message))?.level).toBe("warn");
    } finally {
      setLogLevel("off");
      unsubscribe();
    }
  });

  it("rejects a keylog that is neither a path nor a function", () => {
    expectInvalidConfig(() => new Client({ tls: { keylog: 5 as unknown as string } }));
  });

  it("accepts the remaining TLS options", () => {
    expect(
      () => new Client({ tls: { requireCloseNotify: true, ech: new Uint8Array([0, 0]) } }),
    ).not.toThrow();
  });

  // The client sends no certificate. Over TLS 1.3 the server finds out only after the client
  // has finished its handshake and sent the request, so its alert arrives where the response
  // would: a TlsError all the same. A few tries, as the alert used to get lost now and then.
  it("fails with TlsError when the server wants a client certificate", async () => {
    const tlsServer = createTlsServer(
      {
        key: server.key,
        cert: server.ca,
        ca: server.ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      },
      (socket) => socket.end("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    tlsServer.on("tlsClientError", () => {});
    await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve));
    const { port } = tlsServer.address() as AddressInfo;
    try {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const error = await testClient({ timeouts: { ttfb: 5000 } })
          .session()
          .get(`https://localhost:${port}/`)
          .catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(TlsError);
        expect(error).toMatchObject({ phase: "http_request", retryable: false });
        expect((error as TlsError).message).toMatch(/certificate_required/);
      }
    } finally {
      tlsServer.close();
    }
  });
});

describe("resource limits", () => {
  it("fails a body larger than maxResponseBodySize", async () => {
    const session = testClient({ limits: { maxResponseBodySize: 1024 } }).session();
    await expect(session.get(serverUrl("/bytes/1024"))).resolves.toMatchObject({ status: 200 });
    const error = await session.get(serverUrl("/bytes/4096")).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ResourceLimitError);
    expect(error).toMatchObject({ code: "ERR_LK_RESOURCE_LIMIT" });
  });

  it("fails a response with more headers than maxHeaderCount", async () => {
    const session = testClient({ limits: { maxHeaderCount: 8 } }).session();
    const query = Array.from({ length: 16 }, (_, i) => `x-extra-${i}=1`).join("&");
    await expect(session.get(serverUrl(`/response-headers?${query}`))).rejects.toThrow(
      ResourceLimitError,
    );
  });
});
