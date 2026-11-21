import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { createServer, type SecureVersion } from "node:tls";
import { describe, expect, it } from "vitest";
import { Client, type ClientOptions } from "../src/index.js";
import { server } from "./support/clients.js";
import { expectInvalidConfig } from "./support/helpers.js";

/**
 * A TLS server over one version that answers every request and records, for each connection,
 * whether it resumed a session.
 */
async function startResumptionServer(
  version: SecureVersion,
): Promise<{ url: string; resumed: boolean[]; close(): void }> {
  const resumed: boolean[] = [];
  const tlsServer = createServer(
    {
      key: server.key,
      cert: server.ca,
      minVersion: version,
      maxVersion: version,
      ALPNProtocols: ["http/1.1"],
    },
    (socket) => {
      resumed.push(socket.isSessionReused());
      socket.once("data", () => {
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      });
    },
  );
  tlsServer.on("tlsClientError", () => {});
  await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve));
  const { port } = tlsServer.address() as AddressInfo;
  return { url: `https://127.0.0.1:${port}/`, resumed, close: () => tlsServer.close() };
}

/** A client trusting the test certificate, with `tls` options added. */
function clientWith(tls: ClientOptions["tls"] = {}): Client {
  return new Client({ tls: { ca: server.ca, ...tls } });
}

/** Sends one request from a new session of `client`, so on a connection of its own. */
async function connect(client: Client, url: string): Promise<void> {
  await client.session().get(url);
}

describe.each(["TLSv1.3", "TLSv1.2"] as const)("TLS session cache over %s", (version) => {
  it("resumes the session on later connections", async () => {
    const tlsServer = await startResumptionServer(version);
    try {
      const client = clientWith();
      for (let i = 0; i < 3; i++) await connect(client, tlsServer.url);
      expect(tlsServer.resumed).toEqual([false, true, true]);
    } finally {
      tlsServer.close();
    }
  });

  it.each([
    ["a lifetime of 0", { sessionCacheTtl: 0 }],
    ['the "disabled" policy', { sessionResumptionPolicy: "disabled" }],
  ] as const)("caches nothing with %s", async (_, tls) => {
    const tlsServer = await startResumptionServer(version);
    try {
      const client = clientWith(tls);
      for (let i = 0; i < 2; i++) await connect(client, tlsServer.url);
      expect(tlsServer.resumed).toEqual([false, false]);
    } finally {
      tlsServer.close();
    }
  });

  it("stops resuming a session once its lifetime has passed", async () => {
    const tlsServer = await startResumptionServer(version);
    try {
      const client = clientWith({ sessionCacheTtl: 300 });
      await connect(client, tlsServer.url);
      await connect(client, tlsServer.url);
      await sleep(500);
      await connect(client, tlsServer.url);
      expect(tlsServer.resumed).toEqual([false, true, false]);
    } finally {
      tlsServer.close();
    }
  });
});

describe("tlsSessionCacheTtl and tlsSessionCacheEnabled", () => {
  it("read the setting back", () => {
    expect([clientWith().tlsSessionCacheTtl, clientWith().tlsSessionCacheEnabled]).toEqual([
      null,
      true,
    ]);
    const hour = clientWith({ sessionCacheTtl: 3_600_000 });
    expect([hour.tlsSessionCacheTtl, hour.tlsSessionCacheEnabled]).toEqual([3_600_000, true]);
    const none = clientWith({ sessionCacheTtl: 0 });
    expect([none.tlsSessionCacheTtl, none.tlsSessionCacheEnabled]).toEqual([0, false]);
    const disabled = clientWith({ sessionResumptionPolicy: "disabled" });
    expect(disabled.tlsSessionCacheEnabled).toBe(false);
  });

  it("refuses a negative lifetime", () => {
    expectInvalidConfig(() => clientWith({ sessionCacheTtl: -1 }));
  });
});
