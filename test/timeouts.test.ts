import { type AddressInfo, createServer, type Socket } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, TimeoutError } from "../src/index.js";
import { serverUrl, testClient } from "./support/clients.js";
import { expectInvalidConfig } from "./support/helpers.js";

// A server of its own rather than httpbin's `/drip`: abandoning a slow httpbin response ties up
// one of the shared test server's threads.
let stalling: { url: string; close(): void };

/**
 * An HTTP/1.1 server that sends its headers and the first 10 bytes of a 1000-byte body, then
 * stalls. It hangs up after 10 s, so a deadline that never fires fails a test instead of
 * hanging it.
 */
async function startStallingServer(): Promise<{ url: string; close(): void }> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.once("data", () => {
      socket.write(`HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n${"x".repeat(10)}`);
      setTimeout(() => socket.destroy(), 10_000).unref();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/`,
    close() {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

beforeAll(async () => {
  stalling = await startStallingServer();
});

afterAll(() => {
  stalling.close();
});

describe("timeouts.readIdle", () => {
  it("fails a buffered body that stops arriving", async () => {
    const session = new Client({ timeouts: { readIdle: 300 } }).session();
    const started = Date.now();
    await expect(session.get(stalling.url)).rejects.toBeInstanceOf(TimeoutError);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("fails a streamed body that stops arriving", async () => {
    const res = await new Client({ timeouts: { readIdle: 300 } }).session().stream(stalling.url);
    expect(res.status).toBe(200);
    await expect(res.bytes()).rejects.toBeInstanceOf(TimeoutError);
  });

  it("is off by default", async () => {
    // Only the total time limit ends this one.
    const res = await new Client({ timeouts: { total: 1_000 } }).session().stream(stalling.url);
    const started = Date.now();
    await expect(res.bytes()).rejects.toBeInstanceOf(TimeoutError);
    expect(Date.now() - started).toBeGreaterThan(500);
  });

  it("refuses a negative or NaN limit", () => {
    expectInvalidConfig(() => new Client({ timeouts: { readIdle: -1 } }));
    expectInvalidConfig(() => new Client({ timeouts: { readIdle: Number.NaN } }));
  });
});

describe("timeouts.total and a request's timeout", () => {
  it("bound the reading of a streamed body", async () => {
    const res = await new Client({ timeouts: { total: 500 } }).session().stream(stalling.url);
    await expect(res.bytes()).rejects.toBeInstanceOf(TimeoutError);
    const own = await new Client().session().stream(stalling.url, { timeout: 500 });
    await expect(own.bytes()).rejects.toBeInstanceOf(TimeoutError);
  });
});

describe("null", () => {
  it("turns each time limit off", async () => {
    const client = testClient({
      timeouts: {
        dns: null,
        tcpConnect: null,
        tlsHandshake: null,
        ttfb: null,
        total: null,
        quicConnect: null,
        readIdle: null,
      },
    });
    expect((await client.session().get(serverUrl("/get"))).status).toBe(200);
  });

  it("leaves the other limits in place", async () => {
    const session = new Client({ timeouts: { total: null, readIdle: 300 } }).session();
    await expect(session.get(stalling.url)).rejects.toBeInstanceOf(TimeoutError);
  });
});
