import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Client, listPresets, TlsProfile } from "../src/index.js";
import { h3Url, server, serverUrl, testClient } from "./support/clients.js";
import { expectInvalidConfig } from "./support/helpers.js";

const h3Port = Number(new URL(server.h3Url).port);

describe("HTTP/3", () => {
  it("serves a request over QUIC with http3_only", async () => {
    const session = testClient({ preset: "chrome_155" }).session({
      preferredHttpVersion: "http3_only",
    });
    const res = await session.get(h3Url("/get"), { timeout: 5_000 });
    expect(res.status).toBe(200);
    expect(res.httpVersion).toBe("3.0");
    expect(res.diagnostics.protocol).toBe("h3");
    await expect(res.json()).resolves.toHaveProperty("headers");
  });

  it("times the QUIC handshake of the request that opened the connection", async () => {
    const session = testClient({ preset: "chrome_155" }).session({
      preferredHttpVersion: "http3_only",
    });
    const first = await session.get(h3Url("/get"), { timeout: 5_000 });
    expect(first.diagnostics).toMatchObject({
      protocol: "h3",
      quicMs: expect.any(Number),
      remoteAddr: `127.0.0.1:${h3Port}`,
    });
    expect(first.diagnostics.tcpMs).toBeUndefined();
    expect(first.diagnostics.tlsMs).toBeUndefined();
    // A reused connection had no handshake, but still says where it goes.
    const again = await session.get(h3Url("/get"), { timeout: 5_000 });
    expect(again.diagnostics.quicMs).toBeUndefined();
    expect(again.diagnostics.remoteAddr).toBe(`127.0.0.1:${h3Port}`);
  });

  it.each([
    "chrome",
    "chrome_146",
    "chrome_153",
    "chrome_154",
    "chrome_155",
    "chrome_156",
    "chrome_157",
    "chrome_158",
  ])(
    "keeps the connection across responses that use the QPACK dynamic table (%s)",
    async (quicProfile) => {
      // The Chrome presets advertise a 64 KiB dynamic table and aioquic uses it from the
      // second response on; decoding static references only used to kill the connection.
      const session = testClient({ quicProfile }).session({ preferredHttpVersion: "http3_only" });
      for (let i = 0; i < 4; i++) {
        const res = await session.get(h3Url("/get"), { timeout: 5_000 });
        expect([res.status, res.httpVersion]).toEqual([200, "3.0"]);
      }
    },
  );

  it("decodes concurrent responses against one dynamic table", async () => {
    const session = testClient({ quicProfile: "chrome_154" }).session({
      preferredHttpVersion: "http3_only",
    });
    await session.get(h3Url("/get"), { timeout: 5_000 });
    const responses = await Promise.all(
      Array.from({ length: 30 }, (_, i) => session.get(h3Url(`/get?n=${i}`), { timeout: 10_000 })),
    );
    expect(responses.map((res) => [res.status, res.httpVersion])).toEqual(
      Array.from({ length: 30 }, () => [200, "3.0"]),
    );
  });

  it("streams a response over HTTP/3", async () => {
    const session = testClient({ quicProfile: "chrome_155" }).session({
      preferredHttpVersion: "http3_only",
    });
    const res = await session.stream(h3Url("/stream-bytes/50000?seed=3"), { timeout: 5_000 });
    expect((await res.bytes()).byteLength).toBe(50_000);
  });

  it.runIf(server.h3UrlIpv6 !== null).each([0, 6] as const)(
    "reaches an IPv6 target with family %s",
    async (family) => {
      const session = testClient({ quicProfile: "chrome_154", family }).session({
        preferredHttpVersion: "http3_only",
      });
      const res = await session.get(new URL("/get", server.h3UrlIpv6 ?? "").href, {
        timeout: 5_000,
      });
      expect([res.status, res.httpVersion]).toEqual([200, "3.0"]);
    },
  );

  it("dials the connectTo address over QUIC", async () => {
    const client = testClient({
      quicProfile: "chrome_154",
      tls: { rejectUnauthorized: false },
      connectTo: { [`connect-to.test:${h3Port}`]: `127.0.0.1:${h3Port}` },
    });
    const res = await client
      .session({ preferredHttpVersion: "http3_only" })
      .get(`https://connect-to.test:${h3Port}/get`, { timeout: 5_000 });
    expect([res.status, res.httpVersion]).toEqual([200, "3.0"]);
  });

  it("reuses the pooled HTTP/2 connection when HTTP/3 falls back", async () => {
    // The main server is TCP only, so every HTTP/3 attempt falls back. Upstream once looked
    // only for a pooled HTTP/3 connection and redialled TCP and TLS for each request.
    const session = testClient({ preset: "chrome_152" }).session({
      preferredHttpVersion: "http3_with_fallback",
    });
    const first = await session.get(serverUrl("/get"));
    expect(first.httpVersion).toBe("2.0");
    expect(first.diagnostics.tlsMs).toBeDefined();
    for (let i = 0; i < 2; i++) {
      const res = await session.get(serverUrl("/get"));
      expect(res.httpVersion).toBe("2.0");
      expect(res.diagnostics.tcpMs).toBeUndefined();
      expect(res.diagnostics.tlsMs).toBeUndefined();
    }
  });

  it("never tries HTTP/3 with disableHttp3", async () => {
    const session = testClient({ quicProfile: "chrome_155", disableHttp3: true }).session();
    const res = await session.get(h3Url("/get"), { timeout: 5_000 });
    expect(res.httpVersion).toBe("2.0");
  });
});

describe("quicFingerprint", () => {
  /** What a ClientHello offers: its cipher suites and signature algorithms, GREASE left out. */
  interface Offer {
    readonly cipher_suites: readonly number[];
    readonly signature_algorithms: readonly number[];
  }

  /** `offer` without its GREASE values. */
  function withoutGrease(offer: Offer): Offer {
    const keep = (values: readonly number[]) =>
      values.filter((value) => (value & 0x0f0f) !== 0x0a0a);
    return {
      cipher_suites: keep(offer.cipher_suites),
      signature_algorithms: keep(offer.signature_algorithms),
    };
  }

  // The test server records each QUIC ClientHello under the name it was sent to, so each case
  // sends to a name of its own (the certificate covers `*.lkrequest.test`).
  it.each([
    ["chrome_158", "chrome_158_quic"],
    ["chrome_158_quic", "chrome_158_quic"],
    // What a client with the chrome_147 preset sends over QUIC.
    ["chrome_147", "chrome_146_quic"],
    // Presets without a QUIC ClientHello of their own send their TLS one.
    ["chrome_131", "chrome_131"],
    ["firefox_156", "firefox_156"],
  ])("sends for %s the QUIC ClientHello %s", async (name, expected) => {
    const host = `quic-hello-${randomUUID()}.lkrequest.test`;
    const client = testClient({
      quicProfile: "chrome_158",
      quicFingerprint: name,
      connectTo: { [`${host}:${h3Port}`]: `127.0.0.1:${h3Port}` },
    });
    const res = await client
      .session({ preferredHttpVersion: "http3_only" })
      .get(`https://${host}:${h3Port}/get`, { timeout: 5_000 });
    expect(res.httpVersion).toBe("3.0");
    const control = testClient().session();
    const hellos = (await (
      await control.get(serverUrl(`/_test/quic-hellos?sni=${host}`))
    ).json()) as Offer[];
    expect(hellos.length).toBeGreaterThan(0);
    const sent = withoutGrease(TlsProfile.preset(expected).toJSON() as unknown as Offer);
    expect(hellos.map(withoutGrease)).toEqual(hellos.map(() => sent));
  });

  it("takes every browser preset name and every QUIC TLS preset name", () => {
    const quicTls = TlsProfile.presetNames().filter((name) => name.endsWith("_quic"));
    for (const name of [...listPresets().map((preset) => preset.name), ...quicTls]) {
      expect(() => new Client({ quicFingerprint: name }), name).not.toThrow();
    }
  });

  it("refuses an unknown name, listing the ones it takes", () => {
    expectInvalidConfig(() => new Client({ quicFingerprint: "chrome_158_tcp" }));
    expect(() => new Client({ quicFingerprint: "chrome_158_tcp" })).toThrow(
      /unknown QUIC TLS profile preset "chrome_158_tcp"; expected one of .*chrome_158_quic/,
    );
  });
});
