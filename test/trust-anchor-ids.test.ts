import { X509Certificate } from "node:crypto";
import { rootCertificates } from "node:tls";
import { describe, expect, it, onTestFinished } from "vitest";
import {
  Client,
  type ClientOptions,
  ExtensionType,
  RequestError,
  TlsError,
  TlsProfile,
  trustAnchorIdentity,
} from "../src/index.js";
import { type ClientHello, startClientHelloServer } from "./support/client-hello.js";
import { server, serverUrl, testClient } from "./support/clients.js";
import { expectInvalidConfig } from "./support/helpers.js";
import { rawResponse, startRawHttpServer } from "./support/raw-http.js";

// Trust Anchor Identifiers (draft-ietf-tls-trust-anchor-ids-06). Node's TLS servers do not
// implement them, so the server's side (its ID list, the match flag and a recovery connection)
// is left to upstream's own tests. These cover what the client sends and reports, and the
// settings it refuses.

/** The trust anchor IDs a TLS preset lists, in its order. */
function profileIds(name: string): string[] {
  const extensions = TlsProfile.preset(name).toJSON().extensions as Array<{
    extension_type: number;
    source: { ids?: string[] };
  }>;
  const extension = extensions.find(
    ({ extension_type }) => extension_type === ExtensionType.TRUST_ANCHOR_IDS,
  );
  return extension?.source.ids ?? [];
}

/** `ids` in byte order, duplicates dropped. */
function sortedSet(ids: Iterable<string>): string[] {
  return [...new Set(ids)].sort();
}

/** The ClientHellos a client sends over `count` handshakes, each on a new connection. */
async function hellos(options: ClientOptions, count: number): Promise<readonly ClientHello[]> {
  const capture = await startClientHelloServer();
  onTestFinished(() => capture.close());
  const client = new Client(options);
  for (let handshake = 0; handshake < count; handshake++) {
    await expect(client.session().get(capture.url)).rejects.toThrow(RequestError);
  }
  return capture.hellos;
}

describe("Trust anchor IDs in the ClientHello", () => {
  it.each([
    ["chrome_155", {}],
    ["chrome_156", { preset: "chrome_156" }],
    ["chrome_157", { preset: "chrome_157" }],
    ["chrome_158", { preset: "chrome_158" }],
  ])("keep %s's sorted order on every handshake", async (name, options) => {
    const listed = profileIds(name);
    expect([listed.length, listed]).toEqual([28, sortedSet(listed)]);
    const sent = await hellos(options, 4);
    expect(sent.map((hello) => hello.trustAnchorIds)).toEqual(sent.map(() => listed));
    // The extensions around them are still shuffled per connection.
    expect(new Set(sent.map((hello) => hello.extensions.join())).size).toBeGreaterThan(1);
  });

  it("are shuffled on every handshake by Chrome 154", async () => {
    const sent = await hellos({ preset: "chrome_154" }, 4);
    const listed = sortedSet(profileIds("chrome_154"));
    expect(sent.map((hello) => sortedSet(hello.trustAnchorIds ?? []))).toEqual(
      sent.map(() => listed),
    );
    expect(new Set(sent.map((hello) => hello.trustAnchorIds?.join())).size).toBeGreaterThan(1);
  });

  it("are the trusted roots' with advertisement trusted, a binding's included", async () => {
    const id = "81fd5901";
    const anchorIdentity = trustAnchorIdentity(server.ca);
    const [hello] = await hellos(
      {
        preset: "chrome_157",
        tls: {
          ca: server.ca,
          trustAnchorIds: { advertisement: "trusted", bindings: [{ id, anchorIdentity }] },
        },
      },
      1,
    );
    const sent = hello?.trustAnchorIds ?? [];
    expect(sent).toEqual(sortedSet(sent));
    expect(sent).toContain(id);
    // The bundled metadata names Chrome 157's roots, not the intermediates it also lists.
    const listed = profileIds("chrome_157");
    expect(sent.filter((other) => other !== id && !listed.includes(other))).toEqual([]);
    expect(sent.length).toBeLessThan(listed.length);
  });
});

describe("Diagnostics#trustAnchor", () => {
  it("reports the negotiation of the TLS connection a request opened", async () => {
    const session = testClient({ preset: "chrome_157" }).session();
    const first = await session.get(serverUrl("/get"));
    expect(first.diagnostics.trustAnchor).toEqual({
      requestedIds: profileIds("chrome_157"),
      availableIds: [],
      matchedRequest: false,
      verifiedAnchor: trustAnchorIdentity(server.ca),
      authenticated: true,
      echRejected: false,
      recovered: false,
      recoveryEligible: false,
    });
    // The second request reuses the connection.
    const second = await session.get(serverUrl("/get"));
    expect(second.diagnostics.trustAnchor).toBeUndefined();
  });

  it("is absent over plain HTTP", async () => {
    const raw = await startRawHttpServer(() => rawResponse("200 OK", [], "ok"));
    onTestFinished(() => raw.close());
    const res = await testClient().session().get(raw.url);
    expect(res.diagnostics.trustAnchor).toBeUndefined();
  });
});

describe("RequestError#trustAnchor", () => {
  /** Expects the TLS error of a handshake whose chain reached no trusted root. */
  function expectUntrusted(error: unknown): void {
    expect(error).toBeInstanceOf(TlsError);
    expect((error as TlsError).trustAnchor).toEqual({
      requestedIds: profileIds("chrome_157"),
      availableIds: [],
      matchedRequest: false,
      authenticated: false,
      echRejected: false,
      recovered: false,
      failure: expect.stringMatching(/certificate chain verification failed/),
      // The server listed no IDs, so there is none to recover with.
      recoveryEligible: false,
    });
  }

  // Without the test CA, the server's self-signed certificate reaches no trusted root.
  const untrusting = () => new Client({ preset: "chrome_157" }).session();

  it("reports the failed handshake of request()", async () => {
    expectUntrusted(
      await untrusting()
        .get(serverUrl("/get"))
        .catch((error: unknown) => error),
    );
  });

  it("reports the failed handshake of stream()", async () => {
    expectUntrusted(
      await untrusting()
        .stream(serverUrl("/get"))
        .catch((error: unknown) => error),
    );
  });
});

describe("tls.trustAnchorIds", () => {
  it("builds clients that advertise the trusted roots' IDs or recover", () => {
    for (const trustAnchorIds of [
      { advertisement: "trusted" },
      { recovery: "once" },
      { advertisement: "trusted", recovery: "once" },
    ] as const) {
      expect(() => new Client({ tls: { trustAnchorIds } })).not.toThrow();
      expect(() => new Client({ preset: "chrome_157", tls: { trustAnchorIds } })).not.toThrow();
    }
  });

  /** Options that bind `id` to the test server's certificate. */
  const binding = (id: string): ClientOptions => ({
    tls: {
      ca: server.ca,
      trustAnchorIds: { bindings: [{ id, anchorIdentity: trustAnchorIdentity(server.ca) }] },
    },
  });

  it.each<[string, () => ClientOptions]>([
    [
      "an unknown advertisement",
      () => ({ tls: { trustAnchorIds: { advertisement: "x" as never } } }),
    ],
    ["an unknown recovery", () => ({ tls: { trustAnchorIds: { recovery: "twice" as never } } })],
    ["an ID that is not hex", () => binding("zz")],
    ["an empty ID", () => binding("")],
    ["an ID over 32 bytes", () => binding("01".repeat(33))],
    ["an ID that is not minimally encoded", () => binding("8001")],
    ["an ID that does not end", () => binding("81")],
    [
      "a binding to a root the client does not trust",
      () => ({
        tls: { trustAnchorIds: { bindings: [{ id: "2a", anchorIdentity: "00".repeat(32) }] } },
      }),
    ],
    [
      "one ID bound to two roots",
      () => {
        const roots = [server.ca, rootCertificates[0] ?? ""];
        return {
          tls: {
            ca: roots,
            trustAnchorIds: {
              bindings: roots.map((root) => ({
                id: "2a",
                anchorIdentity: trustAnchorIdentity(root),
              })),
            },
          },
        };
      },
    ],
    [
      "recovery without certificate verification",
      () => ({ tls: { rejectUnauthorized: false, trustAnchorIds: { recovery: "once" } } }),
    ],
    [
      "recovery with fallback.proxyToDirect",
      () => ({ fallback: { proxyToDirect: true }, tls: { trustAnchorIds: { recovery: "once" } } }),
    ],
    [
      "a TLS profile without the extension",
      () => ({ preset: "firefox_156", tls: { trustAnchorIds: { advertisement: "trusted" } } }),
    ],
    [
      "TLS synthesis",
      () => ({
        preset: "chrome_157",
        randomize: { mode: "recombine", layers: ["tls"] },
        tls: { trustAnchorIds: { recovery: "once" } },
      }),
    ],
  ])("rejects %s", (_case, options) => {
    expectInvalidConfig(() => new Client(options()));
  });
});

describe("trustAnchorIdentity", () => {
  it("names a certificate by 64 hex digits, from PEM or DER", () => {
    const identity = trustAnchorIdentity(server.ca);
    expect(identity).toMatch(/^[0-9a-f]{64}$/);
    expect(trustAnchorIdentity(new X509Certificate(server.ca).raw)).toBe(identity);
    expect(trustAnchorIdentity(Buffer.from(server.ca))).toBe(identity);
    expect(trustAnchorIdentity(rootCertificates[0] ?? "")).not.toBe(identity);
  });

  it("rejects what is not a certificate", () => {
    expectInvalidConfig(() => trustAnchorIdentity("not a certificate"));
    expectInvalidConfig(() => trustAnchorIdentity(new Uint8Array([1, 2, 3])));
  });
});
