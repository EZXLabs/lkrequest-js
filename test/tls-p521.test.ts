import type { AddressInfo } from "node:net";
import { createServer, type SecureVersion } from "node:tls";
import { describe, expect, it } from "vitest";
import { Client, TlsError } from "../src/index.js";
import { server } from "./support/clients.js";
import type { TestCertificate } from "./support/global-setup.js";

// P-521, which the Firefox presets and `safari_18` offer: a server certificate on the curve,
// over TLS 1.3 (signed with `ecdsa_secp521r1_sha512`) and TLS 1.2 (signed with the client's
// first ECDSA scheme, which TLS 1.2 allows on any curve), and a key exchange on it. Chrome
// offers none of it and is refused. A P-256 CA signs both certificates, so the chain verifies
// whatever the leaf, and only the handshake is on P-521.

const { ecPki } = server;
const VERSIONS: SecureVersion[] = ["TLSv1.3", "TLSv1.2"];
const OFFER_P521 = ["firefox_156", "safari_18"];

/**
 * Serves `200 OK` over HTTP/1.1 with `leaf`, over one TLS version, and with a key exchange on
 * `curve` alone when one is given. Resolves with the URL and a function that stops it.
 */
async function serve(
  leaf: TestCertificate,
  version: SecureVersion,
  curve?: string,
): Promise<{ url: string; close: () => void }> {
  const tlsServer = createServer(
    {
      cert: leaf.cert,
      key: leaf.key,
      ALPNProtocols: ["http/1.1"],
      minVersion: version,
      maxVersion: version,
      ...(curve !== undefined && { ecdhCurve: curve }),
    },
    (socket) => {
      socket.once("data", () => {
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
      });
    },
  );
  tlsServer.on("tlsClientError", () => {});
  await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve));
  const { port } = tlsServer.address() as AddressInfo;
  return { url: `https://127.0.0.1:${port}/`, close: () => tlsServer.close() };
}

/** Sends a GET with `preset`, trusting the CA of the test certificates. */
async function get(preset: string, url: string): Promise<number> {
  const response = await new Client({ preset, tls: { ca: ecPki.ca } }).session().get(url);
  return response.status;
}

describe.each(VERSIONS)("P-521 over %s", (version) => {
  it.each(OFFER_P521)("accepts a P-521 certificate with %s", async (preset) => {
    const { url, close } = await serve(ecPki.p521, version);
    try {
      expect(await get(preset, url)).toBe(200);
    } finally {
      close();
    }
  });

  // Over TLS 1.3 the presets send no P-521 key share, so the server asks for one with a
  // HelloRetryRequest.
  it.each(OFFER_P521)("agrees on a P-521 key exchange with %s", async (preset) => {
    const { url, close } = await serve(ecPki.p256, version, "secp521r1");
    try {
      expect(await get(preset, url)).toBe(200);
    } finally {
      close();
    }
  });

  it("refuses a P-521 certificate with a Chrome preset, which offers none of it", async () => {
    const { url, close } = await serve(ecPki.p521, version);
    try {
      const error = await get("chrome_157", url).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(TlsError);
      expect(error).toMatchObject({ phase: "tls_handshake" });
    } finally {
      close();
    }
  });
});
