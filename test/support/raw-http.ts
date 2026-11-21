import { createServer, type Socket } from "node:net";
import { createServer as createTlsServer } from "node:tls";

// An HTTP/1.1 server, plain or over TLS, that writes back exactly the bytes a test hands it, for
// responses the httpbin server cannot produce: a `Location` in raw UTF-8, a hand-made deflate
// body. It also records each request head as it arrived, header names in their sent case.

/** A request as the server received it. */
export interface RawRequest {
  /** The request line, for example `GET /path HTTP/1.1`. */
  readonly line: string;
  /** Header names exactly as sent, in arrival order. */
  readonly names: readonly string[];
  /** Header fields in arrival order, names lower-cased and values decoded as latin1. */
  readonly fields: ReadonlyArray<readonly [string, string]>;
  /** Header values by name, as in `fields`; the last one wins where a name repeats. */
  readonly headers: Readonly<Record<string, string>>;
}

/** A running raw HTTP server. */
export interface RawHttpServer {
  /** `http://127.0.0.1:<port>`, or `https://` over TLS. */
  readonly url: string;
  /** Every request received, in arrival order. */
  readonly requests: readonly RawRequest[];
  /** How many connections the server has accepted. */
  readonly connections: number;
  /** Stops listening and drops every connection. */
  close(): Promise<void>;
}

/** Options of {@link startRawHttpServer}. */
export interface RawHttpServerOptions {
  /** Serve over TLS with this key and certificate (PEM), offering only `http/1.1` by ALPN. */
  readonly tls?: { readonly key: string; readonly cert: string };
}

/**
 * Starts a server on a loopback port. As soon as the head of a request has arrived, `answer`
 * returns the whole response to it, which is written as is before the connection is closed.
 * Request bodies are not read.
 */
export async function startRawHttpServer(
  answer: (request: RawRequest, index: number) => Buffer,
  options: RawHttpServerOptions = {},
): Promise<RawHttpServer> {
  const requests: RawRequest[] = [];
  const sockets = new Set<Socket>();
  let connections = 0;
  const serve = (socket: Socket): void => {
    connections += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) return;
      socket.off("data", onData);
      const [line = "", ...lines] = head.subarray(0, end).toString("latin1").split("\r\n");
      const names: string[] = [];
      const fields: Array<readonly [string, string]> = [];
      const headers: Record<string, string> = {};
      for (const field of lines) {
        const colon = field.indexOf(":");
        const sent = field.slice(0, colon).trim();
        const name = sent.toLowerCase();
        const value = field.slice(colon + 1).trim();
        names.push(sent);
        fields.push([name, value]);
        headers[name] = value;
      }
      const request = { line, names, fields, headers };
      requests.push(request);
      socket.end(answer(request, requests.length - 1));
    };
    socket.on("data", onData);
  };
  const server = options.tls
    ? createTlsServer({ ...options.tls, ALPNProtocols: ["http/1.1"] }, serve)
    : createServer(serve);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  return {
    url: `${options.tls ? "https" : "http"}://127.0.0.1:${port}`,
    requests,
    get connections() {
      return connections;
    },
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

/**
 * A complete response that closes the connection, with `Content-Length` added. String header
 * values are written as UTF-8, so a non-ASCII one goes out as raw UTF-8 bytes; pass a `Buffer`
 * for any other bytes.
 */
export function rawResponse(
  status: string,
  headers: ReadonlyArray<readonly [string, string | Buffer]> = [],
  body: Buffer | string = "",
): Buffer {
  const payload = Buffer.from(body);
  const parts = [Buffer.from(`HTTP/1.1 ${status}\r\n`)];
  for (const [name, value] of headers) {
    parts.push(Buffer.from(`${name}: `), Buffer.from(value), Buffer.from("\r\n"));
  }
  parts.push(
    Buffer.from(`Content-Length: ${payload.length}\r\nConnection: close\r\n\r\n`),
    payload,
  );
  return Buffer.concat(parts);
}
