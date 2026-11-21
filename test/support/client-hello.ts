import { createServer, type Socket } from "node:net";

/** The parts of a ClientHello the tests look at. */
export interface ClientHello {
  /** Extension types, in wire order. */
  readonly extensions: readonly number[];
  /** IDs of the trust anchor IDs extension (0xca34) in hex, in wire order, if it is there. */
  readonly trustAnchorIds?: readonly string[];
}

/** A TCP server that reads the ClientHello of each connection, then closes it. */
export interface ClientHelloServer {
  /** `https://127.0.0.1:<port>/`. */
  readonly url: string;
  /** The ClientHellos received so far, oldest first. */
  readonly hellos: readonly ClientHello[];
  /** Stops listening and drops open connections. */
  close(): Promise<void>;
}

const TRUST_ANCHOR_IDS = 0xca34;

/** Starts a {@link ClientHelloServer} on a loopback port. */
export async function startClientHelloServer(): Promise<ClientHelloServer> {
  const hellos: ClientHello[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    let received = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      const message = handshakeMessage(received);
      if (message === undefined) return;
      hellos.push(parseClientHello(message));
      socket.destroy();
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no TCP address");
  return {
    url: `https://127.0.0.1:${address.port}/`,
    hellos,
    close() {
      for (const socket of sockets) socket.destroy();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

/** The first handshake message once its records have all arrived, without record headers. */
function handshakeMessage(data: Buffer): Buffer | undefined {
  const fragments: Buffer[] = [];
  for (let offset = 0; offset + 5 <= data.length; ) {
    const end = offset + 5 + data.readUInt16BE(offset + 3);
    if (end > data.length) break;
    fragments.push(data.subarray(offset + 5, end));
    offset = end;
  }
  const message = Buffer.concat(fragments);
  if (message.length < 4) return undefined;
  const length = 4 + message.readUIntBE(1, 3);
  return message.length >= length ? message.subarray(0, length) : undefined;
}

/** Reads the extension list of a ClientHello handshake message. */
function parseClientHello(message: Buffer): ClientHello {
  // Type and length, version and random.
  let offset = 4 + 2 + 32;
  offset += 1 + message.readUInt8(offset); // session ID
  offset += 2 + message.readUInt16BE(offset); // cipher suites
  offset += 1 + message.readUInt8(offset); // compression methods
  const end = offset + 2 + message.readUInt16BE(offset);
  const extensions: number[] = [];
  let trustAnchorIds: string[] | undefined;
  for (offset += 2; offset < end; ) {
    const type = message.readUInt16BE(offset);
    const length = message.readUInt16BE(offset + 2);
    const data = message.subarray(offset + 4, offset + 4 + length);
    extensions.push(type);
    if (type === TRUST_ANCHOR_IDS) trustAnchorIds = parseIdList(data);
    offset += 4 + length;
  }
  return { extensions, ...(trustAnchorIds !== undefined && { trustAnchorIds }) };
}

/** Reads a list of one-byte-length IDs behind a two-byte list length. */
function parseIdList(data: Buffer): string[] {
  const ids: string[] = [];
  for (let offset = 2; offset < data.length; ) {
    const length = data.readUInt8(offset);
    ids.push(data.subarray(offset + 1, offset + 1 + length).toString("hex"));
    offset += 1 + length;
  }
  return ids;
}
