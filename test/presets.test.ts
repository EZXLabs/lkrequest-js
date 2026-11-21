import { describe, expect, it } from "vitest";
import { Client, ExtensionType, H2Profile, QuicProfile, TlsProfile } from "../src/index.js";
import { expectInvalidConfig } from "./support/helpers.js";

// Checks on upstream's preset data, ported from lkrequest-py's TestNewPresets: a capture that
// changes a fingerprint-visible field must show up here as a reviewed change.

/** A TLS preset's JSON. */
const tls = (name: string): Record<string, unknown> => TlsProfile.preset(name).toJSON();

/** A TLS preset's JSON without its name. */
function withoutName(name: string): Record<string, unknown> {
  const { name: _name, ...rest } = tls(name);
  return rest;
}

/** The source of a TLS preset's trust anchor IDs extension, if it has one. */
function trustAnchors(name: string): { ids: string[]; shuffle: boolean } | undefined {
  const extensions = tls(name).extensions as Array<{
    extension_type: number;
    source: { ids: string[]; shuffle: boolean };
  }>;
  return extensions.find(({ extension_type }) => extension_type === ExtensionType.TRUST_ANCHOR_IDS)
    ?.source;
}

describe("browser presets", () => {
  it("defaults to Chrome 155 TLS and HTTP/2 without a preset", () => {
    const fallback = new Client().fingerprintInfo();
    expect(fallback.tlsProfile).toBe("Chrome 155");
    expect(fallback).toEqual(
      new Client({ tlsProfile: "chrome_155", h2Profile: "chrome_155" }).fingerprintInfo(),
    );
    expect(new Client({ tlsProfile: "chrome_144" }).fingerprintInfo().tlsProfile).toBe(
      "Chrome 144",
    );
  });

  it("builds Chrome 155's TLS and HTTP/2 as Chrome 154's, its trust anchor IDs sorted", () => {
    // Chrome 155 sorts the IDs it sends; Chrome 154's are shuffled on every handshake.
    const unshuffled = (name: string) => {
      const profile = withoutName(name);
      for (const extension of profile.extensions as Array<{
        extension_type: number;
        source: { ids: string[]; shuffle: boolean };
      }>) {
        if (extension.extension_type === ExtensionType.TRUST_ANCHOR_IDS) {
          const { source } = extension;
          extension.source = { ...source, ids: [...source.ids].sort(), shuffle: false };
        }
      }
      return profile;
    };
    for (const variant of ["", "_quic"]) {
      expect(trustAnchors(`chrome_154${variant}`)?.shuffle).toBe(true);
      expect(withoutName(`chrome_155${variant}`)).toEqual(unshuffled(`chrome_154${variant}`));
    }
    expect(H2Profile.preset("chrome_155").toJSON()).toEqual(
      H2Profile.preset("chrome_154").toJSON(),
    );
  });

  it("gives Chrome 155's QUIC profile 16 behaviors Chrome 154's has not", () => {
    const quic = (name: string) =>
      QuicProfile.preset(name).toJSON() as Record<string, Record<string, unknown>>;
    const older = quic("chrome_154");
    const on = (keys: string[]) => Object.fromEntries(keys.map((key) => [key, true]));
    expect(quic("chrome_155")).toEqual({
      ...older,
      h3: {
        ...older.h3,
        ...on([
          "accept_truncated_response_payloads",
          "cancel_response_before_upload",
          "defer_qpack_stream_prefixes",
          "request_priority_updates",
          "wait_for_incomplete_response_frame_headers",
          "wait_for_response_after_upload_stop",
        ]),
      },
      packetization: {
        ...older.packetization,
        ...on([
          "ack_obligation_only",
          "chrome_loss_timing",
          "chrome_pto_timing",
          "chrome_rtt_quantization",
          "discard_blocked_close",
          "pto_single_probe_with_gap",
          "queue_pto_while_blocked",
          "reset_finished_on_stop",
          "reuse_rejected_0rtt_streams",
          "stop_before_matching_reset",
        ]),
      },
    });
  });

  it.each([
    ["156", "155"],
    ["157", "156"],
    ["158", "157"],
  ])("builds Chrome %s as Chrome %s under a new name", (newer, older) => {
    expect([tls(`chrome_${newer}`).name, tls(`chrome_${newer}_quic`).name]).toEqual([
      `Chrome ${newer}`,
      `Chrome ${newer} QUIC`,
    ]);
    expect(withoutName(`chrome_${newer}`)).toEqual(withoutName(`chrome_${older}`));
    expect(withoutName(`chrome_${newer}_quic`)).toEqual(withoutName(`chrome_${older}_quic`));
    expect(H2Profile.preset(`chrome_${newer}`).toJSON()).toEqual(
      H2Profile.preset(`chrome_${older}`).toJSON(),
    );
    expect(QuicProfile.preset(`chrome_${newer}`).toJSON()).toEqual(
      QuicProfile.preset(`chrome_${older}`).toJSON(),
    );
  });

  it("chains Chrome's streams by priority, and starts Firefox 156 on stream 3", () => {
    for (const name of H2Profile.presetNames()) {
      const profile = H2Profile.preset(name);
      const policy = name.startsWith("chrome") ? "priority_chain" : "flat";
      expect([name, profile.priorityConfig.streamDepPolicy]).toEqual([name, policy]);
      expect([name, profile.initialStreamId]).toEqual([name, name === "firefox_156" ? 3 : 1]);
    }
  });

  it("builds Firefox 156's HTTP/2 as Firefox 147's but for the first stream and its weight", () => {
    const parts = (name: string) => {
      const {
        initial_stream_id: id,
        headers_priority: priority,
        ...rest
      } = H2Profile.preset(name).toJSON();
      return { id, priority, rest };
    };
    const [older, newer] = [parts("firefox_147"), parts("firefox_156")];
    expect(newer.rest).toEqual(older.rest);
    expect([older.id, newer.id]).toEqual([1, 3]);
    // Firefox 156 carries the wire weight its captures show, 41 (weight 42).
    expect([older.priority, newer.priority]).toEqual([
      { stream_dependency: 0, weight: 42, exclusive: false },
      { stream_dependency: 0, weight: 41, exclusive: false },
    ]);
  });

  it("greases signature algorithms from Chrome 152 on", () => {
    const greased = [
      "chrome_131",
      "chrome_144",
      "chrome_150",
      "chrome_151",
      "chrome_152",
      "chrome_153",
      "chrome_154",
      "chrome_155",
      "chrome_156",
      "chrome_157",
      "chrome_158",
    ].filter((name) => (tls(name).grease as Record<string, boolean>).signature_algorithms);
    expect(greased).toEqual([
      "chrome_152",
      "chrome_153",
      "chrome_154",
      "chrome_155",
      "chrome_156",
      "chrome_157",
      "chrome_158",
    ]);
  });

  it("sends trust anchor IDs from Chrome 152 on, shuffled until 154 and sorted since 155", () => {
    expect(trustAnchors("chrome_151")).toBeUndefined();
    expect(trustAnchors("chrome_152")?.ids).toHaveLength(32);
    for (const version of [152, 153, 154]) {
      expect([version, trustAnchors(`chrome_${version}`)?.shuffle]).toEqual([version, true]);
    }
    for (const version of [153, 154, 155, 156, 157, 158]) {
      expect([version, trustAnchors(`chrome_${version}`)?.ids.length]).toEqual([version, 28]);
    }
    for (const version of [155, 156, 157, 158]) {
      const anchors = trustAnchors(`chrome_${version}`);
      expect([version, anchors?.shuffle]).toEqual([version, false]);
      expect(anchors?.ids).toEqual([...(anchors?.ids ?? [])].sort());
    }
  });

  it("ships Firefox 156 without a QUIC fingerprint", () => {
    expect(TlsProfile.presetNames()).not.toContain("firefox_156_quic");
    expect(QuicProfile.presetNames()).not.toContain("firefox_156");
    expectInvalidConfig(() => new Client({ quicProfile: "firefox_156" }));
  });
});

describe("H2Profile.fromH2Frames", () => {
  const preface = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "latin1");

  /** A connection preface plus one HEADERS frame (END_HEADERS) carrying `hpack`. */
  function frames(hpack: number[], streamId = 1): Uint8Array {
    const header = Buffer.alloc(9);
    header.writeUIntBE(hpack.length, 0, 3);
    header.writeUInt8(0x01, 3);
    header.writeUInt8(0x04, 4);
    header.writeUInt32BE(streamId, 5);
    return Buffer.concat([preface, header, Buffer.from(hpack)]);
  }

  it("takes the stream id of the first request, which must be odd", () => {
    const hpack = [0x82, 0x87, 0x84];
    expect(H2Profile.fromH2Frames(frames(hpack)).initialStreamId).toBe(1);
    expect(H2Profile.fromH2Frames(frames(hpack, 3)).initialStreamId).toBe(3);
    expectInvalidConfig(() => H2Profile.fromH2Frames(frames(hpack, 2)));
  });

  it.each([
    // :method, :authority, :scheme, :path: the control case.
    [
      [0x82, 0x41, 0x0b, ...Buffer.from("example.com"), 0x87, 0x84],
      ["method", "authority", "scheme", "path"],
    ],
    // Integers and string lengths far past the frame, which overflowed before 3dd3c9e.
    [[0x3f, 0xe1, 0xff, 0xff, 0xff, 0x0f], []],
    [[0x40, 0x7f, 0x80, 0xff, 0xff, 0xff, 0x0f], []],
    [[0x40, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x7f], []],
    [[0x40, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], []],
    // Continuation bytes past 64 bits after one valid field: keeps what it read.
    [[0x82, 0x40, 0x7f, ...new Array<number>(12).fill(0xff), 0x01], ["method"]],
  ])("survives HPACK lengths past the frame (%#)", (hpack, expected) => {
    const profile = H2Profile.fromH2Frames(frames(hpack));
    expect(profile.toJSON().pseudo_header_order).toEqual(expected);
  });
});
