import type { NativePresetBundle } from "../native/index.cjs";
import { parseExactJson } from "./internal/json.js";
import { native } from "./internal/native.js";
import { callNative } from "./internal/native-error.js";

/**
 * A complete browser preset as a profile bundle, lkrequest's v2 preset JSON: its TLS, QUIC TLS,
 * HTTP/2 and QUIC profiles, header and cookie order, protocol policy and session-cache
 * partitioning. Export a built-in preset with {@link PresetBundle.preset}, edit it or write one
 * of your own, and give it to a client as `preset`, as you would a preset name. A bundle carries
 * no TCP fingerprint, so give `tcpFingerprint` alongside if you want one.
 *
 * @example
 * ```ts
 * const json = JSON.stringify(PresetBundle.preset("chrome_155"), null, 2);
 * // ...edit it, store it...
 * const client = new Client({ preset: PresetBundle.fromJSON(json), tcpFingerprint: "chrome" });
 * ```
 */
export class PresetBundle {
  readonly #native: NativePresetBundle;

  /** Bundles come from the static factories. */
  private constructor(nativeBundle: NativePresetBundle) {
    this.#native = nativeBundle;
  }

  /** A built-in preset, any name `listPresets()` gives, as a bundle. */
  static preset(name: string): PresetBundle {
    return new PresetBundle(callNative(() => native.NativePresetBundle.preset(name)));
  }

  /**
   * A bundle from its JSON, as text or a parsed object, of at most 1 MiB. A bundle that cannot
   * be used throws `TypeError` (`ERR_LK_INVALID_CONFIG`) naming the reason and the JSON pointer
   * of the value at fault. Prefer the text as read: `JSON.parse` rounds the integers beyond
   * `Number.MAX_SAFE_INTEGER` that some QUIC parameters hold.
   */
  static fromJSON(json: string | object): PresetBundle {
    const text = typeof json === "string" ? json : JSON.stringify(json);
    return new PresetBundle(callNative(() => native.NativePresetBundle.fromJson(text)));
  }

  /** @internal The native bundle. */
  static toNative(bundle: PresetBundle): NativePresetBundle {
    return bundle.#native;
  }

  /** Name of the bundle, such as the preset it was exported from. */
  get name(): string {
    return this.#native.name;
  }

  /**
   * The bundle as a plain object (`JSON.stringify` uses it). Integers beyond
   * `Number.MAX_SAFE_INTEGER` are `JSON.rawJSON()` values, so they come back exact from
   * `fromJSON()`.
   */
  toJSON(): Record<string, unknown> {
    return parseExactJson(callNative(() => this.#native.toJson()));
  }
}
