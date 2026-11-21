import { describe, expect, it } from "vitest";
import { Client, listPresets, PresetBundle } from "../src/index.js";
import { serverUrl, testClient } from "./support/clients.js";
import { expectInvalidConfig } from "./support/helpers.js";
import { rawResponse, startRawHttpServer } from "./support/raw-http.js";

/** `chrome_155` as a bundle object, with the given top-level fields replaced. */
function editedChrome(fields: Record<string, unknown>): PresetBundle {
  // toJSON() keeps the integers JSON.parse would round, so the edit stays exact.
  return PresetBundle.fromJSON({ ...PresetBundle.preset("chrome_155").toJSON(), ...fields });
}

describe("PresetBundle", () => {
  it("exports every built-in preset and reads it back unchanged", () => {
    for (const { name } of listPresets()) {
      const bundle = PresetBundle.preset(name);
      expect(bundle.name).toBe(name);
      const text = JSON.stringify(bundle);
      expect([name, JSON.stringify(PresetBundle.fromJSON(text))]).toEqual([name, text]);
    }
  });

  it("builds a client as the preset's name does, but without a TCP fingerprint", async () => {
    const named = new Client({ preset: "chrome_155" }).fingerprintInfo();
    const bundle = PresetBundle.preset("chrome_155");
    const bundled = new Client({ preset: bundle }).fingerprintInfo();
    expect(bundled.tcpJa4t).toBeUndefined();
    expect({ ...bundled, tcpJa4t: named.tcpJa4t }).toEqual(named);
    expect(new Client({ preset: bundle, tcpFingerprint: "chrome" }).fingerprintInfo()).toEqual(
      named,
    );
    const res = await testClient({ preset: PresetBundle.preset("firefox_156") })
      .session()
      .get(serverUrl("/get"));
    expect(res.status).toBe(200);
  });

  it("sends headers in the order an edited bundle gives", async () => {
    const raw = await startRawHttpServer(() => rawResponse("200 OK", [["content-length", "0"]]));
    try {
      for (const order of [
        ["x-a", "x-b"],
        ["x-b", "x-a"],
      ]) {
        await new Client({ preset: editedChrome({ header_order: order }) })
          .session()
          .get(`${raw.url}/`, {
            headers: [
              ["x-b", "2"],
              ["x-a", "1"],
            ],
          });
      }
      const sent = raw.requests.map((request) =>
        request.fields.map(([name]) => name).filter((name) => name.startsWith("x-")),
      );
      expect(sent).toEqual([
        ["x-a", "x-b"],
        ["x-b", "x-a"],
      ]);
    } finally {
      await raw.close();
    }
  });

  it("refuses a bundle it cannot use, naming the value at fault", () => {
    expectInvalidConfig(() => editedChrome({ surprise: 1 }));
    expect(() => editedChrome({ surprise: 1 })).toThrow(/UnknownField at \/surprise/);
    expect(() => PresetBundle.fromJSON("{")).toThrow(/InvalidJson/);
    expectInvalidConfig(() => PresetBundle.preset("chrome_999"));
  });
});
