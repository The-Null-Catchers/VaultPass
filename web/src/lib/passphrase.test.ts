import { describe, expect, it, vi } from "vitest";

import * as cryptoModule from "./crypto";
import { generatePassphrase } from "./generator";

describe("generatePassphrase", () => {
  it("builds a deterministic eight-word passphrase from uniform byte choices", () => {
    const sequence = [0, 17, 34, 51, 68, 85, 102, 119];
    let index = 0;
    vi.spyOn(cryptoModule, "bytes").mockImplementation(() => new Uint8Array([sequence[index++]]));

    const result = generatePassphrase();

    expect(result.passphrase.split("-")).toHaveLength(8);
    expect(result.entropy).toBe(64);
    expect(result.passphrase).toBe(
      "amberanchor-briskbird-cedarcloud-dawndrift-emberfield-frostgrove-goldhill-harborisland",
    );
  });

  it("supports capitalization, separators, and an optional numeric token", () => {
    vi.spyOn(cryptoModule, "bytes").mockImplementation(() => new Uint8Array([0]));

    const result = generatePassphrase({
      words: 6,
      separator: ".",
      capitalize: true,
      includeNumber: true,
    });

    expect(result.passphrase).toBe(
      "Amberanchor.Amberanchor.Amberanchor.Amberanchor.Amberanchor.Amberanchor.00",
    );
    expect(result.entropy).toBe(54);
  });

  it("rejects unsafe word counts and separators", () => {
    expect(() => generatePassphrase({ words: 5 })).toThrow("Choose 6–12 words");
    expect(() => generatePassphrase({ separator: "/" as "-" })).toThrow("Unsupported separator");
  });
});
