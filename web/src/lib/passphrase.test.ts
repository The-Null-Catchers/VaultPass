import test from "node:test";
import assert from "node:assert/strict";

import { generatePassphrase } from "./generator";

test("builds a deterministic eight-word passphrase from uniform byte choices", () => {
  const sequence = [0, 17, 34, 51, 68, 85, 102, 119];
  let index = 0;
  const result = generatePassphrase({}, () => sequence[index++]);

  assert.equal(result.passphrase.split("-").length, 8);
  assert.equal(result.entropy, 64);
  assert.equal(
    result.passphrase,
    "amberanchor-briskbird-cedarcloud-dawndrift-emberfield-frostgrove-goldhill-harborisland",
  );
});

test("supports capitalization, separators, and an optional numeric token", () => {
  const result = generatePassphrase(
    {
      words: 6,
      separator: ".",
      capitalize: true,
      includeNumber: true,
    },
    () => 0,
  );

  assert.equal(
    result.passphrase,
    "Amberanchor.Amberanchor.Amberanchor.Amberanchor.Amberanchor.Amberanchor.00",
  );
  assert.equal(result.entropy, 54);
});

test("rejects unsafe word counts and separators", () => {
  assert.throws(() => generatePassphrase({ words: 5 }), /Choose 6–12 words/);
  assert.throws(() => generatePassphrase({ separator: "/" as "-" }), /Unsupported separator/);
});
