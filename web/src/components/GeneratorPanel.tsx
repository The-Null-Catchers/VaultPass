"use client";

import { useState } from "react";
import { WandSparkles } from "lucide-react";

import { generate, generatePassphrase } from "../lib/generator";

type Props = {
  copy: (value: string) => Promise<void>;
};

export function GeneratorPanel({ copy }: Props) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(24);
  const [symbols, setSymbols] = useState(true);
  const [words, setWords] = useState(8);
  const [separator, setSeparator] = useState<"-" | "." | "_" | " ">("-");
  const [capitalize, setCapitalize] = useState(false);
  const [includeNumber, setIncludeNumber] = useState(false);
  const [generated, setGenerated] = useState(() => generate(24, true).password);
  const [entropy, setEntropy] = useState<number | null>(null);

  const make = () => {
    if (mode === "password") {
      const result = generate(length, symbols);
      setGenerated(result.password);
      setEntropy(result.entropy);
      return;
    }
    const result = generatePassphrase({ words, separator, capitalize, includeNumber });
    setGenerated(result.passphrase);
    setEntropy(result.entropy);
  };

  return (
    <section className="panel tool-panel" aria-labelledby="generator-heading">
      <div className="icon-box">
        <WandSparkles />
      </div>
      <h2 id="generator-heading">Generate locally</h2>
      <p>Passwords and passphrases are generated on this device with cryptographically secure randomness.</p>

      <div className="actions" role="group" aria-label="Generator mode">
        <button type="button" className={mode === "password" ? "primary" : ""} onClick={() => setMode("password")}>
          Password
        </button>
        <button type="button" className={mode === "passphrase" ? "primary" : ""} onClick={() => setMode("passphrase")}>
          Passphrase
        </button>
      </div>

      <output className="generated" aria-live="polite">{generated}</output>

      {mode === "password" ? (
        <>
          <label>
            Length · {length}
            <input type="range" min="12" max="128" value={length} onChange={(event) => setLength(Number(event.target.value))} />
          </label>
          <label className="check">
            <input type="checkbox" checked={symbols} onChange={(event) => setSymbols(event.target.checked)} />
            Include symbols
          </label>
        </>
      ) : (
        <>
          <label>
            Words · {words}
            <input type="range" min="6" max="12" value={words} onChange={(event) => setWords(Number(event.target.value))} />
          </label>
          <label>
            Separator
            <select value={separator} onChange={(event) => setSeparator(event.target.value as "-" | "." | "_" | " ")}>
              <option value="-">Hyphen</option>
              <option value=".">Dot</option>
              <option value="_">Underscore</option>
              <option value=" ">Space</option>
            </select>
          </label>
          <label className="check">
            <input type="checkbox" checked={capitalize} onChange={(event) => setCapitalize(event.target.checked)} />
            Capitalize each token
          </label>
          <label className="check">
            <input type="checkbox" checked={includeNumber} onChange={(event) => setIncludeNumber(event.target.checked)} />
            Add a two-digit token
          </label>
        </>
      )}

      <div className="actions">
        <button type="button" className="primary" onClick={make}>
          Generate {mode}
        </button>
        <button type="button" onClick={() => void copy(generated)}>
          Copy
        </button>
      </div>
      <small>
        {entropy === null ? "Nothing is sent to VaultPass servers." : `Estimated discrete-choice entropy: ${entropy} bits. This is not a security guarantee.`}
      </small>
    </section>
  );
}
