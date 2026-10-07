import { bytes } from "./crypto";

export function randomIndex(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > 256) throw new Error("Invalid alphabet size");
  const limit = 256 - (256 % n);
  let x: number;
  do {
    x = bytes(1)[0];
  } while (x >= limit);
  return x % n;
}

export function generate(length = 24, symbols = true, ambiguous = false) {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error("Choose 12–128 characters");
  const groups = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    ...(symbols ? ["!@#$%^&*()-_=+[]{}:?,."] : []),
  ].map((group) => (ambiguous ? group : group.replace(/[Il1O0o]/g, "")));
  const alphabet = groups.join("");
  let password: string;
  do {
    password = Array.from({ length }, () => alphabet[randomIndex(alphabet.length)]).join("");
  } while (!groups.every((group) => [...password].some((character) => group.includes(character))));
  return {
    password,
    entropy: Math.floor(length * Math.log2(alphabet.length)),
    estimate: "Upper-bound entropy estimate before category constraints; not a security guarantee.",
  };
}

const passphraseLeft = [
  "amber",
  "brisk",
  "cedar",
  "dawn",
  "ember",
  "frost",
  "gold",
  "harbor",
  "indigo",
  "jade",
  "kind",
  "lunar",
  "mist",
  "north",
  "opal",
  "quiet",
] as const;

const passphraseRight = [
  "anchor",
  "bird",
  "cloud",
  "drift",
  "field",
  "grove",
  "hill",
  "island",
  "journey",
  "kettle",
  "leaf",
  "meadow",
  "night",
  "orbit",
  "pine",
  "river",
] as const;

export type PassphraseOptions = {
  words?: number;
  separator?: "-" | "." | "_" | " ";
  capitalize?: boolean;
  includeNumber?: boolean;
};

function passphraseWord(index: number): string {
  return `${passphraseLeft[index >> 4]}${passphraseRight[index & 15]}`;
}

export function generatePassphrase({
  words = 8,
  separator = "-",
  capitalize = false,
  includeNumber = false,
}: PassphraseOptions = {}) {
  if (!Number.isInteger(words) || words < 6 || words > 12) throw new Error("Choose 6–12 words");
  if (!["-", ".", "_", " "].includes(separator)) throw new Error("Unsupported separator");

  const selected = Array.from({ length: words }, () => passphraseWord(randomIndex(256))).map((word) =>
    capitalize ? word[0].toUpperCase() + word.slice(1) : word,
  );
  if (includeNumber) selected.push(String(randomIndex(100)).padStart(2, "0"));

  const entropy = words * 8 + (includeNumber ? Math.log2(100) : 0);
  return {
    passphrase: selected.join(separator),
    entropy: Math.floor(entropy),
    estimate: "Entropy is based on independent uniform choices from VaultPass's 256-token passphrase dictionary.",
  };
}

export function health(items: { password?: string; username?: string; url?: string }[]) {
  const passwords = items.filter((item) => item.password);
  const counts = new Map<string, number>();
  for (const item of passwords) counts.set(item.password!, (counts.get(item.password!) || 0) + 1);
  return {
    total: passwords.length,
    weak: passwords.filter((item) => item.password!.length < 14).length,
    reused: passwords.filter((item) => counts.get(item.password!)! > 1).length,
  };
}

export async function breachCount(password: string) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password)));
  const hash = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  const response = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { "Add-Padding": "true" },
    referrerPolicy: "no-referrer",
    credentials: "omit",
  });
  if (!response.ok) throw new Error("Breach service unavailable");
  return Number(
    (await response.text())
      .split(/\r?\n/)
      .find((row) => row.startsWith(`${hash.slice(5)}:`))
      ?.split(":")[1] || 0,
  );
}
