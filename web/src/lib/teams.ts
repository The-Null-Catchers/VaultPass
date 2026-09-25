import {
  b64,
  bytes,
  context,
  decryptJSON,
  encryptJSON,
  Envelope,
  open,
  unb64,
} from "./crypto";

const buffer = (value: Uint8Array) => new Uint8Array(value).buffer;

function teamKeyLabel(teamId: string, userId: string, keyVersion: number) {
  return new TextEncoder().encode(
    context("team-key", teamId, userId, keyVersion),
  );
}

export async function wrapTeamKey(
  teamKey: Uint8Array,
  publicKey: string,
  teamId: string,
  userId: string,
  keyVersion: number,
) {
  if (teamKey.length !== 32 || keyVersion < 1)
    throw new Error("Invalid team key context");
  const rsa = await crypto.subtle.importKey(
    "spki",
    buffer(unb64(publicKey)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  return b64(
    new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "RSA-OAEP", label: teamKeyLabel(teamId, userId, keyVersion) },
        rsa,
        buffer(teamKey),
      ),
    ),
  );
}

export async function unwrapTeamKey(
  wrappedKey: string,
  accountKey: Uint8Array,
  privateEnvelope: Envelope,
  teamId: string,
  userId: string,
  keyVersion: number,
) {
  const privateBytes = await open(
    accountKey,
    privateEnvelope,
    context("sharing-private", userId),
  );
  try {
    const rsa = await crypto.subtle.importKey(
      "pkcs8",
      buffer(privateBytes),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
    const result = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "RSA-OAEP", label: teamKeyLabel(teamId, userId, keyVersion) },
        rsa,
        buffer(unb64(wrappedKey)),
      ),
    );
    if (result.length !== 32) {
      result.fill(0);
      throw new Error("Invalid team key");
    }
    return result;
  } finally {
    privateBytes.fill(0);
  }
}

export async function createTeamKey(
  publicKey: string,
  teamId: string,
  ownerId: string,
) {
  const key = bytes(32);
  return {
    key,
    wrappedKey: await wrapTeamKey(key, publicKey, teamId, ownerId, 1),
  };
}

export async function encryptTeamItem(
  key: Uint8Array,
  value: unknown,
  teamId: string,
  itemId: string,
  keyVersion: number,
  itemVersion: number,
) {
  return encryptJSON(
    key,
    value,
    context("team-item", teamId, itemId, keyVersion, itemVersion),
  );
}

export async function decryptTeamItem<T>(
  key: Uint8Array,
  envelope: Envelope,
  teamId: string,
  itemId: string,
  keyVersion: number,
  itemVersion: number,
) {
  return decryptJSON<T>(
    key,
    envelope,
    context("team-item", teamId, itemId, keyVersion, itemVersion),
  );
}
