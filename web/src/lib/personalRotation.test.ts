import assert from "node:assert/strict";
import { test } from "node:test";

import { bytes, context, decryptJSON, type Envelope } from "./crypto";
import {
  rotatePersonalVault,
  type PersonalRotationProgress,
  type PersonalVaultMetadata,
} from "./personalRotation";

type Call = { path: string; method: string; body?: unknown };

test("personal vault rotation encrypts every next revision under a fresh local key", async () => {
  const accountKey = bytes(32);
  const candidate = new Uint8Array(32).fill(7);
  const calls: Call[] = [];
  let staged: Envelope | undefined;
  const required = [{ id: "item-1", version: 4, deleted: false }];
  const progress: PersonalRotationProgress = {
    id: "rotation-1",
    expected_key_version: 1,
    new_key_version: 2,
    expires: 9999999999,
    required_items: required,
    uploaded_items: 0,
    complete: false,
  };
  const request = async <T>(path: string, method = "GET", body?: unknown): Promise<T> => {
    calls.push({ path, method, body });
    if (path.endsWith("/rotations") && method === "POST") return progress as T;
    if (path.includes("/items/item-1") && method === "PUT") {
      staged = (body as { payload: Envelope }).payload;
      return { ok: true } as T;
    }
    if (path.endsWith("/rotations/rotation-1") && method === "GET") {
      return { ...progress, uploaded_items: 1, complete: true } as T;
    }
    if (path.endsWith("/finalize") && method === "POST") {
      return { ok: true, key_version: 2 } as T;
    }
    throw new Error(`Unexpected request: ${method} ${path}`);
  };

  const result = await rotatePersonalVault({
    userId: "user-1",
    vaultId: "vault-1",
    currentKeyVersion: 1,
    accountKey,
    entries: [{ id: "item-1", version: 4, deleted: false, data: { title: "Secret" } }],
    request,
    makeKey: () => candidate,
    makeId: () => "rotation-1",
  });

  assert.equal(result.keyVersion, 2);
  assert.equal(result.vaultKey, candidate);
  assert.ok(staged);
  assert.deepEqual(
    await decryptJSON<{ title: string }>(
      candidate,
      staged,
      context("item", "vault-1", "item-1", 5),
    ),
    { title: "Secret" },
  );
  const start = calls[0].body as {
    expected_key_version: number;
    wrapped_key: Envelope;
  };
  assert.equal(start.expected_key_version, 1);
  assert.equal(start.wrapped_key.v, 1);
  assert.equal(calls.some((call) => call.method === "DELETE"), false);

  candidate.fill(0);
  accountKey.fill(0);
});

test("snapshot mismatch cancels staging and wipes the candidate key", async () => {
  const accountKey = bytes(32);
  const candidate = new Uint8Array(32).fill(9);
  const calls: Call[] = [];
  const request = async <T>(path: string, method = "GET", body?: unknown): Promise<T> => {
    calls.push({ path, method, body });
    if (path.endsWith("/rotations") && method === "POST") {
      return {
        id: "rotation-2",
        expected_key_version: 1,
        new_key_version: 2,
        expires: 9999999999,
        required_items: [{ id: "item-1", version: 8, deleted: false }],
        uploaded_items: 0,
        complete: false,
      } as T;
    }
    if (path.endsWith("/rotations/rotation-2") && method === "DELETE") {
      return { ok: true } as T;
    }
    throw new Error(`Unexpected request: ${method} ${path}`);
  };

  await assert.rejects(
    rotatePersonalVault({
      userId: "user-1",
      vaultId: "vault-1",
      currentKeyVersion: 1,
      accountKey,
      entries: [{ id: "item-1", version: 7, deleted: false, data: { title: "Old" } }],
      request,
      makeKey: () => candidate,
      makeId: () => "rotation-2",
    }),
    /Vault changed while preparing key rotation/,
  );
  assert.deepEqual(candidate, new Uint8Array(32));
  assert.equal(calls.at(-1)?.method, "DELETE");
  accountKey.fill(0);
});

test("lost finalize response adopts the candidate when the server epoch advanced", async () => {
  const accountKey = bytes(32);
  const candidate = new Uint8Array(32).fill(5);
  const progress: PersonalRotationProgress = {
    id: "rotation-3",
    expected_key_version: 3,
    new_key_version: 4,
    expires: 9999999999,
    required_items: [],
    uploaded_items: 0,
    complete: true,
  };
  const request = async <T>(path: string, method = "GET"): Promise<T> => {
    if (path.endsWith("/rotations") && method === "POST") return progress as T;
    if (path.endsWith("/rotations/rotation-3") && method === "GET") return progress as T;
    if (path.endsWith("/finalize") && method === "POST") throw new Error("connection lost");
    if (path === "/vaults") {
      return [
        {
          id: "vault-1",
          wrapped_key: { v: 1, nonce: "unused", ciphertext: "unused" },
          key_version: 4,
        },
      ] as PersonalVaultMetadata[] as T;
    }
    throw new Error(`Unexpected request: ${method} ${path}`);
  };

  const result = await rotatePersonalVault({
    userId: "user-1",
    vaultId: "vault-1",
    currentKeyVersion: 3,
    accountKey,
    entries: [],
    request,
    makeKey: () => candidate,
    makeId: () => "rotation-3",
  });
  assert.equal(result.keyVersion, 4);
  assert.equal(result.vaultKey, candidate);
  assert.equal(candidate.every((value) => value === 5), true);

  candidate.fill(0);
  accountKey.fill(0);
});
