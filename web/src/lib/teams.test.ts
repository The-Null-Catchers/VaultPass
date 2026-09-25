import assert from "node:assert/strict";
import { test } from "node:test";

import { bytes } from "./crypto";
import { createIdentity } from "./sharing";
import {
  createTeamKey,
  decryptTeamItem,
  encryptTeamItem,
  unwrapTeamKey,
  wrapTeamKey,
} from "./teams";

test("team keys are recipient and epoch bound", async () => {
  const accountKey = bytes(32);
  const identity = await createIdentity(accountKey, "owner");
  const created = await createTeamKey(identity.public_key, "team", "owner");
  const unwrapped = await unwrapTeamKey(
    created.wrappedKey,
    accountKey,
    identity.private_key,
    "team",
    "owner",
    1,
  );
  assert.deepEqual(unwrapped, created.key);
  await assert.rejects(
    unwrapTeamKey(
      created.wrappedKey,
      accountKey,
      identity.private_key,
      "team",
      "owner",
      2,
    ),
  );
  created.key.fill(0);
  unwrapped.fill(0);
  accountKey.fill(0);
});

test("team item ciphertext is bound to team, epoch, item, and revision", async () => {
  const key = bytes(32);
  const envelope = await encryptTeamItem(
    key,
    { title: "Shared" },
    "team",
    "item",
    2,
    4,
  );
  assert.deepEqual(await decryptTeamItem(key, envelope, "team", "item", 2, 4), {
    title: "Shared",
  });
  await assert.rejects(decryptTeamItem(key, envelope, "other", "item", 2, 4));
  await assert.rejects(decryptTeamItem(key, envelope, "team", "item", 1, 4));
  await assert.rejects(decryptTeamItem(key, envelope, "team", "item", 2, 5));
  key.fill(0);
});

test("rotation wraps a fresh key independently for each member", async () => {
  const accountA = bytes(32);
  const accountB = bytes(32);
  const a = await createIdentity(accountA, "a");
  const b = await createIdentity(accountB, "b");
  const rotated = bytes(32);
  const wrappedA = await wrapTeamKey(rotated, a.public_key, "team", "a", 3);
  const wrappedB = await wrapTeamKey(rotated, b.public_key, "team", "b", 3);
  assert.notEqual(wrappedA, wrappedB);
  const openedA = await unwrapTeamKey(
    wrappedA,
    accountA,
    a.private_key,
    "team",
    "a",
    3,
  );
  const openedB = await unwrapTeamKey(
    wrappedB,
    accountB,
    b.private_key,
    "team",
    "b",
    3,
  );
  assert.deepEqual(openedA, rotated);
  assert.deepEqual(openedB, rotated);
  await assert.rejects(
    unwrapTeamKey(wrappedA, accountB, b.private_key, "team", "b", 3),
  );
  for (const value of [accountA, accountB, rotated, openedA, openedB])
    value.fill(0);
});
