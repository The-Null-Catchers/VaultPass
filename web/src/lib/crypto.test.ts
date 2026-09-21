import { test } from "node:test";
import assert from "node:assert/strict";
import { bytes, seal, open, createAccount, unlock, rewrap, context, hex, derive, createRecovery, unlockRecovery } from "./crypto";
import { generate } from "./generator";
import { totp } from "./totp";
test("authenticated encryption binds key, context and ciphertext", async () => {
  const k = bytes(32),
    clear = new TextEncoder().encode("fake test secret");
  const e = await seal(k, clear, "item:1");
  assert.deepEqual(await open(k, e, "item:1"), clear);
  await assert.rejects(open(bytes(32), e, "item:1"));
  await assert.rejects(open(k, e, "item:2"));
  const bad = {
    ...e,
    ciphertext: (e.ciphertext[0] === "A" ? "B" : "A") + e.ciphertext.slice(1),
  };
  await assert.rejects(open(k, bad, "item:1"));
  assert.notEqual((await seal(k, clear, "item:1")).nonce, e.nonce);
});
test("password change rewraps account key without changing vault key or item", async () => {
  const account = await createAccount("fake long master password");
  assert.deepEqual(await unlock("fake long master password", account.id, account.bundle), account.accountKey);
  await assert.rejects(unlock("incorrect master password", account.id, account.bundle));
  const update = await rewrap("another fake long password", account.id, account.accountKey);
  const key = await unlock("another fake long password", account.id, update.bundle);
  assert.deepEqual(await open(key, account.wrappedVaultKey, context("vault", account.id, account.vaultId)), account.vaultKey);
  const d = await derive("fake long master password", account.bundle.salt);
  assert.notEqual(d.auth, hex(d.wrap));
});
test("RFC 6238 SHA1 vectors", async () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  for (const [time, result] of [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ] as const)
    assert.equal(await totp(secret, time * 1000, 8), result);
});
test("generator enforces length, categories and ambiguous exclusion", () => {
  for (let i = 0; i < 100; i++) {
    const { password: p } = generate(24);
    assert.equal(p.length, 24);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[0-9]/);
    assert.match(p, /[^a-zA-Z0-9]/);
    assert.doesNotMatch(p, /[Il1O0o]/);
  }
  assert.throws(() => generate(1));
});

test("cross-client Argon2id/HKDF public interoperability vector", async () => {
  const d = await derive("PUBLIC INTEROP TEST PASSWORD", "000102030405060708090a0b0c0d0e0f");
  assert.equal(hex(d.wrap), "6bbb2ee916608f4432679046375df675c3634f326860d2b4a61eef924596cc2c");
  assert.equal(d.auth, "0b06dd11a65c05b07997387d3259214daa8f3c5d4404721605dd9ba402ab72d8");
});
test("recovery key wraps the account key and rejects wrong material", async () => {
  const id = crypto.randomUUID(),
    accountKey = bytes(32),
    recovery = await createRecovery(accountKey, id),
    opened = await unlockRecovery(recovery.recoveryKey, id, recovery.accountKey);
  assert.deepEqual(opened.accountKey, accountKey);
  assert.equal(opened.recoveryAuth, recovery.recoveryAuth);
  await assert.rejects(unlockRecovery(`VP1-${"00".repeat(32)}`, id, recovery.accountKey));
  await assert.rejects(unlockRecovery(recovery.recoveryKey, crypto.randomUUID(), recovery.accountKey));
});
