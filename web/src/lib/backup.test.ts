import { test } from "node:test";
import assert from "node:assert/strict";
import { createAccount, encryptJSON, context } from "./crypto";
import { restoreBackup, validateItem } from "./backup";

test("encrypted backup restores synthetic entries, skips deleted entries, and rejects a wrong master", async () => {
  const master = "PUBLIC FAKE BACKUP PASSWORD";
  const a = await createAccount(master);
  const item = validateItem({ title: "Fake", type: "login", password: "NOT-A-REAL-PASSWORD" });
  const second = validateItem({ title: "Recovery test", type: "note", notes: "Synthetic note" });
  const id = crypto.randomUUID();
  const secondId = crypto.randomUUID();
  const deletedId = crypto.randomUUID();
  const makeEntry = async (itemId: string, payload: unknown) => ({
    id: itemId,
    version: 1,
    payload: await encryptJSON(a.vaultKey, payload, context("item", a.vaultId, itemId, 1)),
  });
  const backup = {
    format: "vaultpass-backup-v1",
    user_id: a.id,
    bundle: a.bundle,
    vaults: [{ id: a.vaultId, wrapped_key: a.wrappedVaultKey }],
    items: [
      await makeEntry(id, item),
      await makeEntry(secondId, second),
      { ...(await makeEntry(deletedId, item)), deleted: true },
    ],
  };

  assert.deepEqual(await restoreBackup(backup, master), [item, second]);
  await assert.rejects(restoreBackup(backup, "wrong password"));
  assert.throws(() => validateItem({ title: "bad", type: "login", password: { unexpected: true } }));

  // Invalid metadata must be rejected before attempting password derivation.
  await assert.rejects(restoreBackup({ ...backup, items: [...backup.items, backup.items[0]] }, master), /Invalid backup item/);
  await assert.rejects(restoreBackup({ ...backup, items: [{ ...backup.items[0], version: 0 }] }, master), /Invalid backup item/);
  await assert.rejects(restoreBackup({ ...backup, items: [{ ...backup.items[0], deleted: "yes" }] }, master), /Invalid backup item/);
  await assert.rejects(restoreBackup({ ...backup, vaults: [{ ...backup.vaults[0], id: "" }] }, master), /Invalid backup metadata/);
});
