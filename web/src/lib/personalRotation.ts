import { ApiError, api } from "./api";
import { bytes, context, encryptJSON, seal, type Envelope } from "./crypto";

export type PersonalRotationSnapshot = {
  id: string;
  version: number;
  deleted: boolean;
};

export type PersonalRotationProgress = {
  id: string;
  expected_key_version: number;
  new_key_version: number;
  expires: number;
  required_items: PersonalRotationSnapshot[];
  uploaded_items: number;
  complete: boolean;
};

export type PersonalRotationEntry<T> = {
  id: string;
  version: number;
  deleted: boolean;
  data: T;
};

export type PersonalVaultMetadata = {
  id: string;
  wrapped_key: Envelope;
  key_version: number;
};

type Request = <T>(path: string, method?: string, body?: unknown) => Promise<T>;

type RotationInput<T> = {
  userId: string;
  vaultId: string;
  currentKeyVersion: number;
  accountKey: Uint8Array;
  entries: PersonalRotationEntry<T>[];
  request?: Request;
  makeKey?: () => Uint8Array;
  makeId?: () => string;
};

export type RotationResult = {
  vaultKey: Uint8Array;
  keyVersion: number;
};

function assertSnapshot<T>(
  required: PersonalRotationSnapshot[],
  entries: PersonalRotationEntry<T>[],
): Map<string, PersonalRotationEntry<T>> {
  const byId = new Map(entries.map((entry) => [entry.id, entry]));
  if (
    required.length !== entries.length ||
    required.some((row) => {
      const entry = byId.get(row.id);
      return !entry || entry.version !== row.version || entry.deleted !== row.deleted;
    })
  ) {
    throw new Error("Vault changed while preparing key rotation. Sync and try again.");
  }
  return byId;
}

async function bestEffortCancel(
  request: Request,
  vaultId: string,
  rotationId: string,
): Promise<void> {
  try {
    await request(`/vaults/${vaultId}/rotations/${rotationId}`, "DELETE");
  } catch (error) {
    if (!(error instanceof ApiError) || ![404, 410].includes(error.status)) {
      // Cancellation is best effort. The active vault key is unchanged unless finalize committed.
    }
  }
}

export async function rotatePersonalVault<T>({
  userId,
  vaultId,
  currentKeyVersion,
  accountKey,
  entries,
  request = api,
  makeKey = () => bytes(32),
  makeId = () => crypto.randomUUID(),
}: RotationInput<T>): Promise<RotationResult> {
  const candidate = makeKey();
  if (candidate.length !== 32) throw new Error("Personal vault keys must be 256 bits");

  const rotationId = makeId();
  let started = false;
  let finalizeAttempted = false;
  try {
    const wrappedKey = await seal(
      accountKey,
      candidate,
      context("vault", userId, vaultId),
    );
    const start = await request<PersonalRotationProgress>(
      `/vaults/${vaultId}/rotations`,
      "POST",
      {
        id: rotationId,
        expected_key_version: currentKeyVersion,
        wrapped_key: wrappedKey,
      },
    );
    started = true;
    if (start.new_key_version !== currentKeyVersion + 1) {
      throw new Error("Unexpected vault key epoch from server");
    }

    const byId = assertSnapshot(start.required_items, entries);
    for (const row of start.required_items) {
      const entry = byId.get(row.id)!;
      const payload = await encryptJSON(
        candidate,
        entry.data,
        context("item", vaultId, row.id, row.version + 1),
      );
      await request(
        `/vaults/${vaultId}/rotations/${rotationId}/items/${row.id}`,
        "PUT",
        { expected_version: row.version, payload },
      );
    }

    const progress = await request<PersonalRotationProgress>(
      `/vaults/${vaultId}/rotations/${rotationId}`,
    );
    if (
      !progress.complete ||
      progress.new_key_version !== start.new_key_version ||
      progress.uploaded_items !== progress.required_items.length
    ) {
      throw new Error("Personal vault key rotation is not ready to finalize");
    }

    finalizeAttempted = true;
    const result = await request<{ key_version: number }>(
      `/vaults/${vaultId}/rotations/${rotationId}/finalize`,
      "POST",
    );
    return { vaultKey: candidate, keyVersion: result.key_version };
  } catch (error) {
    if (finalizeAttempted) {
      try {
        const vaults = await request<PersonalVaultMetadata[]>("/vaults");
        const vault = vaults.find((row) => row.id === vaultId);
        if (vault?.key_version === currentKeyVersion + 1) {
          return { vaultKey: candidate, keyVersion: vault.key_version };
        }
      } catch {
        // A fresh login can unwrap the server's active wrapped key if finalize committed.
      }
    }
    if (started && !finalizeAttempted) {
      await bestEffortCancel(request, vaultId, rotationId);
    }
    candidate.fill(0);
    throw error;
  }
}
