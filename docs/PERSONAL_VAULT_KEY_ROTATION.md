# Personal vault key rotation

VaultPass personal-vault encryption is zero-knowledge: the server never receives the clear vault key or decrypted item contents. Automatic rotation therefore has to be client-driven while the server provides concurrency control and an atomic ciphertext cutover.

## Foundation in this change

Personal vaults now carry a monotonically increasing `key_version` (starting at `1`), matching the key-epoch concept already used by team vaults. Existing rows are migrated to epoch `1` without changing wrapped keys or ciphertext.

This foundation is intentionally non-breaking: current item read/write APIs keep their existing behavior until the staged rotation protocol and both clients are updated together.

## Required follow-up protocol

The completed rotation flow should:

1. Lock the personal vault at the API layer and record its current key epoch.
2. Have the authenticated client generate a fresh random 256-bit vault key locally.
3. Re-wrap the new vault key under the in-memory account key using the existing vault AAD context.
4. Re-encrypt every retained current item locally using fresh GCM nonces and the existing per-item AAD/version rules.
5. Upload replacements in bounded staged batches rather than one oversized request.
6. Atomically verify that the vault epoch and every item version still match the rotation snapshot.
7. Replace the wrapped vault key, replace current item ciphertext, discard old retained revision ciphertext, increment `key_version`, and advance sync sequencing in one transaction.
8. Reject stale writes from clients using the old key epoch so old ciphertext cannot be reintroduced after cutover.
9. Refresh encrypted offline caches after successful rotation while preserving unsynced/conflicting local ciphertext for explicit recovery.

## Security invariants

- The API must never generate, unwrap, log, or inspect the clear personal vault key.
- Rotation must fail closed on concurrent item changes or a changed key epoch.
- A failed/incomplete staged rotation must leave the active wrapped key and active ciphertext unchanged.
- Finalization must be atomic.
- Old revision ciphertext must not remain queryable after a successful key cutover.
- Rotation payloads remain subject to existing request, item-count, and ciphertext-byte limits.
- Account password changes remain a separate account-key rewrap operation and must not silently rotate the personal vault key.

This document describes the implementation contract; adding the epoch column alone does not close the automatic personal-vault rotation release gate.
