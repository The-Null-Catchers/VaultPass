# Database field classification

All resource identifiers are UUIDs. Primary API reads authorize against the current session's user ID, never a client-supplied owner ID.

| Table / fields | Classification | Reason |
| --- | --- | --- |
| users.id | Public identifier | Routing/key context |
| users.email, verified, created | Sensitive operational metadata | Login/verification |
| users.auth_hash | Authentication verifier (Argon2id hash) | Authentication only; never master password |
| users.bundle.salt, profile | Public cryptographic parameters | Local derivation |
| users.bundle.account_key | Ciphertext + nonce/tag | Wrapped random account key |
| vaults.id, owner_id, sequence | Relationship/sync metadata | Authorization and ordered change feed |
| vaults.wrapped_key | Ciphertext | Wrapped random vault key |
| vault_items.payload, vault_item_versions.payload | Ciphertext | All titles, passwords, folders, tags and types remain inside |
| vault_items.version, sequence, deleted, purged, updated | Sensitive metadata | Conflict handling/trash/sync |
| sessions.access_hash, refresh_tokens.digest | SHA-256 hashes of random tokens | Bearer token lookup; no plaintext token storage |
| sessions.name, created, latest, expires, revoked | Sensitive device/session metadata | Device control; no invasive fingerprinting |
| audit_events.event, created, user_id | Security metadata | Enum-like server-generated actions; no secret values |
| email_verifications.digest, expires | Hash of random short-lived verification token | Single-use email verification |
| sharing_keys.public_key | Public SPKI key | Recipient encryption |
| sharing_keys.private_key | Ciphertext | Account-key-encrypted PKCS8 |
| shares.sender_id, recipient_id, expires, revoked | Sensitive relationship metadata | Access/expiry |
| shares.wrapped_key | RSA-OAEP ciphertext | Recipient-wrapped snapshot key |
| shares.payload | AES-GCM ciphertext | Shared snapshot |

No database field contains plaintext vault data. The protocol cannot prevent a deliberately malicious caller from placing arbitrary bytes in a ciphertext-shaped envelope. The first-party clients are responsible for encryption.

Cascade deletion removes account-owned rows. Backup expiry is an operator responsibility. Audit events are append-only through public APIs, not cryptographically immutable against a database administrator. Use separate database roles/backups and an external tamper-evident audit sink before claiming stronger guarantees.
