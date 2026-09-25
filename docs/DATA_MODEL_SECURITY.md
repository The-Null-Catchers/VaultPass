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
| recovery_keys.auth_hash | Argon2id hash of a recovery-key-derived proof | Verifies possession without storing the recovery key |
| recovery_keys.account_key | Ciphertext + nonce/tag | Account key wrapped locally by the recovery key |
| recovery_keys.version, recovery_attempts.recovery_version | Public random identifiers | Prevent an old verified attempt from applying to a replacement enrollment |
| recovery_attempts.digest, expires | SHA-256 hash of a random five-minute token | Authorizes one reset after recovery proof verification |
| passkey_credentials.id, public_key, sign_count | Public WebAuthn credential material | Verifies authenticator signatures and detects supported counter regressions; no private key |
| passkey_credentials.name, transports, device_type, backed_up, timestamps | Sensitive authenticator metadata | Credential management and security UX |
| passkey_challenges.digest, challenge, purpose, session_id, expires | Hash of opaque transaction token plus public one-time WebAuthn challenge metadata | Purpose/user/session binding and replay-resistant five-minute ceremonies |
| sharing_keys.public_key | Public SPKI key | Recipient encryption |
| sharing_keys.private_key | Ciphertext | Account-key-encrypted PKCS8 |
| shares.sender_id, recipient_id, expires, revoked | Sensitive relationship metadata | Access/expiry |
| shares.wrapped_key | RSA-OAEP ciphertext | Recipient-wrapped snapshot key |
| shares.payload | AES-GCM ciphertext | Shared snapshot |
| teams.name, owner_id, key_version, sequence | Sensitive relationship/sync metadata | Team authorization and key epoch coordination |
| team_members.user_id, role, joined | Sensitive relationship metadata | Server-enforced membership and role authorization |
| team_members.wrapped_key | RSA-OAEP ciphertext | Current team key wrapped independently for that member |
| team_invitations identifiers, role, expiry, state | Sensitive relationship metadata | Short-lived membership workflow and replay prevention |
| team_invitations.wrapped_key | RSA-OAEP ciphertext, erased on use/revocation | Current team key wrapped for the intended recipient |
| team_items.payload, team_item_versions.payload | AES-GCM ciphertext | Editable team-vault content and bounded history |
| team_items version/sequence/deletion timestamps | Sensitive metadata | Conflict handling, trash and ordered sync |
| team_rotation_jobs identifiers, actors, key versions, expiry | Sensitive security workflow metadata | Binds a resumable one-hour rotation to one team, initiator and removal target |
| team_rotation_members.wrapped_key | Staged RSA-OAEP ciphertext | Next-epoch key wrapper; visible only through final application, never returned by status |
| team_rotation_items.payload | Staged AES-GCM ciphertext | Next-revision replacement; atomically promoted only after full-set validation |

No database field contains plaintext vault data. The protocol cannot prevent a deliberately malicious caller from placing arbitrary bytes in a ciphertext-shaped envelope. The first-party clients are responsible for encryption.

Cascade deletion removes account-owned rows. Backup expiry is an operator responsibility. Audit events are append-only through public APIs, not cryptographically immutable against a database administrator. Use separate database roles/backups and an external tamper-evident audit sink before claiming stronger guarantees.
