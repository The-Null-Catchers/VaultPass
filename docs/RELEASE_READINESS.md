# Release readiness

## Assessment

**Pre-release, not production-ready.** The repository contains a functioning personal-vault implementation rather than a full completion of the larger product specification. Critical paths have actual encryption, authentication, sync and tests; unavailable features are not simulated.

## Validation record

This section is updated with observed commands/results at handoff. CI definitions are not evidence that a workflow passed. Android artifacts are test/unsigned builds unless explicitly stated otherwise.

Local checks executed successfully during implementation:

- Backend authentication/authorization/revocation/trash/rate-limiter tests.
- Ruff and mypy checks.
- SQLite Alembic upgrade/schema-drift check (not a PostgreSQL substitute).
- Web crypto round trips, key/context/tamper rejection, password rewrap, RFC 6238 vectors, recipient sharing and generator tests.
- Web TypeScript, ESLint and production build.
- npm runtime dependency audit: no reported vulnerabilities at that scan.
- Flutter analyzer, crypto/TOTP/generator and locked-state widget tests.

Additional interoperability/offline/backup tests and CI results are recorded after their actual execution. Physical biometric, real iOS, full mobile offline device testing and external penetration tests have not run.

## Implemented security review observations

- Master password never enters API request bodies; validation responses avoid reflecting rejected input.
- Wrapped key hierarchy allows password changes without item re-encryption.
- AAD includes revision/object identity; nonces use platform randomness.
- Web keys and tokens remain in memory; mobile cache is ciphertext.
- Optional Android stored key uses enforced OS authentication, a separate namespace and API 28 minimum.
- Every vault/session/history/share read is authorized server-side.
- Refresh replay commits revocation before returning an error.
- Revision conflicts retain local encrypted edits; exact retries are idempotent.
- Only TLS is allowed in mobile release API configuration.
- No plaintext export feature or plaintext secret admin console exists.
- Permanent deletion retains only sync tombstones; account deletion cascades.

## Remaining implementation and release gates

1. Independent cryptographic/security review; full threat-driven penetration testing; physical Android key invalidation/biometric/background/clipboard tests and iOS Keychain behavior.
2. Account MFA/passkeys, recovery-key enrollment and authenticated recovery protocol. Vault TOTP support is not login MFA.
3. Organizations/team vaults, invitations/roles, editable sharing and membership key rotation.
4. iOS biometric unlock, mobile sharing/import/export/account-settings parity, QR TOTP scanning, comprehensive Flutter integration tests and offline crash/multi-device device tests.
5. Encrypted attachments, dedicated structured card/identity forms, CSV/provider adapters, passphrase generator, richer password age/MFA/duplicate analysis, recent/archive sections.
6. Quotas, GCM per-key usage limits/key rotation, account-targeted throttling, edge proxy limits, automated trash/expired-share retention and security notification preferences/new-device emails.
7. Tamper-evident external audit storage, abuse/admin operations UI and operational monitoring/alerting/runbooks.
8. Complete browser E2E/accessibility/visual regression coverage, PostgreSQL concurrency tests, clean-install/backup restoration drills, real email delivery checks.
9. A configured HTTPS test/production endpoint, production Android signing and iOS signing. Default Android CI URL is intentionally non-routable unless configured.
10. Recovery/import/share verification UX hardening and third-party review. Sharing recipient identity requires an out-of-band fingerprint check; there is no key transparency or sender signature.

No release label should be applied until these gaps are triaged and the mandatory gates for its advertised scope pass. Old encrypted backups/offline copies remain accessible with old keys even after session revocation or password changes.
