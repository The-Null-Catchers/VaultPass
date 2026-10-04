# Release readiness

## Assessment

**Pre-release, not production-ready.** The repository contains a functioning personal-vault implementation rather than a full completion of the larger product specification. Critical paths have actual encryption, authentication, sync and tests; unavailable features are not simulated.

## Validation record

This section is updated with observed commands/results at handoff. CI definitions are not evidence that a workflow passed. Android artifacts are test/unsigned builds unless explicitly stated otherwise.

Local checks executed successfully during implementation:

- Backend authentication/passkey/recovery/authorization/revocation/trash/rate-limiter and team role/invitation/rotation tests.
- Ruff and mypy checks.
- SQLite Alembic upgrade/schema-drift check (not a PostgreSQL substitute).
- Web crypto round trips, key/context/tamper rejection, password/recovery rewrap, RFC 6238 vectors, recipient/team sharing and generator tests.
- Web TypeScript, ESLint, production build and browser end-to-end flow in CI.
- npm runtime dependency audit: no reported vulnerabilities at that scan.
- Flutter analyzer, crypto/TOTP/generator and locked-state widget tests.

Cross-client interoperability, encrypted backup restore, mobile offline-queue tests, PostgreSQL migrations, Docker clean-start, Android builds and CodeQL passed in GitHub Actions run `35480633523` / CodeQL run `35480633519`. Physical biometric, real iOS, full mobile offline device testing and external penetration tests have not run. The mobile dependency baseline upgrades from flutter_secure_storage 10.3.4 to 11.2.0 only after already being on v10; automated analyzer/tests/builds must pass on current HEAD, but physical upgrade/invalidation behavior remains a release gate.

## Implemented security review observations

- Master password never enters API request bodies; validation responses avoid reflecting rejected input.
- Wrapped key hierarchy allows password changes without item re-encryption.
- AAD includes revision/object identity; nonces use platform randomness.
- Web keys and tokens remain in memory; mobile cache is ciphertext.
- Optional mobile stored account key uses enforced OS authentication: Android uses the biometric secure-storage namespace (API 28 minimum) and iOS uses this-device passcode Keychain accessibility plus the current enrolled biometric set.
- Every vault/session/history/share read is authorized server-side.
- Refresh replay commits revocation before returning an error.
- Revision conflicts retain local encrypted edits; exact retries are idempotent.
- Only TLS is allowed in mobile release API configuration.
- No plaintext export feature or plaintext secret admin console exists.
- Permanent deletion retains only sync tombstones; account deletion cascades.
- Old deleted personal/team items are automatically purged after the configured trash-retention window while preserving versioned sync tombstones; expired share rows are removed after their configured metadata-retention window.
- Recovery keys are generated and used client-side; recovery proofs and five-minute reset tokens are one-time and successful recovery revokes all sessions.
- Passkey MFA uses purpose-bound five-minute WebAuthn challenges, requires authenticator user verification, and issues no session after the password proof until the assertion succeeds.
- Team vault access is membership-checked server-side; read-only members cannot mutate ciphertext and only the owner can create/manage administrators.
- Member removal uses bounded staged uploads followed by an atomic finalize that increments the key epoch, requires a fresh wrapper for every remaining member and current ciphertext for every retained item, removes old revision ciphertext and invalidates outstanding invitations.
- The supplied Nginx deployment snippets enforce a trusted-edge `/api/` request limit, per-client connection cap, 400 KiB request-size cap, bounded request/proxy timeouts, and overwrite forwarded client-address headers with the edge-observed peer address.

## Remaining implementation and release gates

1. Independent cryptographic/security review; full threat-driven penetration testing; physical Android/iOS key invalidation/biometric/background/clipboard tests and iOS Keychain behavior.
2. Complete the team-vault product surface: the web management/switching surface is implemented for creation, encrypted item editing, invitations, roles, owner transfer/deletion and client-driven member-removal rekey. Flutter now has a first parity slice for team listing/switching, encrypted item read/edit/trash/sync, team creation with an existing sharing identity, incoming invitation accept/decline, account-scoped ciphertext cache and key-epoch mismatch preservation. Safe self-leave is implemented in the API and web client as an admin-completed rekey request with pending/cancel UX. Mobile presentation, richer conflict/rekey recovery UX, mobile membership administration/removal rekey and broader accessibility coverage remain. The overall team surface is not independently reviewed.
3. Physical iOS biometric/Keychain validation, mobile passkey/enrollment UX, mobile sharing-identity/share-management/import/export parity, QR TOTP scanning, comprehensive Flutter integration tests and offline crash/multi-device tests. Flutter now implements email verification, master-password rewrap/session revocation, recovery enrollment/disable and one-time recovery UX, but these mobile account-security paths still require physical-device and multi-device validation.
4. Encrypted attachments, dedicated structured card/identity forms, CSV/provider adapters, passphrase generator, richer password age/MFA/duplicate analysis, recent/archive sections.
5. Automatic personal-vault GCM key rotation and security notification preferences/new-device emails. Account-targeted throttling is applied to master-password login and recovery-key verification in addition to peer-based request limiting. Per-vault current-ciphertext byte caps are enforced for personal and team vaults; request, item, team/member, active-session and passkey caps are also implemented. Automated trash purge, expired-share retention and a deployable trusted-edge Nginx request/connection limiter are implemented, but production sizing/tuning and historical-revision storage accounting still need review.
6. Tamper-evident external audit storage, abuse/admin operations UI and operational monitoring/alerting/runbooks.
7. Complete browser E2E/accessibility/visual regression coverage, physical cross-platform passkey testing, PostgreSQL concurrency tests, clean-install/backup restoration drills, real email delivery checks.
8. A configured HTTPS test/production endpoint, production Android signing and iOS signing. Default Android CI URL is intentionally non-routable unless configured.
9. Recovery/import/share verification UX hardening and third-party review. Recovery is implemented on web and Flutter, but physical mobile validation and broader failure-path testing remain. Sharing recipient identity requires an out-of-band fingerprint check; there is no key transparency or sender signature.

No release label should be applied until these gaps are triaged and the mandatory gates for its advertised scope pass. Old encrypted backups/offline copies remain accessible with old keys even after session revocation or password changes.
