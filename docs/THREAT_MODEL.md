# Threat model

Assets: master passwords, account/vault keys, item plaintext, TOTP seeds, sharing private keys, bearer/refresh tokens, encrypted backups, account/device metadata.

Trust boundary: encryption/decryption runs in the client. The server/database/queue never need vault plaintext. Web delivery, the endpoint OS, cryptographic library supply chain and the unlocked client remain trusted.

| Threat | Mitigation | Remaining limit |
| --- | --- | --- |
| Stolen database | Argon2id + independently wrapped random keys; authenticated ciphertext | Weak masters can be guessed offline; email, timestamps, counts and relationships are visible |
| Passive network observer | TLS required for production; no TLS bypass | Endpoint/IP/timing remains observable |
| Compromised backend | Stored vault data is encrypted; AAD binds identity/revision | Malicious web delivery can steal keys after unlock; rollback/availability attacks remain |
| Stolen locked device | Master-derived wrapping, platform-protected refresh token; optional enforced Android key gate | Rooted devices, OS flaws, device-credential compromise; physical hardware checks pending |
| XSS/browser extensions | React text rendering, nonce CSP, no third-party scripts, no persistent web tokens | An active extension or script in the unlocked origin can read secrets |
| CSRF | Explicit bearer auth, JSON requests, origin checks, no cookies | XSS bypasses this boundary |
| Credential stuffing/brute force | Expensive derivation, proof hash, Redis limits | WebAuthn/passkeys and distributed account-targeted throttling need additional hardening |
| Lost master password | Optional client-generated recovery key wraps the account key; recovery revokes sessions and consumes enrollment | A lost recovery key cannot be retrieved; a copied recovery key can decrypt/reset until disabled or consumed |
| Session theft | Access expiry, one-use refresh rotation/replay revocation, device revocation | A currently valid stolen token can access ciphertext; offline copies remain |
| Malicious insider | No plaintext admin views; audit events have no mutation APIs | Database administrators can modify audit tables; no tamper-evident external log |
| Clipboard leakage | Conditional timed clear and explicit feedback | Browser/OS policies may block clearing; other apps/history managers can retain copies |
| Insecure backup | Only encrypted export; local restore | Old backups retain old wrapping credentials; files expose account metadata |
| Concurrent/offline writes | Expected revision + vault sequence + server lock; local pending queue | Conflicts require explicit action; offline revocation cannot erase cached data |
| Sharing key substitution | SHA-256 fingerprint verified out of band before sending | No automated transparency infrastructure or signed sender identity |
| Shared recipient retention | Expiry/revocation prevents future API downloads | Cannot retract viewed/copied material |
| Dependency compromise | Locks, automated audits, CodeQL, no secret credentials in repo | Scans do not prove absence of malicious code; independent review required |
| DoS | Reverse-proxy body limits, envelope bounds, rate limits, paged sync | Account quotas and per-user storage caps are not yet implemented |

No claim of protection from compromised unlocked endpoints, malicious JavaScript delivery, invasive extensions, coercion, or a malicious recipient. The code is pre-release and should initially handle synthetic data only.
