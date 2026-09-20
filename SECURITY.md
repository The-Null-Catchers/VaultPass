# Security policy

VaultPass 0.1.x is pre-release. It has no independently audited or production-supported version yet. Use synthetic data until the release gates are resolved.

Please report vulnerabilities through GitHub private vulnerability reporting on this repository when enabled. Do not post passwords, keys, real vault payloads or exploit-bearing personal data in public issues. If private reporting is unavailable, ask maintainers for a private channel without publishing the exploit details. A reporting mailbox and response SLA have not been established; none is invented here.

Reports should include affected commit, minimal synthetic reproduction, expected/actual behavior, impact and relevant environment. Allow coordinated remediation before public disclosure. Never test against another person's vault or production account without permission.

The server stores client ciphertext and authentication/session metadata. Argon2id derives separated wrapping/authentication material; random account/vault keys are wrapped with AES-256-GCM. Sharing uses recipient RSA-OAEP key wrapping. See [architecture](docs/SECURITY_ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [known limitations](docs/RELEASE_READINESS.md).

A successful test suite is not a cryptographic audit. No claim of being unhackable, formally verified, resistant to malicious web delivery, or capable of erasing secrets already copied by a recipient is made.
