# VaultPass portfolio roadmap

Baseline reviewed on November 17, 2026. Repository roadmap published on November 18, 2026.

This roadmap applies to this repository and follows the shared Null Catchers portfolio plan. Verify the documented state against the current code and runs before starting work.

**Estimated initial demo effort** 35–60 hours for a developer familiar with the project. The estimate excludes external reviews, store accounts, target environment setup, and later milestones.

## Project priorities

**Documented state** The personal vault implements local encryption, ciphertext synchronization, team protocols, and partial web and mobile parity. Release readiness describes the project as pre-release with independent validation outstanding.

**P0 — Demo** Use synthetic secrets to demonstrate lock and unlock, two-client synchronization, conflicts, and encrypted backup and restore. Document visible server metadata, recovery, old copies, and sharing revocation.

**P1 — Validation and depth** Use two browsers to test invitation, read-only access, member removal, and rekeying. Verify removed members cannot read new ciphertext. Check biometric invalidation, account switching, backgrounding, and clipboard behavior on a physical phone.

**P2 — Later** Consider mobile membership administration and independent cryptography review and security testing before expanding security claims or using real secrets. Assess pinning and protocol changes against the threat model.

**Acceptance criteria** Check API traffic and logs for plaintext, retain conflicts, share cross-client test vectors, and state security limits. Track independent validation separately.

**Demo scenario** Synthetic vault → inspect ciphertext → sync → remove a member and rekey → resolve conflict and restore. [Release Readiness](https://github.com/The-Null-Catchers/VaultPass/blob/main/docs/RELEASE_READINESS.md), [Threat Model](https://github.com/The-Null-Catchers/VaultPass/blob/main/docs/THREAT_MODEL.md).

## Next milestones

[Release readiness](docs/RELEASE_READINESS.md) documents cross-client interoperability, restore, and key rotation. The project remains in pre-release.

1. [ ] Create a synthetic vault entry and test lock and unlock. Open it from a second client and check that the value matches.
2. [ ] Edit the same item concurrently, document the conflict, and restore an encrypted backup to a separate test vault. Verify the item count and rejection of invalid decryption credentials.
3. [ ] Record the clients, commit SHA, and verification limits, including physical biometric testing when available.

## Portfolio acceptance checklist

- [ ] Another person can reproduce the primary workflow from a clean checkout using the README and test credentials or fixtures.
- [ ] The demo tells one complete story with a defined user, problem, and saved result.
- [ ] Tests cover the main flow, an important failure, and access boundaries when multiple accounts are involved.
- [ ] Demo data is labeled synthetic and reproducible. Review screenshots and recordings for secrets and customer data.
- [ ] Include four to six real screenshots where appropriate, a 60–120 second recording, and working links. Identify the revision used for capture.
- [ ] The README describes implemented capabilities, setup, architecture, limits, tests, and the demo.
- [ ] A short case study explains two engineering decisions, a considered alternative, and how the system handles an actual failure.
- [ ] Release evidence records the commit SHA, CI, prerequisites, and limits. Performance data includes workload, hardware, and method.
- [ ] Licensing and contributor attribution are settled before distribution. Choose the license for each repository individually.

A hosted demo is optional. Code execution, server administration, and secret management can be demonstrated through a recording and a reproducible isolated environment. Keep public demo access scoped to the activities it needs.

## Implementation and follow-up

- Break P0 into tasks with expected behavior, acceptance criteria, and a suitable test.
- Verify existing functionality first. Update this plan when evidence tied to a commit or PR closes a milestone.
- Record the fixture source, the revision used for evidence, and the tested limits.
- Review the final diff and verify required checks for its exact SHA before merging. Follow branch protection.
- For documentation-only changes with no applicable workflow, verify content and links and record the checks actually performed.
- Tie performance, security, and readiness claims to supporting evidence.
