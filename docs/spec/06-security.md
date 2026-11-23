# Security

## Trust and evidence

Use adversaries A1–A5 and properties S1–S7 from [the guarantee](../../specs/guarantee.md#security-properties-targets). S1 binds a transcript to the signed delivery commitment. S2 requires a verified future round fixed before delivery. S3 requires monitors or holders to compare signed histories; isolated readers cannot establish global consistency. S4 concerns a proof with matching public statement and pinned model. S5 distinguishes verifiable deviation and incomplete replies from missing or excused evidence. S6 keeps transcript data off public endpoints. S7 is limited to bounded admission and the declared prototype configuration.

Assume secure primitives, a live authenticated beacon, trusted descriptor provenance and holders or monitors who perform checks. Collusion and suppressed observations can reduce detection. Soundness figures apply under the model and verifier assumptions in F12–F13. The guarantee concerns the committed integer function and excludes hardware attribution, model quality and general data-use practices.

## Operational boundaries

Use a private loopback engine behind the allowlisted mutually authenticated proxy. Separate non-root roles and use read-only weight mounts, permissioned secret files, archived verification keys and authenticated service-to-service calls. Treat prover inputs, proofs and statements as equally sensitive. Public verdicts exclude token IDs and proof URLs. Keep pickup ciphertext and proof capabilities separate from inference credentials. Enforce [retention](../../specs/retention.md#retention-policy), including deletion on escrow expiry, and publish redacted coverage gaps.

Adopt dependency locking and provenance review before release. Use the repository's private vulnerability reporting channel and publish its location in the security policy before distribution. Record the owner of each rotation, incident and recovery procedure.

The deployment owner can rehearse rotation, role replacement and expired reads with disposable local state. [Private data and key rotation](../operations/private-data.md)
