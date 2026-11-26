# Private data and key rotation

## Who holds what

The deployment owner provisions service accounts and assigns a person to each operational role. Each service uses its own non-root UID, private state directory and credential files. Record the deployment, role, responsible operator and activation time when changing custody. Keep credential values out of the record. [Service profiles](../../deploy/service-roles/README.md) · [Trust boundaries](../../specs/guarantee.md#roles-and-trust)

| Owner | Material in custody | Handoff |
| --- | --- | --- |
| Gateway and escrow operator | Request during delivery, transcript salt and short-lived encrypted escrow, escrow wrapping key | Send selected material to the authenticated auditor. A lost acknowledgment retries the same leaf. |
| Provider | The engine owns the read-only model access and content-free events. The proxy holds the server TLS identity. The gateway holds the client key. | Admit the configured gateway certificate at the proxy and forward to the loopback engine. |
| Log operator | Log signing secret, durable leaves and signed heads | Publish the signed history and archive each public signing identity. |
| Auditor operator | Audit signing secret, selected-transcript decryption key, private challenge state and capability hashes | Publish signed redacted verdicts. Release private proof material through the holder's challenge capability. |
| Prover operator | Private request spool, proving key and its live counter | Hand the result to the auditor. Keep a single owner of the mutable proving state. |
| Pickup operator and holder | Pickup stores the encrypted envelope. The holder keeps the pickup secret, original input, displayed reply and any challenge capability. | Recover and open the sealed envelope using the original delivery inputs. The holder independently verifies it. |

Provision private credential files in the role's directory with the modes checked at service startup. Keep the directory owner-only. Mount model files read-only on the provider host. Keep the public verification key available to the independent CPU host. [File permissions](../../specs/hardening.md#file-permissions) · [Private runtime](../../prover/README.md)

## Replace a log or auditor signer

1. The deployment owner obtains a trusted copy of the current discovery descriptor and a signed checkpoint. Record the log identity, tree size, root and the outgoing role/key ID. Arrange a single writer during cutover.
2. The role owner provisions a fresh Ed25519 signing key in that role's private credential directory and assigns a new key ID. Keep the old public key in the deployment's `PublicKeyArchive`. Register the replacement with `archive.rotate(role, new_id, public_key, replaces=old_id)`. A mismatch means another rotation may have won. Read the current archive before retrying.
3. The publisher writes the descriptor to a separate output file. Run `python -m operations.publish_keys base-discovery.json verification.sqlite3 public/.well-known/akashi.json` and serve the result from the holder's configured trust source. Confirm the current identity and the archived key for each role before releasing new traffic.
4. The log owner opens the existing log with the same log ID and the replacement signer, supplying `replaces_key_id=old_id` to `MerkleLog`. At cutover, confirm the new signer signs the same tree size and root, and that the retired writer is fenced. A later append extends the tree. For the auditor, stop the previous signing process and reopen the existing audit database with the new signer and ID. Keep access to the role's existing private custody and decryption state for in-window jobs.
5. The holder verifies an old signed receipt with the archived key. For a newly signed receipt it checks inclusion against the new signed head and consistency from its pre-cutover checkpoint. The auditor likewise verifies a retained signed verdict by its original role and key ID. Record the role, public key IDs, checkpoint and bounded validation outcomes. Retire the outgoing signing credential when the replacement is confirmed.

The publisher preserves the last valid public descriptor if validation fails. If activation and publication disagree, keep new traffic paused and reconcile from the durable archive and signed history. [Historical verification keys](../../specs/hardening.md#validating-service-boundaries) · [Log and receipt format](../spec/03-data-model.md)

## Replace a role process

The host operator stops the outgoing process and provisions the replacement under the same service identity and restricted directory permissions. The replacement checks the expected key identity against its durable store before serving. Retain pending work, signed history and private records still within their authorized lifetime. If state or credentials fail that check, leave the service unavailable and record the affected role and bounded failure.

For the prover, use the spool stop hook and wait for the existing process to exit at a batch boundary. Restart the prover under the same UID on the same physical host, using the original secret key directory and counter in place. Provision this writable, owner-only local directory in the role’s state volume, for example `/var/lib/akashi-prover/isk`. The read-only `/prover/keys` mount holds static material such as the public verification key. If the secret directory is lost, copied, restored or its counter history is uncertain, retire it and follow the pinned operator recovery procedure. Check the committed model identity and recover outstanding submissions from the existing job ledger before resuming. Keep a spool on hold after an abnormal shutdown until its owner has reconciled it. [Prover process control](../../specs/hardening.md#process-control) · [Pinned FlashProve operator duties](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/docs/operators-duties.md)

## Retrieve and erase private evidence

The holder authenticates its challenge submission and saves the returned challenge ID and capability in private storage. For private status and proof reads, send the capability in the bearer header to the challenge-specific resource over the authenticated channel. A missing, expired or unrelated capability yields no private evidence. Independently verify the proof with the original input, receipt, checkpoint and trusted verification assets. Keep proof bytes and token sequences out of support tickets and monitoring. [Challenge contract](../rfcs/RFC-0007-challenge-lifecycle.md#proposed-design) · [Holder verification](../../verifier/README.md#verify-a-holder-bundle-offline)

| Custodian | Expiry action |
| --- | --- |
| Escrow | Delete unselected material when the beacon decision is verified. At the five-minute hard cap, discard remaining private material and report any resulting coverage gap. |
| Pickup | Deny access and erase sealed envelopes at seven days. |
| Auditor | Expire selected transcripts and private challenge evidence at the verdict retention boundary. Proofs and statements are available to the holder for 30 days. Preserve the content-free signed verdict. |
| Prover | Retire the temporary spool copy on durable handoff or its job deadline. Check outstanding physical cleanup after native work releases its files. |
| Provider | Expire content-free engine logs after seven days. |
| Log | Preserve log leaves, heads and historical public verification keys permanently. |

Run the deletion worker as the owning role. Record only its aggregate counts and any unresolved cleanup. Exclude the FlashProve secret directory and counter from all copying, backups and snapshots. For private stores eligible for backup, enforce the same retention in the backup and its restoration procedure. Before reopening a restored service, run the owner's expiry check and verify the public checkpoint and signed verdicts independently. [Retention policy](../../specs/retention.md#retention-policy) · [Operational controls](../rfcs/RFC-0009-operational-controls.md#proposed-design)

## Rehearse the handoff

From a clean checkout, run `make setup test-private-operations docs-check`. The drill uses disposable signing keys, a local durable log and private fixture data. It checks replacement of a live log writer, historical verification using the archived key, five-minute escrow expiry and seven-day sealed receipt expiry. Keep the command result, source revision and public verification outcomes as the operation record. The deployment owner can repeat the same checks against an isolated staging role before activating replacement credentials.
