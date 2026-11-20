# Data model

## Wire types

```text
Digest = bytes[32]                      # lowercase hex in JSON
Token = uint32 in [0, vocabulary_size)
Transcript = {profile, prompt: Token[], reply: Token[], max_tokens: uint32}
HolderBundle = {verification, max_tokens, input: Message[] | Token[],
                text: string | null, proof?: ProofArtifact}
Verification = {version: "vig/1", receipt: Receipt,
                 prompt_token_ids: Token[], reply_token_ids: Token[],
                 pickup_id?: Digest}
Receipt = {log_id, endpoint_id, request_id, served_at, commitment_id,
           render_profile, params_digest, transcript_commitment, leaf_hash,
           beacon_round, promise_sig, log_key_id, salt}
PublicLeaf = Receipt without salt and promise_sig, plus leaf_index
ProofArtifact = {statement: bytes, proof: bytes, kind: "conformance" | "deviation"}
VerdictKind = CONFORMS | DEVIATES | INCOMPLETE | EXCUSED_RANGE | UNAVAILABLE
```

Use unsigned 64-bit big-endian for rounds and tree sizes, lowercase canonical UUID text for request IDs and Ed25519 signature octets as lowercase hex. Preserve canonical UTC RFC3339 timestamp bytes at millisecond precision through JSON and signing. Reject unknown major versions and malformed octets before verification. A descriptor pins log identity and verification keys by key ID; key discovery alone establishes no trusted identity. Render digest encoding and model proof request bytes are specified by the applicable RFCs.

## Binding invariants

`parameters.md` fixes the model, E, T and z. For the receipt preimage, domain-separate and length-frame variable fields. Let `frame(b) = u32le(len(b)) || b`. Use the following v1 scheme, derived from the [legacy receipt preimages](../../specs/receipt-log.md#transcript-commitment) to bind the token split and delivery metadata.

```text
H_params = SHA256(u32le(max_tokens))
t = SHA256("vig/transcript/1" || C || R || H_params || salt
           || frame(u32le_vector(x)) || frame(u32le_vector(y)))
leaf_hash = SHA256("vig/leaf/1" || log_id || C || R || H_params || t
                   || u64be(beacon_round) || frame(utc_timestamp)
                   || frame(utf8(endpoint_id)) || frame(utf8(request_id))
                   || frame(utf8(log_key_id)))
```

Hold the fresh salt in holder or escrow material and authorized audit material. Keep it out of public log entries so low-entropy transcript guesses cannot be checked using public fields alone. Public entries can reconstruct the leaf without the salt, because the leaf commits to `t`. Recompute the leaf before checking its signature and tree inclusion. The holder checks requested budget and original input, then independently checks reply text and completeness. A reply is complete if it has no early end token and either ends in E or fills its requested budget.
