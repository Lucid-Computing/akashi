# Error model

## Failure contract

Inference HTTP errors use `{error: {code: string, message: string, param?: string}}`. Before opening a stream, use normal HTTP errors. After opening it, emit a terminal unwarranted event with no receipt if completion cannot be warranted. A disconnected or unterminated stream provides no terminal evidence.

| Condition | Caller-visible action | Operator action |
|---|---|---|
| Malformed input, unsupported parameter or overlong context | 400 with specific policy code | Count bounded rejection reason |
| Missing or invalid authentication | 401, no job or engine work | Count auth failures without credentials |
| Body exceeds configured size | 413 | Reject before parsing |
| Admission or challenge limit | 429 and Retry-After | Bound outstanding work |
| Engine integrity error or incomplete token output | 502 unwarranted_reply | Deny receipt and classify reason |
| Engine unavailable or gates not passed | 503 engine_unavailable | Keep readiness false |
| Commit or promise validation fails | 500, no warranted completion | Reconcile durable state by request ID |
| Expired challenge or invalid bundle | Expired or INVALID_BUNDLE intake error | Do not schedule proof |
| Missing or expired pickup or proof | 404 for absent artifact or invalid private lookup | Purge expired artifacts |
| Beacon unavailable or escrow expires | Gap; sampled deadline outcome remains accountable | Never reassign round or extend escrow |
| Prover failure, rejected proof, deadline missed | UNAVAILABLE with reason, except independently classified range and completeness outcomes | Preserve evidence privately and alert on failure |

## Verification errors

Use the [verifier exit contract](../../specs/verifier-kit.md#exit-codes). Only full successful proof verification exits 0. Receipt-only success has its own output and exit 30 so automation treats it as no model verdict. An incomplete transcript exits 13. Invalid proof rejects at 20, verified deviation at 21, and tool errors or missing files at 30. Diagnose missing inclusion after the merge deadline separately from cryptographic rejection.
