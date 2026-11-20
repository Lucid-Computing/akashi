# ADR-001: Greedy-Only Decoding Constraint

## Status

Accepted

## Date

2026-11-20

## Context

LLM inference can operate in multiple modes:
1. **Greedy decoding**: Always select the highest-probability token (temperature=0.0)
2. **Sampling-based**: Sample from probability distribution (temperature>0, top-p, top-k)
3. **Beam search**: Maintain multiple candidate sequences

The verified inference gateway must prove that served outputs match model execution. However, proving correctness depends on determinism:
- Greedy decoding is fully deterministic (given fixed weights and input)
- Sampling-based methods are inherently non-deterministic
- Beam search can be deterministic but is complex

Zero-knowledge proof systems like FlashProve can prove deterministic computation efficiently. Proving non-deterministic computation requires either:
1. Committing to RNG seeds before execution (complex, changes inference API)
2. Proving output comes from correct distribution (very expensive)
3. Rejecting non-greedy methods

## Decision

The verified inference gateway will **only support greedy decoding** (temperature=0.0). All sampling-based parameters (temperature≠0, top-p, top-k, etc.) will be rejected with a clear error message.

This constraint applies to:
- Initial exploration (M0-M4)
- Production deployment
- All models and configurations

## Consequences

### Positive

- **Determinism**: Perfect reproducibility of outputs
- **Proof simplicity**: FlashProve can efficiently prove correct execution
- **Verification cost**: Lower proof generation and verification costs
- **Implementation clarity**: No need for RNG seed management or complex sampling proofs

### Negative

- **Limited use cases**: Excludes creative writing, diverse outputs, exploration
- **User expectations**: Users accustomed to sampling will need different tools
- **Market coverage**: Cannot serve all inference workloads
- **Temperature=0 isn't always desired**: Some applications prefer varied outputs

### Neutral

- **Quality**: Greedy decoding quality depends on model and use case
- **Scope**: Clearly defined scope helps focus development
- **Compatibility**: Still OpenAI-compatible API, just with restricted parameters

## Alternatives Considered

### Alternative 1: Support Temperature with Seed Commitment

**Description**: Allow temperature>0 by requiring clients to commit to RNG seed before inference.

**Pros**:
- Supports sampling-based decoding
- Maintains determinism via seed commitment
- Broader use case coverage

**Cons**:
- Breaks OpenAI API compatibility (adds seed requirement)
- Complex seed management and verification
- Clients must understand cryptographic commitments
- Seed exposure could leak information

**Why not chosen**: Significant API complexity and user friction. Violates "exploration" scope.

### Alternative 2: Prove Output Distribution

**Description**: Prove that outputs are correctly sampled from the model's probability distribution.

**Pros**:
- Supports full sampling-based inference
- No API changes required
- Theoretically complete solution

**Cons**:
- Extremely expensive proofs (orders of magnitude slower)
- No existing proof systems support this efficiently
- Research problem, not engineering problem
- Verification becomes probabilistic, not deterministic

**Why not chosen**: Not feasible with current ZK proof technology. Research topic for future.

### Alternative 3: Two-Tier System

**Description**: Support both greedy (with proofs) and sampling (without proofs).

**Pros**:
- Serves both use cases
- Users choose based on needs
- Broader market appeal

**Cons**:
- Confusing user experience (sometimes proven, sometimes not)
- Weakens security guarantees
- Implementation complexity
- Defeats purpose of verified inference for sampled outputs

**Why not chosen**: Undermines core value proposition. If some outputs aren't verifiable, the guarantee is weakened.

## References

- `specs/guarantee.md`: Security properties requiring determinism
- `specs/canonical-rendering.md`: Deterministic input rendering
- `specs/engine.md`: Integrity gates enforcing greedy-only
- `specs/facts-register.md`: FlashProve capabilities and limitations

## Implementation Notes

### Gateway Validation

Gateway MUST reject requests with:
```python
if request.temperature != 0.0:
    raise InvalidRequestError(
        "Only greedy decoding (temperature=0.0) is supported. "
        "This gateway provides proofs of correct execution, "
        "which requires deterministic inference."
    )
```

### Error Messages

Provide clear, helpful error messages explaining why sampling is unsupported:
```json
{
  "error": {
    "type": "invalid_request_error",
    "message": "Only greedy decoding (temperature=0.0) is supported",
    "details": "This gateway proves inference correctness, requiring deterministic execution. Sampling-based methods (temperature>0, top-p, top-k) are not supported."
  }
}
```

### Documentation

Prominently document this limitation:
- README.md: List in "What It Proves" section
- API docs: Note parameter restrictions
- Integration guides: Explain use case fit

### Future Research

Track research on sampling-based proofs in `specs/open-questions.md`. If ZK proof technology advances to make sampling proofs feasible, this decision can be revisited.

## Testing

Red team suite must verify:
1. Requests with temperature≠0.0 are rejected
2. Requests with top-p, top-k are rejected
3. Error messages are clear and helpful
4. No way to bypass greedy-only enforcement
