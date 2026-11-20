# Deterrence Model

## Overview

This document analyzes the deterrence properties of probabilistic sampling combined with on-demand challenges. The key insight: under greedy decoding, a deviation at any position makes a valid conformance proof impossible, so providers must serve honestly on all requests to avoid detection.

## Detection Probability

### Formula

A provider that deviates on a fraction f of N receipted requests escapes every sampled audit with probability:

```
P(no detection) = (1 - f/N)^n
P(detection) = 1 - (1 - f/N)^n
```

Where:
- f = number of deviating requests
- N = total requests
- n = number of requests
- Sampling rate r = 1/N

### Simplified Form

When f = N (deviates on every request):
```
P(detection) = 1 - (1 - 1/N)^n
```

## Detection Tables

### N = 20 (Prototype Live Rate)

| Pattern | Requests (n) | Detection Probability |
|---|---|---|
| Deviates on every request | 100 | 1 - 0.95^100 ≈ 99.4% |
| Deviates on every request | 3,000 | ≈ 100% (certain) |
| Deviates on 1% of requests | 10,000 | 1 - (1 - 0.0005)^10000 ≈ 99.3% |
| Deviates on 1% of requests | 1,000,000 | ≈ 100% |

### N = 1,000 (Design Target)

| Pattern | Requests (n) | Detection Probability |
|---|---|---|
| Deviates on every request | 100 | 9.5% |
| Deviates on every request | 3,000 | 1 - 0.999^3000 ≈ 95.0% |
| Deviates on every request | 5,000 | 1 - 0.999^5000 ≈ 99.3% |
| Deviates on 1% of requests | 10,000 | 1 - (1 - 0.00001)^10000 ≈ 9.5% |
| Deviates on 1% of requests | 100,000 | 1 - (1 - 0.00001)^100000 ≈ 63.2% |
| Deviates on 1% of requests | 1,000,000 | 1 - (1 - 0.00001)^1000000 ≈ 99.995% |
| Deviates on 0.1% of requests | 100,000 | 9.5% |

Source: Specification section 15

## Interpretation

### Systematic Deviation

A provider that deviates on every request is detected quickly:
- At N=1,000: 95% probability within 3,000 requests
- At N=20: 99.4% probability within 100 requests

**Time to detection** (at ~550 requests/day on prototype):
- N=1,000: 95% detection within 5.5 days
- N=20: 99.4% detection within 0.2 days (4.8 hours)

### Sparse Deviation

A provider that deviates on 1% of requests:
- At N=1,000, 100K requests: 63.2% detection
- At N=1,000, 1M requests: 99.995% detection

**Time scales**:
- 100K requests ≈ 182 days at 550/day
- 1M requests ≈ 1,818 days at 550/day

### Targeted Deviation

What uniform sampling misses: deviations on a few specific high-value requests. A provider that deviates on 10 carefully chosen requests out of 1M has only a 1% chance of being caught by sampling at N=1,000.

**Mitigation**: The on-demand challenge channel. Any holder can challenge any reply within the retention window. The provider cannot know which replies will be challenged, so it must serve honestly on all of them.

## Two-Channel Deterrence

### Sampling (Statistical)

Catches:
- Systematic deviations (different model, cheaper quantization)
- Frequent selective deviations (e.g., on long prompts)
- Random spot checks maintain pressure

Does not catch:
- Rare targeted deviations on specific requests

### On-Demand Challenges (Deterministic)

Catches:
- Any specific reply a holder suspects
- High-value requests that holders monitor
- Requests flagged by downstream quality checks

Does not catch:
- Deviations on requests whose holders don't challenge

## Combined Deterrence

The combination provides:

1. **Broad coverage**: Sampling catches systematic cheating quickly
2. **Targeted coverage**: Challenges catch specific suspicious replies
3. **Unpredictability**: Provider cannot know which channel will detect them
4. **Retroactive checking**: Challenges work on old requests (within retention window)

## Economic Analysis

### Cost of Cheating

For a provider serving a cheaper substitute:

**Savings per request**: S (difference in inference cost)

**Detection penalty**: P (delisting, reputation loss, breach of contract)

**Expected cost** over N requests:
```
Cost = -S × N + P × P(detection in N requests)
```

**Breakeven**: Cheating is deterred when P(detection) × P ≥ S × N

### Example

Assume:
- S = $0.001 per request (10% cost reduction)
- N = 100,000 requests
- Savings = $100
- P = $10,000 (reputation + lost business)
- Sampling rate N = 1,000

For 1% deviation over 100K requests:
```
P(detection) ≈ 63.2%
Expected penalty = 0.632 × $10,000 = $6,320
Expected savings = $100
Net expected value = -$6,220
```

Cheating is not profitable when detection penalties are high enough.

## Penalty Setting

The deterrence model requires meaningful penalties for failed audits:

### Router Actions

Potential penalties:
1. **Immediate delisting** from provider pool
2. **Public audit failure** on audit page
3. **Notification to affected users** (those who received unaudited replies in same period)
4. **Financial penalties** per contract terms

### Transparency

The audit page publishes:
- Provider endpoint
- Total requests logged
- Requests selected at each N
- Conformance rate
- Deviation count and details
- Incomplete or undefined verdicts

This creates public accountability.

## Sampling Rate Selection

### Trade-offs

| N | Proofs/day (550 req/day) | Detection (systematic) | Cost overhead |
|---|---|---|---|
| 1 | 550 | 100% in 5 requests | ~6,000% (1 per batch) |
| 20 | 27.5 | 99.4% in 100 requests | ~357% to 465% |
| 1,000 | 0.55 | 95% in 3,000 requests | ~7% to 9% |

### Recommendations

**Prototype**: N = 20 (live), N = 1,000 (shadow), N = 1 (soak test)
- Live N=20: Strong deterrence, feasible proof load
- Shadow N=1,000: Demonstrates production economics
- Soak N=1: Measure honest failure rate on full audit

**Production**: N = 1,000
- Affordable proving cost (7-9% overhead)
- Strong deterrence against systematic deviation
- Combined with challenges for targeted coverage

## Monitoring and Response

### Real-Time Monitoring

The audit page shows:
- Selections pending proof
- Overdue proofs (past deadline)
- Deviation detections (alerts)
- Conformance rate trends

### Response to Detection

On first deviation:
1. Alert sent to router and auditor
2. Increase sampling rate to N=1 for that provider
3. Notify all recent users to challenge if suspicious
4. Investigate other concurrent verdicts

Multiple deviations: immediate delisting.

## Limitations

### What Deterrence Does Not Cover

1. **Undetected deviations**: If no sampling hits and no challenges, deviation escapes
2. **Collusion**: Gateway operator + provider can suppress audits (detectable by receipt holders and monitors)
3. **Honest failures**: Range failures in padding, unexplained prover errors (marked as EXCUSED or ERROR, not provider failure)

### Assumptions

Deterrence model assumes:
1. Penalties are high enough to outweigh gains
2. Sampling rule is public and verifiable
3. Beacon provides unbiasable randomness
4. Proof system is sound (per F12 bound)
5. Holders actually check suspicious replies

## Related Specifications

- `guarantee.md`: Security properties S2 (unpredictable selection), S4 (soundness)
- `sampling.md`: Selection rule implementation
- `audit-protocol.md`: Proof generation and verdicts
- `facts-register.md`: Detection probability calculations
