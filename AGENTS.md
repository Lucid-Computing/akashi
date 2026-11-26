# Agent Development Guide

This repository uses AI assistants during development. This document provides context and guardrails.

## Repository Purpose

Akashi is a verified inference gateway serving LLM inference with cryptographic proof of model conformance, built on FlashProve's zero-knowledge proof system.

## Core Principle

**Every claim must be sourced from `specs/facts-register.md` or the specification documents.** Do not invent performance numbers, timeouts, limits, or API details.

## Key Facts (with sources)

| Fact | Value | Source |
|---|---|---|
| Model | Llama 4 Maverick 17B-128E Instruct, UD-Q4_K_XL, ~232 GB | F3 |
| Commitment ID | `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46` | F4 |
| Window | T = 1,024 tokens | F7, parameters.md |
| Decode speed | 0.60 to 0.62 s per token | F22 |
| Proof generation | 58.8 s per request (1 per batch) | F23 |
| Proof cost | 71.4 to 93.0× vLLM prefill GPU time | F23 |
| Verification | 21 s single thread, 36-44 s shared VM | F26 |
| Proof size | 18.78 MB average | F25 |

See `specs/facts-register.md` for complete F1-F40 list.

## Architecture

From `specs/architecture.md`:

- **Gateway**: OpenAI-compatible API, greedy-only policy, receipt generation
- **Engine**: vLLM with FlashProve integer model, integrity gates
- **Log**: RFC 6962 Merkle tree, Ed25519 signatures
- **Auditor**: Challenge processing, automated sampling
- **Prover**: FlashProve ZK proofs
- **Verifier**: Standalone client verification

## Security Model

From `specs/guarantee.md`:

- **Adversaries**: A1 (Provider), A2 (Gateway/Log), A3 (Auditor), A4 (Client), A5 (Network)
- **Properties**: S1 (Binding), S2 (Unpredictable selection), S3 (Non-omission), S4 (Soundness), S5 (Accountable failure), S6 (Confidentiality), S7 (Availability)

## Milestones

From `specs/build-plan.md`:

- **M0**: Bring-up (engine with integer model)
- **M1**: Gateway and log
- **M2**: Auditor
- **M3**: Red team (R1-R19 attacks)
- **M4**: Router and soak

## Essential Specifications

Read these before working on any component:

- `specs/facts-register.md`: Source of truth for all measurements
- `specs/parameters.md`: System configuration
- `specs/guarantee.md`: Security properties
- `specs/architecture.md`: Component boundaries
- Component-specific: `specs/gateway-api.md`, `specs/engine.md`, etc.

## Common Pitfalls

1. **Inventing numbers**: Every metric must cite facts-register.md or a spec
2. **Adding features**: Only implement what the spec describes
3. **Weakening constraints**: Greedy-only is mandatory, T=1024 is fixed
4. **Design elaborations**: Mark clearly as "proposed" or remove

## Questions or Conflicts

If specifications conflict or are unclear:
1. facts-register.md is authoritative for measurements
2. parameters.md is authoritative for configuration
3. Open an issue rather than guessing

When in doubt, read the spec again. Do not proceed with invented assumptions.
