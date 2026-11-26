# Specifications

Complete technical specifications for Akashi, the verified inference gateway.

All specifications source their facts from `facts-register.md` and `parameters.md`. No invented numbers.

## Core Specifications

### Security and Guarantee

| Specification | Description |
|---|---|
| [guarantee.md](./guarantee.md) | Security guarantee, threat model (A1-A5), security properties (S1-S7) |
| [facts-register.md](./facts-register.md) | F1-F40: Source of truth for all measurements and verified facts |
| [glossary.md](./glossary.md) | Terms: commitment ID, conformance proof, deviation proof, receipt, STH, render profile |

### System Parameters

| Specification | Description |
|---|---|
| [parameters.md](./parameters.md) | System parameters: T=1024, C, E, sampling rates, timeouts, beacon config |

### Architecture

| Specification | Description |
|---|---|
| [architecture.md](./architecture.md) | Component boundaries, data flow, fast/slow paths, deployment models |

## API and Integration

| Specification | Description |
|---|---|
| [gateway-api.md](./gateway-api.md) | HTTP endpoints, request policy, error codes, response format, Mode D/R |
| [canonical-rendering.md](./canonical-rendering.md) | Tokenization, chat templates, render profile llama4-chat/1 |
| [router-integration.md](./router-integration.md) | Mode R patterns, discovery, receipt delivery, timeouts |

## Components

| Specification | Description |
|---|---|
| [engine.md](./engine.md) | vLLM integration, model files, launch config, integrity gates, start-up checks |
| [sampling.md](./sampling.md) | drand beacon, selection rule, shadow requests, escrow timeline |
| [receipt-log.md](./receipt-log.md) | Merkle tree, transcript commitment, STH, promise protocol, sealed pickup |
| [audit-protocol.md](./audit-protocol.md) | Challenge flow, conformance/deviation proofs, verification, verdicts |
| [verifier-kit.md](./verifier-kit.md) | 6-step verification, exit codes (0/10/11/12/13/20/21/30/64), second verifier, distribution |

## Performance and Operations

| Specification | Description |
|---|---|
| [capacity.md](./capacity.md) | Throughput, latency, resource requirements (sourced from F22-F27) |
| [deterrence.md](./deterrence.md) | Detection probability formulas, adversary scenarios |
| [retention.md](./retention.md) | Data retention policies (5 years receipts, 30 days pickup) |
| [observability.md](./observability.md) | Metrics, alerts, dashboards |
| [hardening.md](./hardening.md) | Security checklist, configuration, rate limits |

## Development

| Specification | Description |
|---|---|
| [build-plan.md](./build-plan.md) | Milestones M0-M4 with exit criteria and tests |
| [open-questions.md](./open-questions.md) | OQ1-OQ9: Questions to resolve during milestones |
| [redteam-suite.md](./redteam-suite.md) | Attack vectors R1-R19, test scenarios, success criteria |

## Reading Guide

### For Understanding the Guarantee

Start here:
1. `guarantee.md` - What we prove and to whom
2. `facts-register.md` - Performance and capabilities (F1-F40)
3. `parameters.md` - System configuration
4. `deterrence.md` - Detection probabilities

### For Implementing Components

Gateway:
1. `gateway-api.md` - API specification
2. `canonical-rendering.md` - Tokenization
3. `engine.md` - Engine integration
4. `receipt-log.md` - Receipt generation

Auditor:
1. `sampling.md` - Selection protocol
2. `audit-protocol.md` - Challenge processing
3. `verifier-kit.md` - Proof verification

### For Integration

Router integration (Mode R):
1. `router-integration.md` - Discovery and patterns
2. `gateway-api.md` - Endpoint details
3. `receipt-log.md` - Sealed pickup

Client verification:
1. `verifier-kit.md` - 6-step procedure
2. `receipt-log.md` - Receipt format
3. `canonical-rendering.md` - Decode reply

### For Development

1. `build-plan.md` - Milestones and exit criteria
2. `architecture.md` - Component boundaries
3. `hardening.md` - Security checklist
4. `redteam-suite.md` - Attack testing
5. `observability.md` - Metrics and alerts

## Verification

All specifications verified for:
- **Sourced numbers**: Every performance figure from facts-register.md
- **No em dashes**: Only standard hyphens used
- **Internal consistency**: Cross-references resolve
- **Forbidden terms removed**: No internal context (company names, person names, partners)

Last verified: 2026-11-20

## Related Documents

- `../README.md` - Repository overview
- `../AGENTS.md` - AI assistant guidelines
- `../docs/decisions/001-greedy-only-constraint.md` - ADR on temperature=0 requirement
- Component READMEs: `../gateway/`, `../engine/`, `../log/`, `../auditor/`, `../prover/`, `../verifier/`, `../redteam/`

## Status

| Specification | Status | Last Updated |
|---|---|---|
| guarantee.md | Complete | 2026-11-20 |
| facts-register.md | Complete | 2026-11-20 |
| glossary.md | Complete | 2026-11-20 |
| parameters.md | Complete | 2026-11-20 |
| architecture.md | Complete | 2026-11-20 |
| gateway-api.md | Complete | 2026-11-20 |
| canonical-rendering.md | Complete | 2026-11-20 |
| router-integration.md | Complete | 2026-11-20 |
| engine.md | Complete | 2026-11-20 |
| sampling.md | Complete | 2026-11-20 |
| receipt-log.md | Complete | 2026-11-20 |
| audit-protocol.md | Complete | 2026-11-20 |
| verifier-kit.md | Complete | 2026-11-20 |
| capacity.md | Complete | 2026-11-20 |
| deterrence.md | Complete | 2026-11-20 |
| retention.md | Complete | 2026-11-20 |
| observability.md | Complete | 2026-11-20 |
| hardening.md | Complete | 2026-11-20 |
| build-plan.md | Complete | 2026-11-20 |
| open-questions.md | Complete | 2026-11-20 |
| redteam-suite.md | Complete | 2026-11-20 |

All 21 specifications complete.
