# Verified Inference Gateway v1

A holder can check that a delivered reply was bound to a public log and can independently verify an audit against one committed integer model. The prototype combines post-delivery sampling with holder challenges. A promise, an inclusion check, and a verified proof convey different evidence.

The [facts register](specs/facts-register.md#facts-register) governs measurements. [Parameters](specs/parameters.md#fixed-parameters) govern configuration. The contracts and accepted RFCs below resolve conflicting examples in the original `specs/` documents. The [build plan exit tests](specs/build-plan.md#milestone-structure) govern release evidence.

## Specification

- [Overview and scope](docs/spec/00-overview.md#release-scope)
- [Architecture](docs/spec/01-architecture.md#service-boundaries)
- [Public API](docs/spec/02-public-api.md#interfaces)
- [Data model](docs/spec/03-data-model.md#wire-types)
- [Errors](docs/spec/04-error-model.md#failure-contract)
- [Observability](docs/spec/05-observability.md#telemetry-contract)
- [Security](docs/spec/06-security.md#trust-and-evidence)
- [Testing](docs/spec/07-testing-strategy.md#release-gates)
- [Capacity](docs/spec/08-performance-budget.md#measurement-contract)
- [Release and versioning](docs/spec/09-release-and-versioning.md#release-policy)
- [Glossary](docs/spec/10-glossary.md#terms)

## Decisions

See the [RFC index](docs/rfcs/README.md#accepted-decisions) for subsystem decisions and milestone owners.
