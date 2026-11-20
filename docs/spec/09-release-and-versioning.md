# Release and versioning

## Release policy

Use M0–M4 as issue milestones and release gates. The prototype reaches v1.0.0 when all gates have evidence. Version public packages and the verifier CLI using semantic versioning. Patch releases preserve public behavior except corrections; minor releases can add compatible surfaces; breaking contracts require a major release and an explicit protocol or artifact discriminator. Additive JSON fields may be ignored on read surfaces. Requests subject to strict allowlists require an advertised compatible version before clients send additional fields.

Publish deprecation rationale, replacement and removal version in the changelog and affected docs before removal. Keep historical descriptors, render profiles, verifier inputs and log keys available for existing evidence. Never silently reinterpret old signed bytes. Release notes reference source revision, issues, build evidence and known proof limitations.

## Distribution

Use the repository's existing Apache-2.0 license for project source and inventory third-party notices separately. Publish a clean-install verifier package, dependency locks and the artifact digests. Keep weights and secret material outside distributions. Document release builds, contribution setup and test commands in [CONTRIBUTING](../../CONTRIBUTING.md); replace scaffold commands when the build and test entry points land.

Use exact resolved dependency versions and hashes. Reference engine and proof runtime pins in [parameters](../../specs/parameters.md#version-pinning) and F31. Lock the rendering libraries against golden outputs, the beacon library against verified round fixtures, and HTTP, persistence and crypto libraries against CI on supported targets. The build owners record package selections and precise versions at the dependency gate; the gate blocks release for any floating production dependency.
