# Glossary

## Terms

**Commitment ID (C)**: 32-byte fingerprint that binds the model weights and the three configuration files.

**Conformance proof**: An accepted exact-match proof that every reply token is the model's greedy choice.

**Deviation proof**: An accepted exact-match proof that the model's greedy token at one position differs from the served token.

**Receipt**: The signed record of a reply's transcript commitment, returned at delivery.

**Signed entry promise**: The log's signed promise to include a leaf within MMD (maximum merge delay).

**STH**: Signed tree head of the receipt log.

**Render profile**: The pinned tokenizer, chat template and rules that turn `messages` into prompt token IDs.

**Holder**: Whoever holds a transcript and its receipt.

## Abbreviations

**MMD**: Maximum merge delay (10 s)

**STH**: Signed tree head

**VK**: Verifier kit

**ZK**: Zero knowledge

## Parameters

**T**: Window size, prompt plus reply (1,024 tokens)

**C**: Commitment ID (`c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46`)

**E**: End-token IDs ([200001, 200007, 200008])

**z**: Padding token (0)

**r**: Sampling rate (1/N, where N ∈ {1, 20, 1,000})

**P**: Prompt length (number of tokens)

**R**: Reply length (number of tokens)

## Component Abbreviations

**GW**: Gateway

**EN**: Engine (vLLM with integer model plug-in)

**LG**: Receipt log

**PK**: Pickup store (sealed receipts)

**ES**: Transcript escrow

**SM**: Sampler (beacon-based selection)

**CH**: Challenge service

**PW**: Prover worker (FlashProve)

**RX**: Reference scorer (integer model for deviation detection)

**VF**: Verification (`cp_verify`)

**VD**: Verdict signer

**AU**: Audit API

**VK**: Verifier kit

**RT**: Red team harness

## RFC 2119 Keywords

As used throughout specifications:

**MUST**, **REQUIRED**, **SHALL**: Absolute requirement

**MUST NOT**, **SHALL NOT**: Absolute prohibition

**SHOULD**, **RECOMMENDED**: May exist valid reasons to ignore, but implications must be understood

**SHOULD NOT**, **NOT RECOMMENDED**: May exist valid reasons, but implications must be understood

**MAY**, **OPTIONAL**: Truly optional
