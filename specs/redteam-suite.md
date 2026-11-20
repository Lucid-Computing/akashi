# Red Team Test Suite

From specification section 19.

## Attack Vectors

Test scenarios R1-R19 from spec § 19.1:

| ID | Attack | Expected Outcome |
|---|---|---|
| R1 | Engine serves stock vLLM Maverick FP8 | DEVIATES |
| R2 | Engine serves stock vLLM BF16 | DEVIATES |
| R3 | Engine serves llama.cpp on same GGUF | DEVIATES |
| R4 | Engine serves Llama 4 Scout | DEVIATES |
| R5 | Integer model with one perturbed weight tensor | DEVIATES |
| R6 | Engine forces token mid-reply (logit bias) | DEVIATES |
| R7 | Engine truncates with early end token | DEVIATES |
| R8 | Engine truncates without end token below max_tokens | INCOMPLETE |
| R9 | Gateway tampers: one reply token changed | DEVIATES |
| R10 | System prompt injected into x | VK exit 11, CH INVALID_BUNDLE |
| R11 | Chat template swapped | VK exit 11 |
| R12 | Reply text altered in transit | VK exit 12 |
| R13 | Forged or altered receipt | VK exit 10 |
| R14 | Proof replayed for another transcript | VK exit 20 |
| R15 | Proof under another commitment ID | VK exit 20 or 30 |
| R16 | Promised leaf left out of log | Monitor alert, omission evidence |
| R17 | Promise backdated past 30s tolerance | VK warning, monitor alert |
| R18 | Provider deviates only on long prompts | DEVIATES on every selected long prompt |
| R19 | Challenge flood | 429 after rate limits, queue bounded |

## Exit Criteria

From spec § 19.2:

- Pass criterion met: 100% of attacks caught, 0 false positives
- All 19 attack vectors tested
- Test results documented

## Related Specifications

- `guarantee.md`: Threat model A1-A5, security properties S1-S7
- `verifier-kit.md`: Exit codes (VK exit 10/11/12/20/30)
- `audit-protocol.md`: Challenge protocol (CH outcomes)
- `build-plan.md`: M3 milestone integrating red team tests
