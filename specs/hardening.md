# Security Hardening

## Overview

Security hardening checklist from specification section 17.

## Service Accounts and Privileges

### Principle of Least Privilege

- Run every service as its own non-root account
- FlashProve programs NEVER under `sudo` (F14)
- Each service has its own keys and credentials
- Separate service accounts for: gateway, log, sampler, escrow, pickup, auditor, prover, verifier

### File Permissions

```bash
# Model directory
chmod 444 /models/*/weights/*  # Read-only
chown root:root /models/        # Owned by root
mount -o ro /models/            # Mount read-only

# Keys
chmod 600 /keys/*               # Owner read/write only
chown service:service /keys/    # Owned by service account

# Prover key directories
chmod 700 /prover/keys/         # Local disk, one account
chown prover:prover /prover/keys/
```

## vLLM Engine Hardening

### Known Vulnerabilities

vLLM 0.29.0 has about forty published advisories (F32):
- Every fixed advisory is fixed by 0.31.0
- Engine reachable only from gateway over mTLS
- Behind two-route allow-list proxy

### Network Isolation

```
Engine listens on 127.0.0.1:8000 only
        ↓
Reverse proxy (mTLS from gateway)
  - Allow: POST /v1/completions
  - Allow: GET /health
  - Deny: everything else (including /metrics, /invocations, /generative_scoring)
        ↓
Gateway (authenticated client)
```

Routes closed at proxy:
- `/metrics` (F19: answers without API key)
- `/invocations` (F19: answers without API key)
- `/generative_scoring` (F19: answers without API key)
- All admin endpoints

### Environment Restrictions

```bash
# Clean environment (F14)
CUDA_VISIBLE_DEVICES=0
VLLM_USE_V2_MODEL_RUNNER=1
VLLM_NO_USAGE_STATS=1
PYTHONSAFEPATH=1
GLOO_SOCKET_IFNAME=lo
HOME=/var/lib/engine
TMPDIR=/var/tmp/engine

# Never set (F14)
# VLLM_SERVER_DEV_MODE
# VLLM_MODEL_REDIRECT_PATH
# VLLM_LOGGING_LEVEL (use default)

# Model directory read-only
mount -o ro /models
```

### Trust Remote Code

MUST be disabled:
- No `--trust-remote-code` flag (F14)
- No execution of code from model repository
- Tokenizer with `trust_remote_code=False`

## Prover Hardening

### Key Management

```bash
# Key directories on local disk
/prover/keys/ivk/
  ├── key.bin          # chmod 400, prover:prover
  └── leaf/
      └── 0.bin        # chmod 400, prover:prover

# Configuration files
/prover/config/
  ├── policy.txt       # Public
  ├── KL.bin           # Public
  └── layout.txt       # Public
```

### Process Control

```bash
# Stop prover with spool's stop file, never kill (F23)
echo 1 > /prover/spool/stop

# Wait for graceful shutdown
wait_for_process_exit cp_prove

# Never: kill -9 cp_prove
```

### Build Verification

```bash
# Production build only
cp_verify --version
# Output includes build word, recorded in each verdict

# Supply chain
pip-audit --require-hashes
# Runs in CI against FlashProve's lock file
```

### GPU Constraints

```bash
# cp_prove refuses GPU with > 2 GiB in use (F27)
# Stop engine before proving in single-GPU mode
# Or use dedicated GPU for prover
```

## Gateway Hardening

### Input Validation

```python
# Body limit
MAX_BODY_SIZE = 256 * 1024  # 256 KiB

# Header limits
MAX_HEADER_SIZE = 8192
MAX_HEADERS = 100

# Parameter validation
def validate_request(req):
    # Strict whitelist (spec section 5.2)
    # Reject unknown fields
    # Validate ranges
    # Sanitize strings
```

### Rate Limiting

From spec § 17:

```python
# Per endpoint
rate_limit("/v1/chat/completions", requests=Q_max, window="concurrent")

# Challenge API (per holder key)
rate_limit("/v1/challenges", requests=10, window="1h", key="holder_key")
rate_limit("/v1/challenges", requests=3, window="1d", key="transcript_hash")
```

Proposed (not in spec): per-API-key rate limits for gateway endpoints.

### Queue Management

```python
Q_max = 4  # Maximum waiting requests

if queue_depth >= Q_max:
    return 429, {"error": "queue_full", "Retry-After": 30}
```

## Audit API Hardening

### Capability Tokens

Proofs require capability token from challenge submission:

```python
# Challenge submission returns token
challenge_id, token = submit_challenge(bundle)

# Proof download requires token
GET /audit/v1/challenges/{challenge_id}/proof
Authorization: Bearer {token}
```

### Rate Limiting

```python
# Pickup store
rate_limit("/receipts/v1/pickup/*", requests=100, window="1h", key="ip")

# Audit API
rate_limit("/audit/v1/*", requests=1000, window="1h", key="ip")

# No listing endpoints for pickups or proofs
```

## Secrets Management

### Storage

```bash
# Secrets in files, mode 0600
/keys/log_key          # Ed25519 for log
/keys/auditor_key      # Ed25519 for verdicts
/keys/gateway_tls.*    # X.509 for HTTPS
/keys/engine_mtls.*    # X.509 for engine mTLS

# Never in:
# - Command lines (visible in ps)
# - Environment variables (logged)
# - Version control (git)
# - Application logs
```

### Key Rotation

```python
# New key gets new key ID
new_key_id = generate_key_id()
write_key(f"/keys/{component}_{new_key_id}", new_key)

# Old key stays valid for verification
# Publish both key IDs in /.well-known/vig.json
```

## Supply Chain Security

### Dependency Pinning

```bash
# Exact versions in requirements.txt
vllm==0.29.0
flashprove @ git+https://github.com/...@9e2bdd8ff5bf9c62f18263d7dac189b0400b260c

# Hash verification
pip install --require-hashes -r requirements.txt
```

### Build Reproducibility

```bash
# Record build info
cp_verify --version > /etc/verified-gateway/build-info
# Build word appears in verdicts
```

### Vulnerability Scanning

```bash
# CI pipeline
pip-audit --require-hashes
trivy image gateway:latest
snyk test
```

## Audit Logging

### Security Events

Log at ERROR or WARN:
- Unwarranted replies
- Range failures
- Prover failures
- Verification failures
- Beacon unavailable
- Rate limit hits
- Invalid authentication
- Proof download attempts (with capability check result)

### Log Format

```json
{
  "timestamp": "...",
  "level": "ERROR",
  "event": "unwarranted_reply",
  "request_id": "...",
  "reason": "range_failure",
  "component": "gateway"
}
```

No sensitive data in logs:
- Never prompt or reply content
- Never API keys
- Never secrets

## Penetration Testing

Before production:
1. Red team suite (spec section 19)
2. External penetration test (recommended)
3. Dependency audit
4. Key management audit
5. Network isolation verification

## Monitoring for Attacks

### Indicators

- Spike in unwarranted replies (potential model swap)
- Unusual request patterns (potential reconnaissance)
- Challenge flood (potential DoS)
- Receipt replay attempts (detected by log)
- Beacon manipulation attempts (verifier checks signature)

### Response

On security event:
1. Alert security team
2. Log full context
3. Rate limit offending source
4. Escalate if pattern detected
5. Preserve evidence for analysis

## Compliance Checklist

Before deployment:

- [ ] All services run as non-root
- [ ] Keys are mode 0600, owned by service account
- [ ] Model directory is read-only
- [ ] Engine behind mTLS + allow-list
- [ ] No `--trust-remote-code`
- [ ] vLLM advisories reviewed
- [ ] Secrets not in code or logs
- [ ] Supply chain verified
- [ ] Red team suite passes
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Backup and recovery tested

## Related Specifications

- `guarantee.md`: Security properties S1-S7
- `engine.md`: Engine configuration F14
- `audit-protocol.md`: Proof handling F40
- `observability.md`: Security logging and alerts
- `redteam-suite-spec.md`: Attack vectors R1-R19
