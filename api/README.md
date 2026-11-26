# Akashi platform API

One Cloudflare Worker serves the [web preview](../web/README.md) and this API at `akashi.lucidcomputing.ai`. It takes challenges, keeps one proof job per challenged reply in D1, and hands those jobs to the GPU provers. **The provers are mocked for now:** the cron plays two H100s and writes sample outcomes. No proof is generated or checked.

## How it fits

```text
challenger ──POST /challenges──▶ Worker ──▶ D1: challenges, jobs
                                   ▲
H100 worker ──claim, then result───┘   (the GPUs pull: they need outbound HTTPS only)
```

- **A challenge** names a logged reply by its `request_id`, with a role (`holder`, `regulator`, `auditor`, `thirdparty`), a reason (`model`, `altered`, `routine`) and an optional public note. The bearer key identifies the challenger and is stored only as its SHA-256.
- **Quotas** are those of [the parameters](../specs/parameters.md#rate-limits): 10 per key per hour and 3 per reply per day. A refusal answers 429 with `Retry-After`.
- **One job per reply.** Every challenge on the same reply shares its proof, so the GPUs prove each reply once. A reply whose proof was unavailable is queued again by its next challenge.
- **Leases.** A GPU claims the oldest job under a lease (`LEASE_MS`) and reports the result with that lease. A lease that runs out returns the job to the queue. After `MAX_ATTEMPTS` the outcome is `unavailable`. Both are deployment choices in `wrangler.jsonc`, not spec values.

A challenge reads `queued`, then `proving` while a GPU holds its job, then `settled` with an `outcome` of `conformant`, `deviation` or `unavailable`.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `GET /api/v1/challenges?limit=20` | Anyone | The most recent challenges, newest first |
| `GET /api/v1/challenges/:id` | Anyone | One challenge and its proof job |
| `POST /api/v1/challenges` | A challenger, `Authorization: Bearer <key>` | File a challenge: `{request_id, role, reason, note?}` |
| `POST /api/v1/prover/claim` | A GPU, `Authorization: Bearer <PROVER_TOKEN>` | `{worker}`. Returns `{request_id, lease, lease_until}`, or 204 when the queue is empty |
| `POST /api/v1/prover/jobs/:request_id` | A GPU, `Authorization: Bearer <PROVER_TOKEN>` | `{lease, outcome, proof_digest, proof_ms}`. 409 when the lease is no longer current |

## What is not real yet

- **The GPU link.** `src/mock-gpu.ts` stands in for the H100s, through the same claim and complete calls a real worker makes. To use the real machines, run a worker loop on each H100 against the two prover routes, give it `PROVER_TOKEN`, and set `MOCK_GPUS` to `"0"`.
- **The checks.** Intake trusts the `request_id` and the declared role. The real intake verifies the holder's receipt bundle and the challenger's key before admitting anything, and the verdict is signed. That logic lives in the Python [auditor](../auditor/README.md) and [prover](../prover/README.md). The job sent to a GPU carries only the `request_id`, not the escrowed transcript.

## Work on it

Node 24.

```sh
cd api
npm ci
npm run check     # types, then the tests in the Workers runtime
npm run dev       # local D1, the site and the API on http://localhost:8787
```

Put `PROVER_TOKEN=<anything of 16 characters or more>` in `api/.dev.vars` to call the prover routes locally. To run the cron by hand, open `http://localhost:8787/__scheduled?cron=*+*+*+*+*`.

## Deploy

Cloudflare builds and deploys `main` on every push (Workers Builds, connected to this repository). The settings are:

| Setting | Value |
| --- | --- |
| Root directory | `api` |
| Build command | `npm ci` |
| Deploy command | `npm run deploy` (applies new D1 migrations, then deploys) |

The custom domain is declared in `wrangler.jsonc`, so a deploy creates its DNS record in the `lucidcomputing.ai` zone. Set the prover token once with `npx wrangler secret put PROVER_TOKEN`.
