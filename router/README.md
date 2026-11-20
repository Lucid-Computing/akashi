# Run the local router POC

From the repository root, run the demo on a CPU.

```bash
make setup demo-router
```

The demo starts a loopback router in a separate process, a gateway with the pinned chat renderer and mock engine, an encrypted escrow, a signed Merkle log and a test pickup service. It fetches two digest-checked public tokenizer files on demand. For an offline run, set `VIG_RENDER_ASSETS` to the directory containing the pinned `tokenizer.json` and `tokenizer_config.json`.

| Router mode | What the holder observes |
| --- | --- |
| `opaque` | The completion has text only in its message and omits the receipt header and verification extension. The holder derives the pickup ID from its original messages, budget, displayed text and secret, opens the sealed envelope, and verifies the promise and log inclusion. |
| `transparent` | The holder receives the verification object and receipt header and checks both against the recovered envelope. |
| `rewrite-messages` | The router replaces the final message content. The holder's original inputs yield an unknown pickup ID. |
| `inject-sampling` | The router injects a non-greedy temperature. The gateway returns HTTP 400 before creating a receipt. |

A successful run exits zero and prints a JSON summary. It also checks that a different secret cannot recover the receipt. This fixture uses an in-memory ciphertext store and synthetic inference. It demonstrates OQ3/OQ4 on the local route. Model conformance requires the independent proof and verifier gates. [Router contract](../docs/rfcs/RFC-0010-router-pickup.md#proposed-design)

## Connect to an existing gateway

For a gateway listening on local port 8000, the following example starts an opaque router on port 8080. Choose a socket timeout appropriate to your deployment.

```bash
uv run --locked python -m router.mock \
  --upstream http://127.0.0.1:8000 --port 8080 \
  --mode opaque --timeout-seconds 180
```

Send the usual `POST /v1/chat/completions` to `http://127.0.0.1:8080` with the gateway's bearer credential. The router forwards that credential to its configured upstream. It preserves the original request bytes in transparent and opaque modes. The process binds to loopback, prints its listening port once and omits access logs. Stop it with Ctrl-C. Port 0 selects a free port. The router also forwards `GET /router/models`, which lists the gateway's advertised model, context window, completion budget and greedy constraints. [Provider feed](../specs/router-integration.md#provider-feed)

For streaming upstreams, transparent mode preserves complete SSE frames. Opaque mode strips the verification member from JSON data events and passes through comments and the upstream's final `[DONE]`. A holder recovers evidence through pickup. Run `make test-router` for the HTTP transport, holder and forwarding controls.
