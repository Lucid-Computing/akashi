# Run the CPU router demo

From the repository root, run the demo on a CPU.

```bash
make setup demo-router
```

The demo starts a loopback router in a separate process, a gateway with the pinned chat renderer and mock engine, an encrypted escrow, a signed Merkle log and the SQLite-backed sealed pickup service. The gateway writes envelopes into a private temporary database. A separate reader serves them over the rate-limited, no-store pickup endpoint. It fetches two digest-checked public tokenizer files on demand. For an offline run, set `AKASHI_RENDER_ASSETS` to the directory containing the pinned `tokenizer.json` and `tokenizer_config.json`.

| Router mode | What the holder observes |
| --- | --- |
| `opaque` | The completion has text only in its message and omits the receipt header and verification extension. The holder derives the pickup ID from its original messages, budget, displayed text and secret, opens the sealed envelope, and verifies the promise and log inclusion. |
| `transparent` | The holder receives the verification object and receipt header and checks both against the recovered envelope. |
| `rewrite-messages` | The router replaces the final message content. The holder's original inputs yield an unknown pickup ID. |
| `inject-sampling` | The router injects a non-greedy temperature. The gateway returns HTTP 400 before creating a receipt. |

The demo first verifies a direct completion. It then exercises all four router modes and repeats transparent and opaque delivery with gateway streaming enabled. The holder waits for a finishing event and `[DONE]`, opens the envelope using the exact displayed text, verifies the signed promise and transcript commitment, and checks inclusion against a signed tree head. A different secret fails both lookup and decryption.

A successful run prints `"status": "passed"`, `"pickup_store": "sqlite"` and `"logged": 6`. The report limits its output to counts and check results. It records OQ3/OQ4 for this local mock router. For real proof verification on a separate CPU, see the [recorded Maverick run](../docs/demo/README.md). [Router contract](../docs/rfcs/RFC-0010-router-pickup.md#proposed-design)

## Connect to an existing gateway

For a gateway listening on local port 8000, the following example starts an opaque router on port 8080. Choose a socket timeout appropriate to your deployment.

```bash
uv run --locked python -m router.mock \
  --upstream http://127.0.0.1:8000 --port 8080 \
  --mode opaque --timeout-seconds 180
```

Send the usual `POST /v1/chat/completions` to `http://127.0.0.1:8080` with the gateway's bearer credential. The router forwards that credential to its configured upstream. It preserves the original request bytes in transparent and opaque modes. The process binds to loopback, prints its listening port once and omits access logs. Stop it with Ctrl-C. Port 0 selects a free port. The router also forwards `GET /router/models`, which lists the gateway's advertised model, context window, completion budget and greedy constraints. The feed includes `stream` only when the gateway has a configured SSE heartbeat. [Provider feed](../specs/router-integration.md#provider-feed)

For streaming upstreams, transparent mode preserves complete SSE frames. Opaque mode strips the verification member from JSON data events and passes through comments and the upstream's final `[DONE]`. A holder recovers evidence through pickup. Run `make test-router` for the HTTP transport, holder and forwarding controls.
