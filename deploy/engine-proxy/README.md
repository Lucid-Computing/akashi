# Engine proxy

Run HAProxy as `vig-proxy` on the engine host. The vLLM launcher and host firewall must restrict the upstream to the proxy account on `127.0.0.1:8000`. Publish the TLS listener on the private gateway network. [Engine network contract](../../specs/engine.md#network-exposure) · [Host service roles](../service-roles/)

Install `engine-proxy.cfg` at `/etc/vig/engine-proxy.cfg`. Supply the following values in the `vig@proxy.service` environment file at `/etc/vig/proxy.conf`. Keep the configuration and trust anchors under host administrator control.

| Variable | Deployment value |
| --- | --- |
| `VIG_PROXY_LISTEN` | Private interface address and port reachable by the gateway |
| `VIG_PROXY_CERT` | Absolute path to a PEM containing the proxy's TLS server certificate, chain and private key. Restrict access to the proxy role. The certificate SAN must match the hostname the gateway connects to. |
| `VIG_GATEWAY_CA` | Absolute path to the CA PEM used to validate gateway client certificates |
| `VIG_GATEWAY_CERT_SHA256` | 64 hexadecimal digits identifying the authorized gateway leaf certificate, computed over its DER bytes |
| `VIG_PROXY_CONNECT_TIMEOUT` | Operator-configured HAProxy connect timeout with duration unit |
| `VIG_PROXY_IO_TIMEOUT` | Operator-configured HAProxy client and server inactivity timeout with duration unit. Allow for engine execution within the configured request budget. |

Obtain the gateway certificate fingerprint using its public certificate.

```sh
openssl x509 -in gateway-client.pem -outform DER | openssl dgst -sha256
```

Set the fingerprint to the digest portion of the output. With the service environment loaded, run `haproxy -c -f /etc/vig/engine-proxy.cfg` before starting `vig@proxy.service`. The shipped host rules use upstream port 8000. The integration test supplies an ephemeral port through `VIG_ENGINE_PORT`.

On the gateway, set `ENGINE_URL` to the private HTTPS origin and provide the proxy CA and gateway client credential files. This probe verifies the server certificate and presents the configured client identity.

```sh
curl --fail --silent --show-error --noproxy '*' \
  --cacert "$PROXY_CA" --cert "$GATEWAY_CLIENT_CERT" --key "$GATEWAY_CLIENT_KEY" \
  "$ENGINE_URL/health"
```

The proxy accepts one active connection and forwards exactly `GET /health` and `POST /v1/completions`. When replacing a gateway credential, validate the replacement configuration and restart the proxy so sessions authenticated under the previous credential end. Run `make test-service-boundaries` for the real TLS and route checks.
