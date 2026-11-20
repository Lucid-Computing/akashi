# Service roles on Linux

These systemd profiles provision role boundaries for the gateway components.
The host operator supplies the pinned engine environment and the service
executables. Use the engine and proxy profiles together on the dedicated
provider host. The other instances belong on the nodes assigned to those
roles. [Service boundaries](../../docs/spec/01-architecture.md#service-boundaries)
and [file permissions](../../specs/hardening.md#file-permissions) define the requirements.

## Install the profiles

1. Install `vig.sysusers` as `/usr/lib/sysusers.d/vig.conf` and `vig.tmpfiles`
   as `/usr/lib/tmpfiles.d/vig.conf`. Run `systemd-sysusers vig.conf`, then
   `systemd-tmpfiles --create vig.conf`. Each `vig-ROLE` account has its own
   group, disabled login and private key directory. Keep `/etc/vig` and
   `/prover` owned by root and inaccessible for writes by service accounts.
2. Install `vig@.service`, `vig-engine-firewall.service` and the corresponding `vig@*.service.d` directories
   under `/etc/systemd/system/`. Install `check-keys.py` under
   `/usr/local/libexec/vig/`. Keep units, executables and their parent
   directories owned by root and writable only by root.
3. Provision each service's private credentials as regular files in
   `/etc/vig/keys/ROLE/`, owned by its account with mode 0600. Source key
   material from the site's secret store. For the prover, provision
   `/prover/keys` on a local disk, with mode 0700 for every directory and
   0400 for each key file, owned by `vig-prover`. Startup checks ownership,
   permissions, file type and link count. The prover sees its key tree
   through a read-only mount. Publish the verification key archive outside
   these credential directories.
4. Install each selected service's executable as `/usr/local/libexec/vig/ROLE`.
   The engine executable accepts `--host 127.0.0.1 --port 8000` and must
   preserve those arguments when launching the pinned vLLM with the gates
   and flags in the [engine specification](../../specs/engine.md#launch-configuration).
   Provision the Python environment under `/opt/vig/engine` and the model
   and reference assets under root-owned `/models` on read-only storage.
   The unit gives the engine a clean environment and a read-only bind mount.
   Grant the engine and prover accounts the GPU access required on their hosts.
   Provision the prover's writable `/prover/spool` and the proof worker's
   required `/usr/local/libexec/vig/stop-prover` hook. The hook must signal
   the spool stop file and wait for the proof process to exit (F23).
5. On the engine host, install the supplied [HAProxy configuration](../engine-proxy/engine-proxy.cfg)
   as `/etc/vig/engine-proxy.cfg`. In root-owned `/etc/vig/proxy.conf`, set
   `VIG_PROXY_LISTEN` to the private listener address and port,
   `VIG_PROXY_CERT` to the proxy's certificate and private key PEM file,
   `VIG_GATEWAY_CA` to the client CA file, and `VIG_GATEWAY_CERT_SHA256` to
   the SHA-256 of the authorized client certificate in DER format.
   Set `VIG_ENGINE_PORT=8000` and configure `VIG_PROXY_CONNECT_TIMEOUT`
   and `VIG_PROXY_IO_TIMEOUT` for the deployment. Keep key bytes in the
   proxy's role-owned credential files.
6. Install `engine.nft` as root-owned `/etc/vig/engine.nft`. Include it in the
   site's persistent nftables ruleset *after* the accounts exist. Validate the
   complete ruleset with `nft --check -f /etc/nftables.conf`, load
   it and confirm `nft list table inet vig_engine`. The rule admits local
   connections to the plaintext engine port only from the proxy UID.
   Each engine start requires the firewall unit to install its rules
   successfully, even if the site omitted the include during boot. Run
   `systemctl daemon-reload` before starting the provisioned units. Keep
   FlashProve under its service UID throughout its lifetime.

## Verify isolation

`make test-service-boundaries` checks Unix file modes, service identities,
mTLS routing and the key archive. On a disposable Linux runner with systemd
tools, HAProxy, nftables, iproute2 and util-linux installed, run
`sudo bash deploy/service-roles/test-linux.sh`. It provisions accounts and
directories under a temporary root, checks the units with `systemd-analyze`
and exercises allowed and denied loopback connections in a fresh network
namespace. The unit syntax check substitutes a test executable for the
host-supplied daemon and stop hook.
