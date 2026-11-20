#!/usr/bin/env bash
# Run as root only inside a disposable Linux CI runner.
set -euo pipefail
cd -- "$(dirname -- "$0")"
sandbox=$(mktemp -d)
trap 'rm -rf -- "$sandbox"' EXIT
stage="$sandbox/root"
mkdir -p "$stage/etc" "$stage/usr/lib"/{sysusers.d,tmpfiles.d,systemd/system}
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$stage/etc/passwd"
printf 'root:x:0:\n' > "$stage/etc/group"
install -m644 vig.sysusers "$stage/usr/lib/sysusers.d/vig.conf"
install -m644 vig.tmpfiles "$stage/usr/lib/tmpfiles.d/vig.conf"
systemd-sysusers --root="$stage"
systemd-tmpfiles --root="$stage" --create
for role in gateway engine proxy log sampler escrow pickup auditor prover verifier; do
    entry=$(awk -F: -v user="vig-$role" '$1==user {print $3 ":" $4}' "$stage/etc/passwd")
    [[ "$entry" != 0:* && -n "$entry" ]]
    [[ $(stat -c '%u:%g %a' "$stage/etc/vig/keys/$role") == "$entry 700" ]]
done
prover_uid=$(stat -c %u "$stage/etc/vig/keys/prover")
[[ $(stat -c '%u %a' "$stage/prover/keys") == "$prover_uid 700" ]]

# Verify the actual units against host utilities and a harmless stand-in for
# the operator-supplied daemon. systemd-analyze does not launch services.
units="$sandbox/units"
mkdir "$units"
cp vig@.service "$units/"
cp vig-engine-firewall.service "$units/"
cp -R vig@*.service.d "$units/"
sed -i 's|^ExecStart=/usr/local/libexec/vig/%i$|ExecStart=/usr/bin/true|' "$units/vig@.service"
sed -i 's|^ExecStop=/usr/local/libexec/vig/stop-prover$|ExecStop=/usr/bin/true|' "$units/vig@prover.service.d/isolation.conf"
for role in engine log proxy prover; do
    cp "$units/vig@.service" "$units/vig@$role.service"
done
SYSTEMD_UNIT_PATH="$units:" systemd-analyze verify "$units/vig-engine-firewall.service" "$units"/vig@{engine,log,proxy,prover}.service

# Resolve the proxy's UID from the isolated account database before loading the
# real rule into its own network namespace; host NSS contains no test accounts.
proxy_uid=$(stat -c %u "$stage/etc/vig/keys/proxy")
proxy_gid=$(stat -c %g "$stage/etc/vig/keys/proxy")
sed "s/\"vig-proxy\"/$proxy_uid/g" engine.nft > "$sandbox/engine.nft"
unshare --net -- bash -eu -c '
    ip link set lo up
    nft -f "$1"
    nft -f "$1"
    python3 - "$2" "$3" <<"PY"
import socketserver
import subprocess
import sys
import threading

class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"ok")

with socketserver.TCPServer(("127.0.0.1", 8000), Backend) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = ["python3", "-c", "import socket; s=socket.create_connection((\"127.0.0.1\",8000)); assert s.recv(2)==b\"ok\""]
    allowed = subprocess.run(["setpriv", "--reuid", sys.argv[1], "--regid", sys.argv[2], "--clear-groups", *client])
    denied = subprocess.run(client, stderr=subprocess.DEVNULL)
    assert allowed.returncode == 0 and denied.returncode != 0
PY
' _ "$sandbox/engine.nft" "$proxy_uid" "$proxy_gid"
