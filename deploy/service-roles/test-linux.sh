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
install -m644 akashi.sysusers "$stage/usr/lib/sysusers.d/akashi.conf"
install -m644 akashi.tmpfiles "$stage/usr/lib/tmpfiles.d/akashi.conf"
systemd-sysusers --root="$stage"
systemd-tmpfiles --root="$stage" --create
for role in gateway engine proxy log sampler escrow pickup auditor prover verifier; do
    entry=$(awk -F: -v user="akashi-$role" '$1==user {print $3 ":" $4}' "$stage/etc/passwd")
    [[ "$entry" != 0:* && -n "$entry" ]]
    [[ $(stat -c '%u:%g %a' "$stage/etc/akashi/keys/$role") == "$entry 700" ]]
done
prover_uid=$(stat -c %u "$stage/etc/akashi/keys/prover")
[[ $(stat -c '%u %a' "$stage/prover/keys") == "$prover_uid 700" ]]

# Verify the actual units against host utilities and a harmless stand-in for
# the operator-supplied daemon. systemd-analyze does not launch services.
units="$sandbox/units"
mkdir "$units"
cp akashi@.service akashi-retention@.service "$units/"
cp -R akashi-retention@prover.service.d "$units/"
sed -i 's|/opt/akashi/venv/bin/python|/usr/bin/python3|' "$units/akashi-retention@.service"
cp akashi-engine-firewall.service "$units/"
cp -R akashi@*.service.d "$units/"
sed -i 's|^ExecStart=/usr/local/libexec/akashi/%i$|ExecStart=/usr/bin/true|' "$units/akashi@.service"
sed -i 's|^ExecStop=/usr/local/libexec/akashi/stop-prover$|ExecStop=/usr/bin/true|' "$units/akashi@prover.service.d/isolation.conf"
for role in engine log proxy prover; do
    cp "$units/akashi@.service" "$units/akashi@$role.service"
done
for role in auditor engine pickup prover; do
    cp "$units/akashi-retention@.service" "$units/akashi-retention@$role.service"
done
SYSTEMD_UNIT_PATH="$units:" systemd-analyze verify "$units"/akashi-retention@{auditor,engine,pickup,prover}.service "$units/akashi-engine-firewall.service" "$units"/akashi@{engine,log,proxy,prover}.service

# Resolve the proxy's UID from the isolated account database before loading the
# real rule into its own network namespace; host NSS contains no test accounts.
proxy_uid=$(stat -c %u "$stage/etc/akashi/keys/proxy")
proxy_gid=$(stat -c %g "$stage/etc/akashi/keys/proxy")
sed "s/\"akashi-proxy\"/$proxy_uid/g" engine.nft > "$sandbox/engine.nft"
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
