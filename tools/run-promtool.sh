#!/bin/sh
# Use an installed promtool or verify the official archive before extracting it.
set -eu
if [ -n "${PROMTOOL:-}" ]; then exec "$PROMTOOL" "$@"; fi
if command -v promtool >/dev/null 2>&1; then exec promtool "$@"; fi
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) platform=linux-amd64; digest=68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34 ;;
    Darwin/arm64) platform=darwin-arm64; digest=f7c71b553316f822bdd860a3ea527ebefb2f8e944e5b7dfd419ae2653cf3ba01 ;;
    *) echo 'Set PROMTOOL to an installed Prometheus promtool on this platform.' >&2; exit 1 ;;
esac
version=3.16.0
name=prometheus-$version.$platform
cache="$(dirname "$0")/../build/tools/$name"
mkdir -p "$cache"
if [ ! -x "$cache/promtool" ]; then
    stage=$(mktemp -d "$cache/stage.XXXXXXXX")
    trap 'rm -rf "$stage"' EXIT
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/prometheus/prometheus/releases/download/v$version/$name.tar.gz" -o "$stage/release.tar.gz"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$stage/release.tar.gz")
    else
        actual=$(shasum -a 256 "$stage/release.tar.gz")
    fi
    [ "${actual%% *}" = "$digest" ] || { echo 'Prometheus archive checksum mismatch.' >&2; exit 1; }
    tar -xzf "$stage/release.tar.gz" -C "$stage" "$name/promtool"
    mv "$stage/$name/promtool" "$cache/promtool"
    rm -rf "$stage"
    trap - EXIT
fi
exec "$cache/promtool" "$@"
