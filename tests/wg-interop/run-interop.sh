#!/usr/bin/env bash
# End-to-end interoperability test: stand up a userland wireguard-go tunnel and
# drive a handshake + ping against it from the F# WireGuard implementation.
#
#   WG_GO=/path/to/wireguard-go  ./tests/wg-interop/run-interop.sh
#
# Requires: sudo (to create the TUN device and configure the interface), and the
# wireguard-go binary (built from golang.zx2c4.com/wireguard).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WG_GO="${WG_GO:?set WG_GO to the wireguard-go binary path}"
DEV="${DEV:-wgtest}"
PORT="${PORT:-51820}"
LOG="${LOG:-/tmp/wireguard-go-$DEV.log}"
APP="$ROOT/samples/WgInterop/bin/Release/net10.0/WgInterop"
SOCK="/var/run/wireguard/$DEV.sock"

cleanup() {
  sudo pkill -f "$WG_GO $DEV" 2>/dev/null || true
  sudo ip link del "$DEV" 2>/dev/null || true
}
trap cleanup EXIT

echo "== building interop app =="
dotnet build "$ROOT/samples/WgInterop/WgInterop.fsproj" -c Release -v q >/dev/null

echo "== generating keys =="
read -r IPRIV IPUB RPRIV RPUB < <("$APP" keygen)
echo "   initiator(F#) public: $IPUB"
echo "   responder(wg) public: $RPUB"

echo "== starting wireguard-go ($DEV) =="
sudo rm -f "$SOCK"
sudo env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=verbose "$WG_GO" "$DEV" >"$LOG" 2>&1 &
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "wireguard-go socket never appeared"; cat "$LOG"; exit 1; }

echo "== configuring wireguard-go via UAPI socket =="
sudo "$APP" wg-config "$SOCK" "$RPRIV" "$PORT" "$IPUB" "10.0.0.2/32"

echo "== bringing up interface 10.0.0.1/24 =="
sudo ip addr add 10.0.0.1/24 dev "$DEV"
sudo ip link set "$DEV" up

echo "== running F# WireGuard handshake + ping =="
"$APP" connect "127.0.0.1:$PORT" "$IPRIV" "$IPUB" "$RPUB" "10.0.0.2" "10.0.0.1"
RC=$?

echo "== wireguard-go log (tail) =="
tail -n 15 "$LOG" || true
exit $RC
