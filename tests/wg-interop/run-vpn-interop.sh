#!/usr/bin/env bash
# Full VPN data-plane interop: the F# WireGuard *device* (with a real Linux TUN) in
# the root namespace, against userland wireguard-go in its own network namespace,
# connected by a veth pair. A real `ping` then traverses the tunnel end to end.
#
#   WG_GO=/path/to/wireguard-go  ./tests/wg-interop/run-vpn-interop.sh
#
# Topology:
#   root ns:  F# device, tun wgf0 = 10.66.0.1/24, udp/51821, veth 10.99.0.1
#   wgns:     wireguard-go, tun wg0 = 10.66.0.2/24, udp/51820, veth 10.99.0.2
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WG_GO="${WG_GO:?set WG_GO to the wireguard-go binary path}"
APP="$ROOT/samples/WgInterop/bin/Release/net10.0/WgInterop"
NS=wgns
SOCK=/var/run/wireguard/wg0.sock
FPORT=51821
GPORT=51820
DEVPID=""

cleanup() {
  [ -n "$DEVPID" ] && kill "$DEVPID" 2>/dev/null || true
  sudo pkill -f "$WG_GO wg0" 2>/dev/null || true
  sudo ip netns del $NS 2>/dev/null || true
  sudo ip link del vethr 2>/dev/null || true
  sudo ip link del wgf0 2>/dev/null || true
}
trap cleanup EXIT

echo "== build =="
dotnet build "$ROOT/samples/WgInterop/WgInterop.fsproj" -c Release -v q >/dev/null

echo "== keys =="
read -r FPRIV FPUB < <("$APP" genkey)
read -r GPRIV GPUB < <("$APP" genkey)
echo "   F# device pub: $FPUB"
echo "   wireguard-go pub: $GPUB"

echo "== network namespace + veth =="
sudo ip netns add $NS
sudo ip link add vethr type veth peer name vethn
sudo ip link set vethn netns $NS
sudo ip addr add 10.99.0.1/24 dev vethr
sudo ip link set vethr up
sudo ip netns exec $NS ip addr add 10.99.0.2/24 dev vethn
sudo ip netns exec $NS ip link set vethn up
sudo ip netns exec $NS ip link set lo up

echo "== persistent TUN wgf0 for the F# device (root ns) =="
sudo ip tuntap add dev wgf0 mode tun user "$USER"
sudo ip addr add 10.66.0.1/24 dev wgf0
sudo ip link set wgf0 up
sudo sysctl -q net.ipv4.conf.wgf0.rp_filter=2 net.ipv4.conf.all.rp_filter=2 || true

echo "== start wireguard-go in $NS =="
sudo rm -f "$SOCK"
sudo ip netns exec $NS env WG_PROCESS_FOREGROUND=1 "$WG_GO" wg0 >/tmp/wireguard-go-vpn.log 2>&1 &
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "wireguard-go socket missing"; cat /tmp/wireguard-go-vpn.log; exit 1; }
sudo ip netns exec $NS "$APP" wg-config "$SOCK" "$GPRIV" "$GPORT" "$FPUB" "10.66.0.1/32"
sudo ip netns exec $NS ip addr add 10.66.0.2/24 dev wg0
sudo ip netns exec $NS ip link set wg0 up

echo "== start F# device in root ns =="
"$APP" vpn wgf0 "$FPORT" "$FPRIV" "$GPUB" "10.99.0.2:$GPORT" "10.66.0.2/32" &
DEVPID=$!
sleep 1.5

echo "== ping 10.66.0.2 through the F# WireGuard tunnel =="
if ping -c 3 -W 2 10.66.0.2; then
  echo "RESULT: SUCCESS — ping traversed the F# WireGuard data plane"
  RC=0
else
  echo "RESULT: FAILED"
  RC=1
fi

echo "== wireguard-go log (tail) =="
tail -n 8 /tmp/wireguard-go-vpn.log || true
exit $RC
