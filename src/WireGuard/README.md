# WireGuard on Noise (F#)

A from-scratch implementation of the [WireGuard](https://www.wireguard.com/protocol/)
handshake and transport, built on the [Noise library](../Noise) in this repo.

WireGuard's handshake is exactly the Noise pattern
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, with two WireGuard-specific framing choices
that the Noise core handles transparently:

* the **prologue** is WireGuard's `IDENTIFIER` string, and
* the responder's static key is the `IK` pre-message (`<- s`).

Because of that, the Noise library already emits byte-identical handshake material.
This module only adds the parts that live *outside* the Noise state machine:

| WireGuard element | Where it comes from |
| --- | --- |
| Message framing (types 1/2/4, indices, reserved bytes) | `WireGuard.fs` |
| `mac1` (keyed BLAKE2s over the message) | `WireGuard.fs` (`mac1` is required; `mac2` is zero without a cookie) |
| TAI64N timestamp (message 1 payload) | `WireGuard.fs` |
| Encrypted static / empty / timestamp, all DHs, the PSK, key split | the Noise `HandshakeState` |
| Transport records (explicit 64-bit counter as the nonce) | `WireGuard.fs` over the split `CipherState`s |

`InitiatorSession` and `ResponderSession` cover both ends of the handshake.

## The VPN device

`Device` (in `Device.fs`) is a full WireGuard endpoint built on the handshake above.
It manages, for every peer:

* the **session lifecycle** — handshake on demand when there is traffic, key split
  into transport `CipherState`s, current/previous keypairs, and rekeying;
* the **timer state machine** — handshake retransmission (every `REKEY_TIMEOUT`, up to
  `REKEY_ATTEMPT_TIME`), passive and persistent keepalives, and session expiry;
* **index demultiplexing** — a receiver-index table routes responses and transport
  records to the right peer/session;
* **anti-replay** — a sliding counter window per receiving keypair;
* **routing** — outbound IP packets are matched to a peer by allowed-IPs, inbound
  packets are checked against them.

The data plane is abstracted behind two interfaces in `Adapters.fs`:

* `ITunnel` — a source/sink of IP packets. Default: `LinuxTun` (a `/dev/net/tun`
  device via `ioctl`). `MockTunnel` is an in-memory one for tests.
* `IBind` — the UDP transport. Default: `UdpBind` over a socket.

What is **not** implemented: the cookie reply (type 3) DoS-mitigation path — `mac1`
is computed and verified, but `mac2` is always zero and incoming cookie replies are
ignored (this only matters when a peer is under load).

## Interoperability tests

`tests/wg-interop/run-interop.sh` stands up a userland **wireguard-go** instance,
configures it through its UAPI socket (no `wg` tool needed), and then runs the F#
initiator against it: a real handshake followed by an ICMP echo that round-trips
*through the tunnel*.

```bash
# build wireguard-go once:
GOBIN=$PWD/bin go install golang.zx2c4.com/wireguard@latest

# run the interop test (needs sudo for the TUN device + interface config):
WG_GO=$PWD/bin/wireguard ./tests/wg-interop/run-interop.sh
```

Expected tail:

```
-> sent handshake initiation (148 bytes, sender_index=0x...)
<- received 92 bytes (type 2)
   handshake complete. handshake_hash=...
-> sent encrypted ICMP echo request to 10.0.0.1 (80 bytes on wire)
<- received encrypted ICMP echo reply from 10.0.0.1 — round trip through the tunnel OK
```

`tests/wg-interop/run-vpn-interop.sh` goes further: it runs the full F# **device**
(with a real Linux TUN) in the root namespace and wireguard-go in a separate network
namespace, then sends a real `ping` through the tunnel:

```
== ping 10.66.0.2 through the F# WireGuard tunnel ==
3 packets transmitted, 3 received, 0% packet loss
RESULT: SUCCESS — ping traversed the F# WireGuard data plane
```

Network-free checks also run under `dotnet test`: a handshake + transport check
(`WireGuardTests.fs`) and a two-device data-plane exchange over loopback with mock
tunnels (`DeviceTests.fs`).
