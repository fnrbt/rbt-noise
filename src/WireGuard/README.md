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

## Interoperability test

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

A network-free F#↔F# handshake + transport check also runs as part of `dotnet test`
(`WireGuardTests.fs`).

## Scope

This is a focused, correct implementation of the WireGuard **cryptographic protocol**
(handshake + transport records), suitable for interop and study. It is not a full VPN:
it does not implement the cookie/DoS-mitigation reply (type 3), the timer state machine
(rekeying, keepalives, handshake retries), or a TUN/routing data plane.
