module Noise.Tests.DeviceTests

open System
open System.Net
open Xunit
open Noise
open WireGuard

// A full WireGuard data-plane exchange between two F# Devices over loopback UDP,
// using in-memory tunnels. Exercises on-demand handshakes, routing by allowed-IPs,
// index demultiplexing and the encrypted transport — no root required.

/// A minimal IPv4 packet (header + payload), enough for routing/trimming.
let private ipv4 (src: string) (dst: string) (payload: byte[]) =
    let total = 20 + payload.Length
    let p = Array.zeroCreate total
    p.[0] <- 0x45uy
    p.[2] <- byte (total >>> 8)
    p.[3] <- byte total
    p.[8] <- 64uy
    p.[9] <- 253uy // experimental protocol
    Array.blit (IPAddress.Parse(src).GetAddressBytes()) 0 p 12 4
    Array.blit (IPAddress.Parse(dst).GetAddressBytes()) 0 p 16 4
    Array.blit payload 0 p 20 payload.Length
    p

let private peer (pub: byte[]) (port: int) (allowed: string) : PeerConfig =
    { PublicKey = pub
      PresharedKey = None
      Endpoint = Some(IPEndPoint(IPAddress.Loopback, port))
      AllowedIps = [ IPAddress.Parse allowed, 32 ]
      PersistentKeepalive = 0 }

[<Fact>]
let ``two devices handshake on demand and tunnel packets both ways`` () =
    let bindA = UdpBind 0
    let bindB = UdpBind 0
    let tunA = MockTunnel()
    let tunB = MockTunnel()
    let kA = Noise.generateKeyPair "25519"
    let kB = Noise.generateKeyPair "25519"

    let deviceA =
        Device({ PrivateKey = kA.PrivateKey; Peers = [ peer kB.PublicKey bindB.Port "10.0.0.2" ]; Log = None }, tunA, bindA)
    let deviceB =
        Device({ PrivateKey = kB.PrivateKey; Peers = [ peer kA.PublicKey bindA.Port "10.0.0.1" ]; Log = None }, tunB, bindB)

    try
        deviceA.Start()
        deviceB.Start()

        // A sends to 10.0.0.2: no key yet, so A handshakes with B, then tunnels it.
        let aToB = ipv4 "10.0.0.1" "10.0.0.2" (Text.Encoding.ASCII.GetBytes "ping from A")
        tunA.InjectOutbound aToB
        let atB = tunB.TryTakeInbound 5000
        Assert.True(atB.IsSome, "B never received A's tunneled packet")
        Assert.Equal<byte[]>(aToB, atB.Value)

        // The reverse direction reuses the established session.
        let bToA = ipv4 "10.0.0.2" "10.0.0.1" (Text.Encoding.ASCII.GetBytes "pong from B")
        tunB.InjectOutbound bToA
        let atA = tunA.TryTakeInbound 5000
        Assert.True(atA.IsSome, "A never received B's tunneled packet")
        Assert.Equal<byte[]>(bToA, atA.Value)
    finally
        deviceA.Stop()
        deviceB.Stop()
