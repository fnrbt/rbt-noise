module Noise.Tests.DeviceTests

open System
open System.Net
open System.Collections
open System.Collections.Concurrent
open System.Reflection
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

/// An in-memory wire: tests explicitly choose which authenticated datagrams reach a device.
type private ControlledBind() =
    let incoming = new BlockingCollection<byte[] * IPEndPoint>()
    let sent = new BlockingCollection<byte[] * IPEndPoint>()

    member _.Inject(packet: byte[], from: IPEndPoint) = incoming.Add((packet, from))
    member _.TryTakeSent(timeoutMs: int) =
        let mutable item = Unchecked.defaultof<byte[] * IPEndPoint>
        if sent.TryTake(&item, timeoutMs) then Some item else None

    interface IBind with
        member _.Receive() = incoming.Take()
        member _.Send packet endpoint = sent.Add((packet, endpoint))
        member _.Close() = incoming.CompleteAdding()

let private endpoint port = IPEndPoint(IPAddress.Loopback, port)

let private configuredPeer pub port (allowed: (string * int) list) : PeerConfig =
    { PublicKey = pub
      PresharedKey = None
      Endpoint = Some(endpoint port)
      AllowedIps = allowed |> List.map (fun (address, prefix) -> IPAddress.Parse address, prefix)
      PersistentKeepalive = 0 }

let private ipv6 (src: string) (dst: string) (payload: byte[]) =
    let p = Array.zeroCreate (40 + payload.Length)
    p.[0] <- 0x60uy
    p.[4] <- byte (payload.Length >>> 8)
    p.[5] <- byte payload.Length
    p.[6] <- 253uy
    p.[7] <- 64uy
    Array.blit (IPAddress.Parse(src).GetAddressBytes()) 0 p 8 16
    Array.blit (IPAddress.Parse(dst).GetAddressBytes()) 0 p 24 16
    Array.blit payload 0 p 40 payload.Length
    p

let private putU32 (p: byte[]) offset (n: uint32) =
    for i in 0 .. 3 do p.[offset + i] <- byte (n >>> (8 * i))

let private putU64 (p: byte[]) offset (n: uint64) =
    for i in 0 .. 7 do p.[offset + i] <- byte (n >>> (8 * i))

let private getU32 (p: byte[]) offset =
    [ 0 .. 3 ] |> List.fold (fun n i -> n ||| (uint32 p.[offset + i] <<< (8 * i))) 0u

/// A raw Noise initiator permits chosen, cryptographically authenticated handshake
/// timestamps and transport counters, without exposing test hooks in Device.
type private RawInitiator(local: KeyPair, remote: byte[], timestamp: byte[], index: uint32) =
    let handshake =
        Noise.createHandshake Protocol.Construction true (Text.Encoding.ASCII.GetBytes Protocol.Identifier)
            { HandshakeKeys.empty with
                LocalStatic = Some local
                RemoteStatic = Some remote
                Psks = [ Array.zeroCreate 32 ] }
    let mutable transport: Transport option = None
    let mutable remoteIndex = 0u

    member _.Initiation() =
        let noise, _ = handshake.WriteMessage timestamp
        let msg = Array.zeroCreate 148
        msg.[0] <- Protocol.MsgInitiation
        putU32 msg 4 index
        Array.blit noise 0 msg 8 noise.Length
        Array.blit (Protocol.mac1 remote msg.[0..115]) 0 msg 116 16
        msg

    member _.ReadResponse(msg: byte[]) =
        Assert.Equal(Protocol.MsgResponse, msg.[0])
        Assert.Equal(index, getU32 msg 8)
        remoteIndex <- getU32 msg 4
        let _, t = handshake.ReadMessage msg.[12..59]
        transport <- t

    member _.Encrypt(counter: uint64, payload: byte[]) =
        let t = Option.get transport
        t.SendingCipherState.SetNonce counter
        let padded = Array.zeroCreate ((payload.Length + 15) / 16 * 16)
        Array.blit payload 0 padded 0 payload.Length
        let ciphertext = t.SendingCipherState.EncryptWithAd([||], padded)
        let msg = Array.zeroCreate (16 + ciphertext.Length)
        msg.[0] <- Protocol.MsgTransport
        putU32 msg 4 remoteIndex
        putU64 msg 8 counter
        Array.blit ciphertext 0 msg 16 ciphertext.Length
        msg

    member _.Decrypt(msg: byte[]) =
        Assert.Equal(Protocol.MsgTransport, msg.[0])
        Assert.Equal(index, getU32 msg 4)
        let t = Option.get transport
        let counter =
            [ 0 .. 7 ] |> List.fold (fun n i -> n ||| (uint64 msg.[8 + i] <<< (8 * i))) 0UL
        t.ReceivingCipherState.SetNonce counter
        t.ReceivingCipherState.DecryptWithAd([||], msg.[16..])

let private takeSent (bind: ControlledBind) =
    match bind.TryTakeSent 3000 with
    | Some (msg, ep) -> msg, ep
    | None -> failwith "Device did not send the expected wire datagram"

let private expectNoSent (bind: ControlledBind) =
    Assert.True((bind.TryTakeSent 150).IsNone, "Unexpected wire datagram")

let private expectNoInbound (tun: MockTunnel) =
    Assert.True((tun.TryTakeInbound 150).IsNone, "Unexpected decrypted IP packet")

let private nextSecond (timestamp: byte[]) =
    let copy = Array.copy timestamp
    let mutable i = 7
    while i >= 0 && copy.[i] = 255uy do
        copy.[i] <- 0uy
        i <- i - 1
    copy.[i] <- copy.[i] + 1uy
    copy

/// The age belongs to an established private session; use reflection to avoid
/// waiting three minutes or adding production-only test APIs.
let private setCurrentSessionAge (device: Device) seconds =
    let flags = BindingFlags.Instance ||| BindingFlags.NonPublic ||| BindingFlags.Public
    let peersField = device.GetType().GetField("peers", flags)
    Assert.NotNull peersField
    let peer = (peersField.GetValue(device) :?> IEnumerable) |> Seq.cast<obj> |> Seq.head
    let current = peer.GetType().GetProperty("Current", flags).GetValue(peer)
    Assert.NotNull current
    let session = current.GetType().GetProperty("Value", flags).GetValue(current)
    let established = session.GetType().GetProperty("Established", flags)
    Assert.NotNull established
    established.SetValue(session, DateTime.UtcNow.AddSeconds(-seconds))

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

[<Fact>]
let ``inbound packet source must belong to authenticated peer for IPv4 and IPv6`` () =
    let local = Noise.generateKeyPair "25519"
    let broad = Noise.generateKeyPair "25519"
    let narrow = Noise.generateKeyPair "25519"
    let bind = ControlledBind()
    let tun = MockTunnel()
    let broadPeer =
        configuredPeer broad.PublicKey 30401
            [ "10.40.0.0", 16; "fd40::", 16 ]
    let narrowPeer =
        configuredPeer narrow.PublicKey 30402
            [ "10.40.7.0", 24; "fd40:7::", 32 ]
    let device = Device({ PrivateKey = local.PrivateKey; Peers = [ broadPeer; narrowPeer ]; Log = None }, tun, bind)
    let initiator = RawInitiator(broad, local.PublicKey, Protocol.timestamp (), 201u)
    let remote = endpoint 30401
    try
        device.Start()
        bind.Inject(initiator.Initiation(), remote)
        let response, _ = takeSent bind
        initiator.ReadResponse response

        let stolenV4 = ipv4 "10.40.7.9" "10.40.8.1" [| 1uy |]
        let stolenV6 = ipv6 "fd40:7::9" "fd40:8::1" [| 2uy |]
        let unownedV4 = ipv4 "10.41.1.9" "10.40.8.1" [| 3uy |]
        for (counter, packet) in [ 0UL, stolenV4; 1UL, stolenV6; 2UL, unownedV4 ] do
            bind.Inject(initiator.Encrypt(counter, packet), remote)
            expectNoInbound tun

        let ownedV4 = ipv4 "10.40.8.9" "10.40.8.1" [| 4uy |]
        let ownedV6 = ipv6 "fd40:8::9" "fd40:8::1" [| 5uy |]
        bind.Inject(initiator.Encrypt(3UL, ownedV4), remote)
        Assert.Equal<byte[]>(ownedV4, (tun.TryTakeInbound 3000).Value)
        bind.Inject(initiator.Encrypt(4UL, ownedV6), remote)
        Assert.Equal<byte[]>(ownedV6, (tun.TryTakeInbound 3000).Value)
    finally
        device.Stop()

[<Fact>]
let ``replayed and older initiations are ignored without disrupting the active session`` () =
    let local = Noise.generateKeyPair "25519"
    let remoteKey = Noise.generateKeyPair "25519"
    let bind = ControlledBind()
    let tun = MockTunnel()
    let device =
        Device({ PrivateKey = local.PrivateKey
                 Peers = [ configuredPeer remoteKey.PublicKey 30403 [ "10.50.0.0", 16 ] ]
                 Log = None }, tun, bind)
    let remote = endpoint 30403
    let initiator = RawInitiator(remoteKey, local.PublicKey, Protocol.timestamp (), 203u)
    let older = RawInitiator(remoteKey, local.PublicKey, Array.zeroCreate 12, 204u)
    try
        device.Start()
        let first = initiator.Initiation()
        bind.Inject(first, remote)
        let response, _ = takeSent bind
        initiator.ReadResponse response
        bind.Inject(initiator.Encrypt(0UL, [||]), remote) // Confirm the original session.

        bind.Inject(first, remote)
        expectNoSent bind
        bind.Inject(older.Initiation(), remote)
        expectNoSent bind

        let packet = ipv4 "10.50.1.2" "10.50.2.3" [| 9uy |]
        bind.Inject(initiator.Encrypt(1UL, packet), remote)
        Assert.Equal<byte[]>(packet, (tun.TryTakeInbound 3000).Value)
        let outbound = ipv4 "10.50.2.3" "10.50.1.2" [| 10uy |]
        tun.InjectOutbound outbound
        let wire, _ = takeSent bind
        Assert.Equal<byte[]>(outbound, (initiator.Decrypt wire).[0 .. outbound.Length - 1])
    finally
        device.Stop()

[<Fact>]
let ``responder queues without a confirmed key and retains old key during rekey`` () =
    let local = Noise.generateKeyPair "25519"
    let remoteKey = Noise.generateKeyPair "25519"
    let bind = ControlledBind()
    let tun = MockTunnel()
    let device =
        Device({ PrivateKey = local.PrivateKey
                 Peers = [ configuredPeer remoteKey.PublicKey 30404 [ "10.60.0.0", 16 ] ]
                 Log = None }, tun, bind)
    let remote = endpoint 30404
    let firstTimestamp = Protocol.timestamp ()
    let first = RawInitiator(remoteKey, local.PublicKey, firstTimestamp, 205u)
    let second = RawInitiator(remoteKey, local.PublicKey, nextSecond firstTimestamp, 206u)
    try
        device.Start()
        bind.Inject(first.Initiation(), remote)
        let response, _ = takeSent bind
        first.ReadResponse response

        let queued = ipv4 "10.60.2.3" "10.60.1.2" [| 1uy |]
        tun.InjectOutbound queued
        expectNoSent bind // A responder must not transmit before receiving confirmation.
        let forgedConfirmation = first.Encrypt(0UL, [||])
        forgedConfirmation.[forgedConfirmation.Length - 1] <- forgedConfirmation.[forgedConfirmation.Length - 1] ^^^ 1uy
        bind.Inject(forgedConfirmation, remote)
        expectNoSent bind // An unauthenticated frame must not flush the queue.
        bind.Inject(first.Encrypt(0UL, [||]), remote)
        let flushed, _ = takeSent bind
        Assert.Equal<byte[]>(queued, (first.Decrypt flushed).[0 .. queued.Length - 1])

        bind.Inject(second.Initiation(), remote)
        let nextResponse, _ = takeSent bind
        second.ReadResponse nextResponse
        let duringRekey = ipv4 "10.60.2.3" "10.60.1.2" [| 2uy |]
        tun.InjectOutbound duringRekey
        let stillOld, _ = takeSent bind
        Assert.Equal<byte[]>(duringRekey, (first.Decrypt stillOld).[0 .. duringRekey.Length - 1])
        let fromOld = ipv4 "10.60.1.2" "10.60.2.3" [| 4uy |]
        bind.Inject(first.Encrypt(1UL, fromOld), remote)
        Assert.Equal<byte[]>(fromOld, (tun.TryTakeInbound 3000).Value)

        let confirmation = ipv4 "10.60.1.2" "10.60.2.3" [| 5uy |]
        bind.Inject(second.Encrypt(0UL, confirmation), remote)
        Assert.Equal<byte[]>(confirmation, (tun.TryTakeInbound 3000).Value)
        let afterConfirmation = ipv4 "10.60.2.3" "10.60.1.2" [| 3uy |]
        tun.InjectOutbound afterConfirmation
        let nowNew, _ = takeSent bind
        Assert.Equal<byte[]>(afterConfirmation, (second.Decrypt nowNew).[0 .. afterConfirmation.Length - 1])
    finally
        device.Stop()

[<Fact>]
let ``receive accepts young session but rejects authenticated data after 180 seconds`` () =
    let local = Noise.generateKeyPair "25519"
    let remoteKey = Noise.generateKeyPair "25519"
    let bind = ControlledBind()
    let tun = MockTunnel()
    let device =
        Device({ PrivateKey = local.PrivateKey
                 Peers = [ configuredPeer remoteKey.PublicKey 30405 [ "10.70.0.0", 16 ] ]
                 Log = None }, tun, bind)
    let remote = endpoint 30405
    let initiator = RawInitiator(remoteKey, local.PublicKey, Protocol.timestamp (), 207u)
    try
        device.Start()
        bind.Inject(initiator.Initiation(), remote)
        let response, _ = takeSent bind
        initiator.ReadResponse response
        let confirmation = ipv4 "10.70.1.2" "10.70.2.3" [| 0uy |]
        bind.Inject(initiator.Encrypt(0UL, confirmation), remote)
        Assert.Equal<byte[]>(confirmation, (tun.TryTakeInbound 3000).Value)

        setCurrentSessionAge device 179.0
        let fresh = ipv4 "10.70.1.2" "10.70.2.3" [| 1uy |]
        bind.Inject(initiator.Encrypt(1UL, fresh), remote)
        Assert.Equal<byte[]>(fresh, (tun.TryTakeInbound 3000).Value)

        setCurrentSessionAge device 180.0
        bind.Inject(initiator.Encrypt(2UL, ipv4 "10.70.1.2" "10.70.2.3" [| 2uy |]), remote)
        expectNoInbound tun
    finally
        device.Stop()

[<Fact>]
let ``receive rejects transport counters at rejection threshold but accepts prior counters`` () =
    let local = Noise.generateKeyPair "25519"
    let remoteKey = Noise.generateKeyPair "25519"
    let bind = ControlledBind()
    let tun = MockTunnel()
    let device =
        Device({ PrivateKey = local.PrivateKey
                 Peers = [ configuredPeer remoteKey.PublicKey 30406 [ "10.80.0.0", 16 ] ]
                 Log = None }, tun, bind)
    let remote = endpoint 30406
    let initiator = RawInitiator(remoteKey, local.PublicKey, Protocol.timestamp (), 208u)
    let threshold = UInt64.MaxValue - 8192UL
    try
        device.Start()
        bind.Inject(initiator.Initiation(), remote)
        let response, _ = takeSent bind
        initiator.ReadResponse response
        let accepted = ipv4 "10.80.1.2" "10.80.2.3" [| 1uy |]
        bind.Inject(initiator.Encrypt(threshold - 1UL, accepted), remote)
        Assert.Equal<byte[]>(accepted, (tun.TryTakeInbound 3000).Value)
        bind.Inject(initiator.Encrypt(threshold, ipv4 "10.80.1.2" "10.80.2.3" [| 2uy |]), remote)
        expectNoInbound tun
        let stillAccepted = ipv4 "10.80.1.2" "10.80.2.3" [| 3uy |]
        bind.Inject(initiator.Encrypt(threshold - 2UL, stillAccepted), remote)
        Assert.Equal<byte[]>(stillAccepted, (tun.TryTakeInbound 3000).Value)
    finally
        device.Stop()

[<Fact>]
let ``outbound IPv4 and IPv6 choose longest prefix regardless of peer order`` () =
    let local = Noise.generateKeyPair "25519"
    let broad = Noise.generateKeyPair "25519"
    let narrow = Noise.generateKeyPair "25519"
    let broadPeer = configuredPeer broad.PublicKey 30407 [ "10.90.0.0", 16; "fd90::", 16 ]
    let narrowPeer = configuredPeer narrow.PublicKey 30408 [ "10.90.7.0", 24; "fd90:7::", 32 ]
    let narrowV4 = ipv4 "10.90.9.1" "10.90.7.2" [| 1uy |]
    let narrowV6 = ipv6 "fd90:9::1" "fd90:7::2" [| 2uy |]
    for (peers, firstPacket, queuedPacket) in
        [ [ broadPeer; narrowPeer ], narrowV4, narrowV6
          [ broadPeer; narrowPeer ], narrowV6, narrowV4
          [ narrowPeer; broadPeer ], narrowV4, narrowV6 ] do
        let bind = ControlledBind()
        let tun = MockTunnel()
        let device = Device({ PrivateKey = local.PrivateKey; Peers = peers; Log = None }, tun, bind)
        try
            device.Start()
            tun.InjectOutbound firstPacket
            let first, firstDestination = takeSent bind
            Assert.Equal(Protocol.MsgInitiation, first.[0])
            Assert.Equal(endpoint 30408, firstDestination)

            tun.InjectOutbound queuedPacket
            expectNoSent bind // Same narrow peer already has a handshake pending.

            tun.InjectOutbound(ipv4 "10.90.7.1" "10.90.9.2" [| 3uy |])
            let other, otherDestination = takeSent bind
            Assert.Equal(Protocol.MsgInitiation, other.[0])
            Assert.Equal(endpoint 30407, otherDestination)
        finally
            device.Stop()
