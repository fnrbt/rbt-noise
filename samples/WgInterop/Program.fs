module WgInterop.Program

open System
open System.Net
open System.Net.Sockets
open System.Text
open Noise
open WireGuard

let private hex (b: byte[]) = Convert.ToHexString(b).ToLowerInvariant()
let private fromHex (s: string) = Convert.FromHexString s

// ---------------------------------------------------------------------------
// IPv4 + ICMP echo, so we can ping *through* the tunnel and prove transport works.
// ---------------------------------------------------------------------------

let private checksum (data: byte[]) =
    let mutable sum = 0u
    let mutable i = 0
    while i + 1 < data.Length do
        sum <- sum + (uint32 data.[i] <<< 8 ||| uint32 data.[i + 1])
        i <- i + 2
    if i < data.Length then sum <- sum + (uint32 data.[i] <<< 8)
    while (sum >>> 16) <> 0u do
        sum <- (sum &&& 0xffffu) + (sum >>> 16)
    uint16 (~~~sum &&& 0xffffu)

let private putU16be (buf: byte[]) off (v: uint16) =
    buf.[off] <- byte (v >>> 8)
    buf.[off + 1] <- byte v

/// Build an IPv4 ICMP echo request from `src` to `dst`.
let private icmpEchoRequest (src: IPAddress) (dst: IPAddress) (ident: uint16) (seq: uint16) (payload: byte[]) =
    let icmp = Array.zeroCreate (8 + payload.Length)
    icmp.[0] <- 8uy // echo request
    putU16be icmp 4 ident
    putU16be icmp 6 seq
    Array.blit payload 0 icmp 8 payload.Length
    putU16be icmp 2 (checksum icmp)

    let total = 20 + icmp.Length
    let ip = Array.zeroCreate total
    ip.[0] <- 0x45uy // IPv4, IHL=5
    putU16be ip 2 (uint16 total)
    ip.[8] <- 64uy // TTL
    ip.[9] <- 1uy // protocol = ICMP
    Array.blit (src.GetAddressBytes()) 0 ip 12 4
    Array.blit (dst.GetAddressBytes()) 0 ip 16 4
    putU16be ip 10 (checksum ip.[0..19])
    Array.blit icmp 0 ip 20 icmp.Length
    ip

/// Is `packet` an ICMP echo reply (type 0) carrying the given id/seq?
let private isEchoReply (packet: byte[]) (ident: uint16) (seq: uint16) =
    packet.Length >= 28
    && (packet.[0] >>> 4) = 4uy
    && packet.[9] = 1uy // ICMP
    && packet.[20] = 0uy // echo reply
    && (uint16 packet.[24] <<< 8 ||| uint16 packet.[25]) = ident
    && (uint16 packet.[26] <<< 8 ||| uint16 packet.[27]) = seq

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

/// keygen -> prints "initPriv initPub respPriv respPub" (hex) on one line.
let keygen () =
    let i = Noise.generateKeyPair "25519"
    let r = Noise.generateKeyPair "25519"
    printfn "%s %s %s %s" (hex i.PrivateKey) (hex i.PublicKey) (hex r.PrivateKey) (hex r.PublicKey)
    0

/// wg-config <sockPath> <devPrivHex> <listenPort> <peerPubHex> <allowedIp/cidr>
/// Configures a running wireguard-go device through its UAPI unix socket (no `wg` tool).
let wgConfig (argv: string[]) =
    let sockPath, devPriv, port, peerPub, allowed = argv.[0], argv.[1], argv.[2], argv.[3], argv.[4]
    use sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)
    sock.Connect(UnixDomainSocketEndPoint sockPath)
    let request =
        String.concat "\n"
            [ "set=1"
              sprintf "private_key=%s" devPriv
              sprintf "listen_port=%s" port
              sprintf "public_key=%s" peerPub
              sprintf "allowed_ip=%s" allowed
              "protocol_version=1"
              ""
              "" ]
    sock.Send(Encoding.ASCII.GetBytes request) |> ignore
    let buf: byte[] = Array.zeroCreate 4096
    let n = sock.Receive buf
    let resp = Encoding.ASCII.GetString(buf, 0, n)
    printf "%s" resp
    if resp.Contains "errno=0" then 0 else 1

/// connect <wgIp:port> <initPrivHex> <initPubHex> <respPubHex> <srcTunIp> <dstTunIp>
/// Performs a full WireGuard handshake against the endpoint, then pings dstTunIp
/// through the tunnel and waits for the echo reply.
let connect (argv: string[]) =
    let endpoint =
        let parts = argv.[0].Split(':')
        IPEndPoint(IPAddress.Parse parts.[0], int parts.[1])
    let initStatic = { PrivateKey = fromHex argv.[1]; PublicKey = fromHex argv.[2] }
    let respPub = fromHex argv.[3]
    let srcTun = IPAddress.Parse argv.[4]
    let dstTun = IPAddress.Parse argv.[5]

    use udp = new UdpClient()
    udp.Client.ReceiveTimeout <- 5000
    udp.Connect endpoint

    let session = WireGuard.Protocol.InitiatorSession(initStatic, respPub, null)

    // 1. Handshake initiation -> response.
    let initiation = session.CreateInitiation()
    udp.Send(initiation, initiation.Length) |> ignore
    printfn "-> sent handshake initiation (%d bytes, sender_index=0x%08x)" initiation.Length session.SenderIndex

    let mutable remote = endpoint
    let response = udp.Receive(&remote)
    printfn "<- received %d bytes (type %d)" response.Length response.[0]
    session.ReadResponse response
    printfn "   handshake complete. handshake_hash=%s" (hex session.HandshakeHash)

    // 2. Ping through the tunnel.
    let ident, seq = 0x1234us, 1us
    let request = icmpEchoRequest srcTun dstTun ident seq (Encoding.ASCII.GetBytes "noise-fsharp")
    let dataMsg = session.EncryptTransport request
    udp.Send(dataMsg, dataMsg.Length) |> ignore
    printfn "-> sent encrypted ICMP echo request to %O (%d bytes on wire)" dstTun dataMsg.Length

    // 3. Await the encrypted echo reply (skip keepalives, which decrypt to empty).
    let mutable result = 1
    let mutable waiting = true
    while waiting do
        try
            let reply = udp.Receive(&remote)
            if reply.Length > 0 && reply.[0] = WireGuard.Protocol.MsgTransport then
                let plain = session.DecryptTransport reply
                if plain.Length = 0 then
                    printfn "<- received encrypted keepalive"
                elif isEchoReply plain ident seq then
                    printfn "<- received encrypted ICMP echo reply from %O — round trip through the tunnel OK" dstTun
                    result <- 0
                    waiting <- false
                else
                    printfn "<- received transport packet (%d bytes, not our echo reply)" plain.Length
            else
                printfn "<- received non-transport message (type %d)" (if reply.Length > 0 then int reply.[0] else -1)
        with :? SocketException ->
            printfn "   timed out waiting for echo reply"
            waiting <- false
    result

[<EntryPoint>]
let main argv =
    match Array.toList argv with
    | "keygen" :: _ -> keygen ()
    | "wg-config" :: rest -> wgConfig (List.toArray rest)
    | "connect" :: rest -> connect (List.toArray rest)
    | _ ->
        eprintfn "usage: WgInterop (keygen | wg-config ... | connect ...)"
        2
