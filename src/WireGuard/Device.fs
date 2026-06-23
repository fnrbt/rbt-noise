namespace WireGuard

open System
open System.Collections.Generic
open System.Net
open System.Security.Cryptography
open System.Threading
open Noise

/// Configuration for one peer.
type PeerConfig =
    { /// The peer's static public key (32 bytes).
      PublicKey: byte[]
      /// Optional pre-shared key (32 bytes).
      PresharedKey: byte[] option
      /// Where to send packets to (may also be learned from received packets).
      Endpoint: IPEndPoint option
      /// Networks routed to this peer, as (network, prefix-length).
      AllowedIps: (IPAddress * int) list
      /// Send a keepalive every N seconds (0 = disabled).
      PersistentKeepalive: int }

/// Configuration for a device.
type DeviceConfig =
    { /// The device's static private key (32 bytes).
      PrivateKey: byte[]
      Peers: PeerConfig list
      /// Optional log sink for protocol events.
      Log: (string -> unit) option }

module private Wire =
    let putU32le (b: byte[]) o (v: uint32) =
        b.[o] <- byte v
        b.[o + 1] <- byte (v >>> 8)
        b.[o + 2] <- byte (v >>> 16)
        b.[o + 3] <- byte (v >>> 24)

    let getU32le (b: byte[]) o =
        uint32 b.[o] ||| (uint32 b.[o + 1] <<< 8) ||| (uint32 b.[o + 2] <<< 16) ||| (uint32 b.[o + 3] <<< 24)

    let putU64le (b: byte[]) o (v: uint64) =
        for i in 0 .. 7 do b.[o + i] <- byte (v >>> (8 * i))

    let getU64le (b: byte[]) o =
        let mutable v = 0UL
        for i in 0 .. 7 do v <- v ||| (uint64 b.[o + i] <<< (8 * i))
        v

    /// Does `ip` fall within the CIDR (network, prefix)?
    let inCidr (ip: IPAddress) ((network: IPAddress), (prefix: int)) =
        let a = ip.GetAddressBytes()
        let n = network.GetAddressBytes()
        if a.Length <> n.Length then false
        else
            let mutable bits = prefix
            let mutable i = 0
            let mutable ok = true
            while ok && bits > 0 do
                let take = min 8 bits
                let mask = byte (0xFF <<< (8 - take))
                if (a.[i] &&& mask) <> (n.[i] &&& mask) then ok <- false
                bits <- bits - take
                i <- i + 1
            ok

    /// Destination address of an IPv4/IPv6 packet, if parseable.
    let destinationOf (packet: byte[]) =
        if packet.Length < 20 then None
        else
            match packet.[0] >>> 4 with
            | 4uy -> Some(IPAddress(packet.[16..19]))
            | 6uy when packet.Length >= 40 -> Some(IPAddress(packet.[24..39]))
            | _ -> None

    /// Trim a decrypted (zero-padded) packet to its real length from the IP header.
    let trimToIpLength (packet: byte[]) =
        if packet.Length >= 20 && packet.[0] >>> 4 = 4uy then
            let total = (int packet.[2] <<< 8) ||| int packet.[3]
            if total > 0 && total <= packet.Length then packet.[0 .. total - 1] else packet
        elif packet.Length >= 40 && packet.[0] >>> 4 = 6uy then
            let payload = (int packet.[4] <<< 8) ||| int packet.[5]
            let total = 40 + payload
            if total <= packet.Length then packet.[0 .. total - 1] else packet
        else packet

/// Sliding-window anti-replay protection for a receiving keypair.
type private ReplayWindow() =
    let size = 2048UL
    let seen = HashSet<uint64>()
    let mutable max = 0UL
    let mutable started = false

    /// Record an authenticated counter; returns false if it is a replay or too old.
    member _.Accept(counter: uint64) =
        if not started then
            started <- true
            max <- counter
            seen.Add counter |> ignore
            true
        elif counter > max then
            max <- counter
            seen.Add counter |> ignore
            if uint64 seen.Count > size * 2UL then
                seen.RemoveWhere(fun c -> c + size < max) |> ignore
            true
        elif counter + size < max then false
        elif seen.Contains counter then false
        else
            seen.Add counter |> ignore
            true

/// An established transport keypair.
type private Session =
    { LocalIndex: uint32
      mutable RemoteIndex: uint32
      Send: CipherState
      Recv: CipherState
      Replay: ReplayWindow
      mutable Established: DateTime
      IsInitiator: bool
      mutable Confirmed: bool }

type private Peer =
    { Config: PeerConfig
      Psk: byte[]
      mutable Endpoint: IPEndPoint option
      mutable Current: Session option
      mutable Previous: Session option
      mutable Handshake: HandshakeState option
      mutable HandshakeIndex: uint32
      mutable HandshakeStarted: DateTime
      mutable LastInitiationSent: DateTime
      mutable LastSent: DateTime
      mutable KeepaliveDue: DateTime option
      // Outbound packets awaiting a usable session (flushed once the handshake completes).
      mutable Queued: byte[] list }

type private IndexEntry =
    | HandshakeEntry of Peer
    | SessionEntry of Peer * Session

/// A WireGuard device: drives handshakes and the encrypted data plane for a set of
/// peers over an `IBind` (UDP) and an `ITunnel` (IP packets). Construct it with a
/// configuration and the two adapters, then call Start.
type Device(config: DeviceConfig, tunnel: ITunnel, bind: IBind) =
    // WireGuard timer constants (seconds).
    static let rekeyTimeout = TimeSpan.FromSeconds 5.0
    static let rekeyAfterTime = TimeSpan.FromSeconds 120.0
    static let rejectAfterTime = TimeSpan.FromSeconds 180.0
    static let rekeyAttemptTime = TimeSpan.FromSeconds 90.0
    static let keepaliveTimeout = TimeSpan.FromSeconds 10.0
    static let rejectAfterMessages = System.UInt64.MaxValue - 8192UL

    let log (msg: string) = config.Log |> Option.iter (fun f -> f msg)
    let localStatic = Noise.keyPairFromPrivate "25519" config.PrivateKey
    let identifier = Text.Encoding.ASCII.GetBytes Protocol.Identifier

    let peers =
        config.Peers
        |> List.map (fun p ->
            { Config = p
              Psk = p.PresharedKey |> Option.defaultValue (Array.zeroCreate 32)
              Endpoint = p.Endpoint
              Current = None
              Previous = None
              Handshake = None
              HandshakeIndex = 0u
              HandshakeStarted = DateTime.MinValue
              LastInitiationSent = DateTime.MinValue
              LastSent = DateTime.MinValue
              KeepaliveDue = None
              Queued = [] })

    let indexTable = Dictionary<uint32, IndexEntry>()
    let stateLock = obj ()
    let mutable running = false
    let threads = ResizeArray<Thread>()

    let now () = DateTime.UtcNow

    let allocateIndex (entry: IndexEntry) =
        let mutable idx = 0u
        let mutable ok = false
        while not ok do
            idx <- BitConverter.ToUInt32(RandomNumberGenerator.GetBytes 4, 0)
            if idx <> 0u && not (indexTable.ContainsKey idx) then ok <- true
        indexTable.[idx] <- entry
        idx

    let sessionValid (s: Session) =
        now () - s.Established < rejectAfterTime && s.Send.Nonce < rejectAfterMessages

    let sendTo (peer: Peer) (msg: byte[]) =
        peer.Endpoint |> Option.iter (fun ep -> bind.Send msg ep)

    // ---- handshake ----

    let sendInitiation (peer: Peer) =
        // Fresh IKpsk2 initiation each (re)transmission.
        peer.Handshake |> Option.iter (fun _ -> indexTable.Remove peer.HandshakeIndex |> ignore)
        let hs =
            Noise.createHandshake Protocol.Construction true identifier
                { HandshakeKeys.empty with
                    LocalStatic = Some localStatic
                    RemoteStatic = Some peer.Config.PublicKey
                    Psks = [ peer.Psk ] }
        let idx = allocateIndex (HandshakeEntry peer)
        peer.Handshake <- Some hs
        peer.HandshakeIndex <- idx
        peer.LastInitiationSent <- now ()

        let noise, _ = hs.WriteMessage(Protocol.timestamp ())
        let msg = Array.zeroCreate 148
        msg.[0] <- Protocol.MsgInitiation
        Wire.putU32le msg 4 idx
        Array.blit noise 0 msg 8 noise.Length
        Array.blit (Protocol.mac1 peer.Config.PublicKey msg.[0..115]) 0 msg 116 16
        sendTo peer msg
        log (sprintf "-> handshake initiation to %A (index 0x%08x)" peer.Endpoint idx)

    let startHandshake (peer: Peer) =
        if peer.Handshake.IsNone then
            peer.HandshakeStarted <- now ()
        sendInitiation peer

    let installSession (peer: Peer) (session: Session) =
        peer.Previous |> Option.iter (fun p -> indexTable.Remove p.LocalIndex |> ignore)
        peer.Previous <- peer.Current
        peer.Current <- Some session
        indexTable.[session.LocalIndex] <- SessionEntry(peer, session)

    // ---- transport ----

    let encryptTo (peer: Peer) (session: Session) (packet: byte[]) =
        let padded =
            let n = (packet.Length + 15) / 16 * 16
            if n = packet.Length then packet else Array.append packet (Array.zeroCreate (n - packet.Length))
        let counter = session.Send.Nonce
        let ciphertext = session.Send.EncryptWithAd([||], padded)
        let msg = Array.zeroCreate (16 + ciphertext.Length)
        msg.[0] <- Protocol.MsgTransport
        Wire.putU32le msg 4 session.RemoteIndex
        Wire.putU64le msg 8 counter
        Array.blit ciphertext 0 msg 16 ciphertext.Length
        sendTo peer msg
        peer.LastSent <- now ()
        peer.KeepaliveDue <- None

    let sendKeepalive (peer: Peer) =
        peer.Current |> Option.iter (fun s -> if sessionValid s then encryptTo peer s [||])

    /// Send any packets that were queued while waiting for a session.
    let flushQueued (peer: Peer) (session: Session) =
        let queued = List.rev peer.Queued
        peer.Queued <- []
        for packet in queued do
            encryptTo peer session packet

    /// Encrypt and send an outbound IP packet, starting a handshake if there is no key yet.
    let sendPacket (peer: Peer) (packet: byte[]) =
        match peer.Current with
        | Some s when sessionValid s -> encryptTo peer s packet
        | _ ->
            peer.Queued <- (packet :: peer.Queued) |> List.truncate 16
            if peer.Handshake.IsNone || now () - peer.HandshakeStarted > rekeyAttemptTime then
                startHandshake peer

    // ---- inbound message handling ----

    let handleInitiation (msg: byte[]) (from: IPEndPoint) =
        if msg.Length = 148 && Protocol.mac1 localStatic.PublicKey msg.[0..115] = msg.[116..131] then
            // First pass (psk irrelevant to message 1) recovers the initiator's static
            // key so we can identify the peer and use its pre-shared key.
            let probe =
                Noise.createHandshake Protocol.Construction false identifier
                    { HandshakeKeys.empty with LocalStatic = Some localStatic; Psks = [ Array.zeroCreate 32 ] }
            try
                probe.ReadMessage msg.[8..115] |> ignore
                let remoteStatic = probe.RemoteStaticKey
                match remoteStatic |> Option.bind (fun rs -> peers |> List.tryFind (fun p -> p.Config.PublicKey = rs)) with
                | None -> log "<- initiation from unknown peer (dropped)"
                | Some peer ->
                    let hs =
                        Noise.createHandshake Protocol.Construction false identifier
                            { HandshakeKeys.empty with LocalStatic = Some localStatic; Psks = [ peer.Psk ] }
                    hs.ReadMessage msg.[8..115] |> ignore
                    let noise, transport = hs.WriteMessage [||]
                    let t = Option.get transport
                    let localIndex = allocateIndex (HandshakeEntry peer)
                    let session =
                        { LocalIndex = localIndex
                          RemoteIndex = Wire.getU32le msg 4
                          Send = t.SendingCipherState
                          Recv = t.ReceivingCipherState
                          Replay = ReplayWindow()
                          Established = now ()
                          IsInitiator = false
                          Confirmed = false }
                    peer.Endpoint <- Some from
                    installSession peer session
                    flushQueued peer session
                    let response = Array.zeroCreate 92
                    response.[0] <- Protocol.MsgResponse
                    Wire.putU32le response 4 localIndex
                    Wire.putU32le response 8 session.RemoteIndex
                    Array.blit noise 0 response 12 noise.Length
                    Array.blit (Protocol.mac1 peer.Config.PublicKey response.[0..59]) 0 response 60 16
                    sendTo peer response
                    log (sprintf "<- initiation; -> response (index 0x%08x)" localIndex)
            with ex ->
                log (sprintf "<- initiation failed: %s" ex.Message)

    let handleResponse (msg: byte[]) (from: IPEndPoint) =
        if msg.Length = 92 then
            let receiverIndex = Wire.getU32le msg 8
            match indexTable.TryGetValue receiverIndex with
            | true, HandshakeEntry peer ->
                match peer.Handshake with
                | Some hs ->
                    try
                        let _, transport = hs.ReadMessage msg.[12..59]
                        let t = Option.get transport
                        let session =
                            { LocalIndex = receiverIndex
                              RemoteIndex = Wire.getU32le msg 4
                              Send = t.SendingCipherState
                              Recv = t.ReceivingCipherState
                              Replay = ReplayWindow()
                              Established = now ()
                              IsInitiator = true
                              Confirmed = true }
                        peer.Handshake <- None
                        peer.Endpoint <- Some from
                        installSession peer session
                        log (sprintf "<- handshake response; session established (index 0x%08x)" receiverIndex)
                        // Flush any packets queued during the handshake; if there were
                        // none, send a keepalive so the responder can start sending too.
                        if peer.Queued.IsEmpty then sendKeepalive peer else flushQueued peer session
                    with ex ->
                        log (sprintf "<- response failed: %s" ex.Message)
                | None -> ()
            | _ -> ()

    let handleTransport (msg: byte[]) (from: IPEndPoint) =
        if msg.Length >= 32 then
            let receiverIndex = Wire.getU32le msg 4
            match indexTable.TryGetValue receiverIndex with
            | true, SessionEntry(peer, session) ->
                let counter = Wire.getU64le msg 8
                session.Recv.SetNonce counter
                try
                    let plaintext = session.Recv.DecryptWithAd([||], msg.[16..])
                    if session.Replay.Accept counter then
                        peer.Endpoint <- Some from
                        if not session.Confirmed then session.Confirmed <- true
                        if plaintext.Length = 0 then
                            () // keepalive
                        else
                            tunnel.WritePacket(Wire.trimToIpLength plaintext)
                            if peer.KeepaliveDue.IsNone then peer.KeepaliveDue <- Some(now () + keepaliveTimeout)
                with _ -> ()
            | _ -> ()

    // ---- background loops ----

    let receiveLoop () =
        while running do
            let ok, msg, from =
                try
                    let m, f = bind.Receive()
                    true, m, f
                with _ -> false, [||], null
            if ok && msg.Length > 0 then
                lock stateLock (fun () ->
                    match msg.[0] with
                    | t when t = Protocol.MsgInitiation -> handleInitiation msg from
                    | t when t = Protocol.MsgResponse -> handleResponse msg from
                    | t when t = Protocol.MsgTransport -> handleTransport msg from
                    | _ -> ())

    let tunnelLoop () =
        while running do
            let packet = try tunnel.ReadPacket() with _ -> [||]
            if packet.Length > 0 then
                lock stateLock (fun () ->
                    match Wire.destinationOf packet with
                    | Some dst ->
                        match peers |> List.tryFind (fun p -> p.Config.AllowedIps |> List.exists (Wire.inCidr dst)) with
                        | Some peer -> sendPacket peer packet
                        | None -> ()
                    | None -> ())

    let timerLoop () =
        while running do
            Thread.Sleep 250
            lock stateLock (fun () ->
                let t = now ()
                for peer in peers do
                    // Retransmit a pending handshake, or give up after the attempt window.
                    match peer.Handshake with
                    | Some _ ->
                        if t - peer.HandshakeStarted > rekeyAttemptTime then
                            indexTable.Remove peer.HandshakeIndex |> ignore
                            peer.Handshake <- None
                        elif t - peer.LastInitiationSent > rekeyTimeout then
                            sendInitiation peer
                    | None ->
                        // Rekey before the current session gets too old (initiator only).
                        match peer.Current with
                        | Some s when s.IsInitiator && t - s.Established > rekeyAfterTime -> startHandshake peer
                        | _ -> ()
                    // Passive keepalive after receiving data.
                    match peer.KeepaliveDue with
                    | Some due when t >= due -> sendKeepalive peer; peer.KeepaliveDue <- None
                    | _ -> ()
                    // Persistent keepalive.
                    if peer.Config.PersistentKeepalive > 0
                       && peer.Current.IsSome
                       && t - peer.LastSent > TimeSpan.FromSeconds(float peer.Config.PersistentKeepalive) then
                        sendKeepalive peer)

    /// The device's static public key.
    member _.PublicKey = localStatic.PublicKey

    /// Start the device's background loops.
    member _.Start() =
        running <- true
        for body in [ receiveLoop; tunnelLoop; timerLoop ] do
            let th = Thread(ThreadStart(body), IsBackground = true)
            th.Start()
            threads.Add th
        // Kick off any peers configured with a persistent keepalive or endpoint.
        lock stateLock (fun () ->
            for peer in peers do
                if peer.Config.PersistentKeepalive > 0 && peer.Endpoint.IsSome then startHandshake peer)

    /// Stop the device and close its adapters.
    member _.Stop() =
        running <- false
        try bind.Close() with _ -> ()
        try tunnel.Close() with _ -> ()
