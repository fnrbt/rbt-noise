namespace WireGuard

open System
open System.Security.Cryptography
open Noise
open Org.BouncyCastle.Crypto.Digests

/// A from-scratch implementation of the WireGuard handshake and transport protocol,
/// built on top of the Noise library. WireGuard's handshake is exactly the Noise
/// pattern `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` with the WireGuard IDENTIFIER as
/// the prologue and the responder's static key as the IK pre-message; this module
/// adds WireGuard's own message framing, mac1/mac2 fields, session indices, TAI64N
/// timestamp and counter-based transport records around that Noise core.
module Protocol =

    [<Literal>]
    let Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

    [<Literal>]
    let Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

    [<Literal>]
    let LabelMac1 = "mac1----"

    let private ascii (s: string) = Text.Encoding.ASCII.GetBytes s

    // ---- little/big-endian helpers ----
    let private putU32le (buf: byte[]) off (v: uint32) =
        buf.[off] <- byte v
        buf.[off + 1] <- byte (v >>> 8)
        buf.[off + 2] <- byte (v >>> 16)
        buf.[off + 3] <- byte (v >>> 24)

    let private getU32le (buf: byte[]) off =
        uint32 buf.[off]
        ||| (uint32 buf.[off + 1] <<< 8)
        ||| (uint32 buf.[off + 2] <<< 16)
        ||| (uint32 buf.[off + 3] <<< 24)

    let private putU64le (buf: byte[]) off (v: uint64) =
        for i in 0 .. 7 do
            buf.[off + i] <- byte (v >>> (8 * i))

    let private getU64le (buf: byte[]) off =
        let mutable v = 0UL
        for i in 0 .. 7 do
            v <- v ||| (uint64 buf.[off + i] <<< (8 * i))
        v

    let private putU64be (buf: byte[]) off (v: uint64) =
        for i in 0 .. 7 do
            buf.[off + i] <- byte (v >>> (8 * (7 - i)))

    let private putU32be (buf: byte[]) off (v: uint32) =
        for i in 0 .. 3 do
            buf.[off + i] <- byte (v >>> (8 * (3 - i)))

    /// Keyed BLAKE2s used by WireGuard's mac1 (and the cookie MAC). `outLen` bytes.
    let private blake2sKeyed (key: byte[]) (outLen: int) (data: byte[]) =
        let digest = Blake2sDigest(key, outLen, null, null)
        digest.BlockUpdate(data, 0, data.Length)
        let out = Array.zeroCreate outLen
        digest.DoFinal(out, 0) |> ignore
        out

    /// mac1 key for a peer: HASH(LABEL_MAC1 || that peer's static public key).
    let mac1Key (peerStaticPublic: byte[]) =
        Primitives.blake2s.Hash(Array.append (ascii LabelMac1) peerStaticPublic)

    /// WireGuard's TAI64N timestamp (12 bytes): a 64-bit big-endian TAI seconds count
    /// followed by a 32-bit big-endian nanoseconds count. Used for replay protection.
    let timestamp () =
        let now = DateTimeOffset.UtcNow
        let seconds = 0x400000000000000AUL + uint64 (now.ToUnixTimeSeconds())
        let nanos = uint32 ((now.UtcTicks % 10_000_000L) * 100L)
        let b = Array.zeroCreate 12
        putU64be b 0 seconds
        putU32be b 8 nanos
        b

    let private randomU32 () =
        let b = RandomNumberGenerator.GetBytes 4
        getU32le b 0

    // WireGuard message types.
    [<Literal>]
    let MsgInitiation = 1uy
    [<Literal>]
    let MsgResponse = 2uy
    [<Literal>]
    let MsgTransport = 4uy

    /// Pad a transport payload up to a multiple of 16 bytes, as WireGuard requires.
    let private pad16 (data: byte[]) =
        let padded = (data.Length + 15) / 16 * 16
        if padded = data.Length then data
        else Array.append data (Array.zeroCreate (padded - data.Length))

    /// Encode a transport data message (type 4): receiver index, the running send
    /// counter (used as the AEAD nonce), then the encrypted, padded payload.
    let private encodeTransport (transport: Transport) (receiverIndex: uint32) (payload: byte[]) =
        let counter = transport.SendingCipherState.Nonce
        let ciphertext = transport.SendingCipherState.EncryptWithAd([||], pad16 payload)
        let msg = Array.zeroCreate (16 + ciphertext.Length)
        msg.[0] <- MsgTransport
        putU32le msg 4 receiverIndex
        putU64le msg 8 counter
        Array.blit ciphertext 0 msg 16 ciphertext.Length
        msg

    /// Decode a transport data message, returning the (still padded) plaintext.
    let private decodeTransport (transport: Transport) (msg: byte[]) =
        transport.ReceivingCipherState.SetNonce(getU64le msg 8)
        transport.ReceivingCipherState.DecryptWithAd([||], msg.[16..])

    /// A WireGuard session driven from the initiator side. It owns the underlying
    /// Noise handshake and, once complete, the transport CipherStates.
    type InitiatorSession(localStatic: KeyPair, remoteStaticPublic: byte[], presharedKey: byte[]) =
        let psk = if isNull presharedKey then Array.zeroCreate 32 else presharedKey
        let handshake =
            Noise.createHandshake Construction true (ascii Identifier)
                { HandshakeKeys.empty with
                    LocalStatic = Some localStatic
                    RemoteStatic = Some remoteStaticPublic
                    Psks = [ psk ] }

        let senderIndex = randomU32 ()
        let mutable receiverIndex = 0u
        let mutable transport: Transport option = None

        /// Our session index (placed in the initiation; echoed by the responder).
        member _.SenderIndex = senderIndex

        /// True once the handshake response has been processed.
        member _.IsEstablished = transport.IsSome

        /// Build a 148-byte handshake initiation message (type 1).
        member _.CreateInitiation() : byte[] =
            // Noise IKpsk2 message 1: e, es, s, ss + payload(timestamp).
            // -> unencrypted_ephemeral(32) || encrypted_static(48) || encrypted_timestamp(28)
            let noise, _ = handshake.WriteMessage(timestamp ())
            let msg = Array.zeroCreate 148
            msg.[0] <- MsgInitiation
            putU32le msg 4 senderIndex
            Array.blit noise 0 msg 8 noise.Length // 108 bytes at offset 8
            // mac1 = keyed-BLAKE2s(mac1Key(responder static), msg[0 .. before mac1]).
            let mac1 = blake2sKeyed (mac1Key remoteStaticPublic) 16 msg.[0..115]
            Array.blit mac1 0 msg 116 16
            // mac2 stays zero (no cookie).
            msg

        /// Process a 92-byte handshake response (type 2). After this the session is
        /// established and transport messages can be exchanged.
        member _.ReadResponse(msg: byte[]) =
            if msg.Length <> 92 then invalidArg "msg" "WireGuard response must be 92 bytes"
            if msg.[0] <> MsgResponse then invalidArg "msg" "not a handshake response"
            receiverIndex <- getU32le msg 4 // responder's sender index
            // Noise IKpsk2 message 2: ephemeral(32) || encrypted_empty(16).
            let noise = msg.[12 .. 59]
            let _, t = handshake.ReadMessage noise
            transport <- Some(Option.get t)

        /// The final Noise handshake hash (a session channel binding).
        member _.HandshakeHash = handshake.HandshakeHash

        /// Encrypt a payload (e.g. an IP packet) into a transport data message (type 4).
        member _.EncryptTransport(payload: byte[]) : byte[] =
            encodeTransport (Option.get transport) receiverIndex payload

        /// Decrypt a transport data message (type 4) and return the padded plaintext.
        member _.DecryptTransport(msg: byte[]) : byte[] =
            decodeTransport (Option.get transport) msg


    /// A WireGuard session driven from the responder side: it answers an initiation,
    /// learning the initiator's static key during the handshake (the IK pattern).
    type ResponderSession(localStatic: KeyPair, presharedKey: byte[]) =
        let psk = if isNull presharedKey then Array.zeroCreate 32 else presharedKey
        let handshake =
            Noise.createHandshake Construction false (ascii Identifier)
                { HandshakeKeys.empty with LocalStatic = Some localStatic; Psks = [ psk ] }

        let senderIndex = randomU32 ()
        let mutable receiverIndex = 0u
        let mutable transport: Transport option = None
        let mutable remoteStatic: byte[] option = None

        /// Our session index (placed in the response).
        member _.SenderIndex = senderIndex

        /// The initiator's static public key, learned during the handshake.
        member _.RemoteStaticPublic = remoteStatic

        /// True once the response has been produced and the session is established.
        member _.IsEstablished = transport.IsSome

        /// The final Noise handshake hash.
        member _.HandshakeHash = handshake.HandshakeHash

        /// Process a 148-byte handshake initiation (type 1); returns its TAI64N timestamp.
        member _.ReadInitiation(msg: byte[]) : byte[] =
            if msg.Length <> 148 then invalidArg "msg" "WireGuard initiation must be 148 bytes"
            if msg.[0] <> MsgInitiation then invalidArg "msg" "not a handshake initiation"
            receiverIndex <- getU32le msg 4 // initiator's sender index
            let payload, _ = handshake.ReadMessage msg.[8..115] // noise: 108 bytes
            remoteStatic <- handshake.RemoteStaticKey
            payload

        /// Build a 92-byte handshake response (type 2). After this the session is established.
        member _.CreateResponse() : byte[] =
            // Noise IKpsk2 message 2: ephemeral(32) || encrypted_empty(16) = 48 bytes.
            let noise, t = handshake.WriteMessage [||]
            transport <- Some(Option.get t)
            let msg = Array.zeroCreate 92
            msg.[0] <- MsgResponse
            putU32le msg 4 senderIndex
            putU32le msg 8 receiverIndex
            Array.blit noise 0 msg 12 noise.Length // 48 bytes at offset 12
            // mac1 = keyed-BLAKE2s(mac1Key(initiator static), msg[0 .. before mac1]).
            let mac1 = blake2sKeyed (mac1Key (Option.get remoteStatic)) 16 msg.[0..59]
            Array.blit mac1 0 msg 60 16
            msg

        /// Encrypt a payload into a transport data message (type 4).
        member _.EncryptTransport(payload: byte[]) : byte[] =
            encodeTransport (Option.get transport) receiverIndex payload

        /// Decrypt a transport data message (type 4) and return the padded plaintext.
        member _.DecryptTransport(msg: byte[]) : byte[] =
            decodeTransport (Option.get transport) msg
