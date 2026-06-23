namespace Noise

open Noise.Patterns

/// The transport phase. Produced when a handshake completes (Split). Holds the
/// two CipherStates and routes messages according to the local role: by Noise
/// convention the initiator sends with c1 / receives with c2, and the responder
/// does the reverse.
type Transport internal (c1: CipherState, c2: CipherState, initiator: bool, oneWay: bool, handshakeHash: byte[]) =
    let sending = if initiator then c1 else c2
    let receiving = if initiator then c2 else c1

    /// The final handshake hash (a unique channel binding for the session).
    member _.HandshakeHash = handshakeHash

    /// True for one-way patterns (N/K/X), where only the initiator may send.
    member _.IsOneWay = oneWay

    /// Encrypt and authenticate a transport message.
    member _.WriteMessage(payload: byte[]) : byte[] =
        if oneWay && not initiator then
            invalidOp "Noise: the responder cannot send transport messages in a one-way pattern"
        sending.EncryptWithAd([||], payload)

    /// Decrypt and verify a transport message.
    member _.ReadMessage(message: byte[]) : byte[] =
        if oneWay && initiator then
            invalidOp "Noise: the initiator cannot receive transport messages in a one-way pattern"
        receiving.DecryptWithAd([||], message)

    /// REKEY the outgoing CipherState.
    member _.RekeyOutgoing() = sending.Rekey()

    /// REKEY the incoming CipherState.
    member _.RekeyIncoming() = receiving.Rekey()


/// HandshakeState (section 5.3 of the spec). Drives a handshake to completion via
/// alternating WriteMessage / ReadMessage calls; the side whose turn it is calls
/// WriteMessage, the other ReadMessage. When the final message is processed both
/// calls return Some Transport.
type HandshakeState
    internal
    (
        pattern: HandshakePattern,
        isPsk: bool,
        initiator: bool,
        prologue: byte[],
        dh: Dh,
        cipher: Cipher,
        hash: Hash,
        protocolName: byte[],
        localStatic: KeyPair option,
        localEphemeral: KeyPair option,
        remoteStatic: byte[] option,
        remoteEphemeral: byte[] option,
        psks: byte[] list
    ) =

    let symmetric = SymmetricState(cipher, hash)

    let mutable s = localStatic
    let mutable e = localEphemeral
    let mutable rs = remoteStatic
    let mutable re = remoteEphemeral
    let mutable messageIndex = 0

    let messages = List.toArray pattern.Messages
    let oneWay = messages.Length = 1
    let pskQueue = System.Collections.Generic.Queue<byte[]>(psks: seq<byte[]>)

    // Perform a DH and mix the result into the symmetric state. The exact keys
    // depend on the token and on whether we are the initiator (sections 5.3, 7.1).
    let mixDh token =
        let secret =
            match token with
            | EE -> dh.Agreement (Option.get e).PrivateKey (Option.get re)
            | SS -> dh.Agreement (Option.get s).PrivateKey (Option.get rs)
            | ES ->
                if initiator then dh.Agreement (Option.get e).PrivateKey (Option.get rs)
                else dh.Agreement (Option.get s).PrivateKey (Option.get re)
            | SE ->
                if initiator then dh.Agreement (Option.get s).PrivateKey (Option.get re)
                else dh.Agreement (Option.get e).PrivateKey (Option.get rs)
            | _ -> failwith "Noise: not a DH token"
        symmetric.MixKey secret

    let splitIfDone () =
        if messageIndex = messages.Length then
            let c1, c2 = symmetric.Split()
            Some(Transport(c1, c2, initiator, oneWay, symmetric.GetHandshakeHash()))
        else
            None

    do
        symmetric.InitializeSymmetric protocolName
        symmetric.MixHash prologue
        // Mix in pre-message public keys, initiator's line first then responder's.
        for preMsg in pattern.PreMessages do
            let isOurs = preMsg.FromInitiator = initiator
            for token in preMsg.Tokens do
                match token with
                | E -> symmetric.MixHash(if isOurs then (Option.get e).PublicKey else Option.get re)
                | S -> symmetric.MixHash(if isOurs then (Option.get s).PublicKey else Option.get rs)
                | _ -> failwith "Noise: pre-messages may only contain e and s"

    /// The handshake hash so far. After the handshake completes this is the final
    /// channel-binding value (also available on the Transport).
    member _.HandshakeHash = symmetric.GetHandshakeHash()

    /// The remote party's static public key, once it is known.
    member _.RemoteStaticKey = rs

    /// The local static key pair, if any.
    member _.LocalStaticKey = s

    /// Whether this party is the initiator.
    member _.IsInitiator = initiator

    /// True once all message patterns have been processed.
    member _.IsComplete = messageIndex = messages.Length

    /// Write the next handshake message, encrypting `payload`. Returns the wire
    /// bytes and, if this was the final message, the resulting Transport.
    member _.WriteMessage(payload: byte[]) : byte[] * Transport option =
        if messageIndex >= messages.Length then invalidOp "Noise: handshake already complete"
        if initiator <> (messageIndex % 2 = 0) then invalidOp "Noise: not this party's turn to write"

        let buffer = System.Collections.Generic.List<byte>()
        for token in messages.[messageIndex] do
            match token with
            | E ->
                let kp =
                    match e with
                    | Some kp -> kp
                    | None ->
                        let kp = dh.GenerateKeyPair()
                        e <- Some kp
                        kp
                buffer.AddRange kp.PublicKey
                symmetric.MixHash kp.PublicKey
                if isPsk then symmetric.MixKey kp.PublicKey
            | S -> buffer.AddRange(symmetric.EncryptAndHash (Option.get s).PublicKey)
            | EE | ES | SE | SS -> mixDh token
            | PSK -> symmetric.MixKeyAndHash(pskQueue.Dequeue())

        buffer.AddRange(symmetric.EncryptAndHash payload)
        messageIndex <- messageIndex + 1
        buffer.ToArray(), splitIfDone ()

    /// Read the next handshake message, returning the decrypted payload and, if
    /// this was the final message, the resulting Transport.
    member _.ReadMessage(message: byte[]) : byte[] * Transport option =
        if messageIndex >= messages.Length then invalidOp "Noise: handshake already complete"
        if initiator <> (messageIndex % 2 = 1) then invalidOp "Noise: not this party's turn to read"

        let mutable offset = 0
        let read n =
            if offset + n > message.Length then invalidOp "Noise: handshake message is too short"
            let chunk = message.[offset .. offset + n - 1]
            offset <- offset + n
            chunk

        for token in messages.[messageIndex] do
            match token with
            | E ->
                let pub = read dh.DhLen
                re <- Some pub
                symmetric.MixHash pub
                if isPsk then symmetric.MixKey pub
            | S ->
                let len = if symmetric.HasKey then dh.DhLen + 16 else dh.DhLen
                rs <- Some(symmetric.DecryptAndHash(read len))
            | EE | ES | SE | SS -> mixDh token
            | PSK -> symmetric.MixKeyAndHash(pskQueue.Dequeue())

        let payload = symmetric.DecryptAndHash message.[offset..]
        messageIndex <- messageIndex + 1
        payload, splitIfDone ()
