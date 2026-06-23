module Noise.Tests.SelfConsistencyTests

open System
open Xunit
open Noise

/// Drive a handshake to completion with freshly generated keys, returning both
/// transports. Static keys (and their cross-known public keys) and PSKs are
/// supplied to both sides; unused ones are simply ignored by the pattern.
let private completeHandshake (protocolName: string) =
    let dhName = (Noise.parseProtocolName protocolName).Dh
    let patternSection = protocolName.Split('_').[1]
    let pattern, _ = Patterns.parse patternSection
    let oneWay = pattern.Messages.Length = 1
    let pskCount =
        (patternSection.Split('+') |> Array.filter (fun m -> m.Contains "psk")).Length

    let initStatic = Noise.generateKeyPair dhName
    let respStatic = Noise.generateKeyPair dhName
    let psks = [ for i in 0 .. pskCount - 1 -> Array.create 32 (byte (0x40 + i)) ]

    let initKeys =
        { HandshakeKeys.empty with
            LocalStatic = Some initStatic
            RemoteStatic = Some respStatic.PublicKey
            Psks = psks }
    let respKeys =
        { HandshakeKeys.empty with
            LocalStatic = Some respStatic
            RemoteStatic = Some initStatic.PublicKey
            Psks = psks }

    let init = Noise.createHandshake protocolName true [||] initKeys
    let resp = Noise.createHandshake protocolName false [||] respKeys

    let mutable initT: Transport option = None
    let mutable respT: Transport option = None
    let mutable i = 0
    while Option.isNone initT do
        let writer, reader = if i % 2 = 0 then init, resp else resp, init
        let payload = Text.Encoding.ASCII.GetBytes(sprintf "handshake payload %d" i)
        let wire, wT = writer.WriteMessage payload
        let got, rT = reader.ReadMessage wire
        Assert.Equal<byte[]>(payload, got)
        if i % 2 = 0 then initT <- wT; respT <- rT else respT <- wT; initT <- rT
        i <- i + 1

    // Both sides must agree on the handshake hash.
    Assert.Equal(Convert.ToHexString init.HandshakeHash, Convert.ToHexString resp.HandshakeHash)
    oneWay, initT.Value, respT.Value

let private roundTrip (sender: Transport) (receiver: Transport) (text: string) =
    let payload = Text.Encoding.UTF8.GetBytes text
    let ct = sender.WriteMessage payload
    Assert.Equal<byte[]>(payload, receiver.ReadMessage ct)

// A representative slice of the matrix: one-way, the popular interactive patterns,
// a deferred pattern, single and combined PSKs, across all four cipher/hash kinds.
[<Theory>]
[<InlineData("Noise_N_25519_ChaChaPoly_SHA256")>]
[<InlineData("Noise_X_448_AESGCM_SHA512")>]
[<InlineData("Noise_NN_25519_ChaChaPoly_BLAKE2s")>]
[<InlineData("Noise_XX_25519_ChaChaPoly_SHA256")>]
[<InlineData("Noise_XX_448_AESGCM_BLAKE2b")>]
[<InlineData("Noise_IK_25519_AESGCM_SHA256")>]
[<InlineData("Noise_XK_25519_ChaChaPoly_SHA512")>]
[<InlineData("Noise_KK_25519_ChaChaPoly_SHA256")>]
[<InlineData("Noise_X1X1_25519_AESGCM_SHA256")>]
[<InlineData("Noise_NNpsk0_25519_ChaChaPoly_SHA256")>]
[<InlineData("Noise_XXpsk3_25519_AESGCM_BLAKE2b")>]
[<InlineData("Noise_NNpsk0+psk2_25519_ChaChaPoly_BLAKE2s")>]
let ``handshake completes and transport messages round-trip`` (protocolName: string) =
    let oneWay, initT, respT = completeHandshake protocolName

    Assert.Equal<byte[]>(initT.HandshakeHash, respT.HandshakeHash)

    // Initiator -> responder always works.
    roundTrip initT respT "first transport message"
    roundTrip initT respT "second transport message"

    if oneWay then
        // The responder cannot send in a one-way pattern.
        Assert.Throws<InvalidOperationException>(fun () -> respT.WriteMessage [||] |> ignore) |> ignore
    else
        // Interactive patterns are bidirectional.
        roundTrip respT initT "reply from responder"
        roundTrip initT respT "and back again"

[<Fact>]
let ``tampered transport message fails authentication`` () =
    let _, initT, respT = completeHandshake "Noise_XX_25519_ChaChaPoly_SHA256"
    let ct = initT.WriteMessage (Text.Encoding.ASCII.GetBytes "secret")
    let tampered = Array.copy ct
    tampered.[tampered.Length - 1] <- tampered.[tampered.Length - 1] ^^^ 0x01uy
    Assert.ThrowsAny<exn>(fun () -> respT.ReadMessage tampered |> ignore) |> ignore

[<Fact>]
let ``a wrong pre-shared key breaks the handshake`` () =
    let proto = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
    let init = Noise.createHandshake proto true [||] { HandshakeKeys.empty with Psks = [ Array.create 32 0x01uy ] }
    let resp = Noise.createHandshake proto false [||] { HandshakeKeys.empty with Psks = [ Array.create 32 0x02uy ] }
    let msg0, _ = init.WriteMessage [||]
    // psk0 keys message 0, so the responder cannot even authenticate it under a different PSK.
    Assert.ThrowsAny<exn>(fun () -> resp.ReadMessage msg0 |> ignore) |> ignore

[<Fact>]
let ``the remote static key is exposed once learned`` () =
    let dhName = "25519"
    let respStatic = Noise.generateKeyPair dhName
    let initStatic = Noise.generateKeyPair dhName
    let init = Noise.createHandshake "Noise_XX_25519_ChaChaPoly_SHA256" true [||] { HandshakeKeys.empty with LocalStatic = Some initStatic }
    let resp = Noise.createHandshake "Noise_XX_25519_ChaChaPoly_SHA256" false [||] { HandshakeKeys.empty with LocalStatic = Some respStatic }
    // -> e
    let m0, _ = init.WriteMessage [||]
    resp.ReadMessage m0 |> ignore
    // <- e, ee, s, es   (responder sends its static; initiator learns it)
    let m1, _ = resp.WriteMessage [||]
    init.ReadMessage m1 |> ignore
    Assert.Equal<byte[]>(respStatic.PublicKey, Option.get init.RemoteStaticKey)
    // -> s, se   (initiator sends its static; responder learns it)
    let m2, _ = init.WriteMessage [||]
    resp.ReadMessage m2 |> ignore
    Assert.Equal<byte[]>(initStatic.PublicKey, Option.get resp.RemoteStaticKey)
