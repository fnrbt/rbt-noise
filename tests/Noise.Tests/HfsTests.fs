module Noise.Tests.HfsTests

open System
open System.IO
open System.Text.Json
open Xunit
open Noise

// HFS (hybrid forward secrecy) tests.
//
// 1. Known-answer tests against the noise-c hybrid vectors that use "25519+448":
//    here the hybrid KEM is 448 adapted as a DH-based KEM, so the results are fully
//    deterministic and we can check them byte-for-byte. (The "25519+NewHope" vectors
//    are skipped — BouncyCastle does not provide NewHope.)
// 2. A self-consistency check with a real post-quantum KEM, ML-KEM-768.

let private hexBytes (s: string) = Convert.FromHexString s

let private kemKeyPairFromPrivate (kemName: string) (priv: byte[]) =
    (Primitives.resolveKem kemName).KeyPairFromPrivate priv

/// Drive a handshake to completion, then continue with transport messages, checking
/// every ciphertext (and the handshake hash) against the vector. Returns an error or None.
let private drive (init: HandshakeState) (resp: HandshakeState) (messages: (byte[] * byte[]) list) (handshakeHash: byte[] option) =
    let mutable initT: Transport option = None
    let mutable respT: Transport option = None
    let mutable err = None
    messages
    |> List.iteri (fun i (payload, expected) ->
        if Option.isNone err then
            let senderIsInit = i % 2 = 0
            match initT with
            | None ->
                let writer, reader = if senderIsInit then init, resp else resp, init
                let wire, wT = writer.WriteMessage payload
                if wire <> expected then err <- Some(sprintf "message %d ciphertext mismatch" i)
                else
                    let got, rT = reader.ReadMessage wire
                    if got <> payload then err <- Some(sprintf "message %d payload mismatch" i)
                    elif senderIsInit then initT <- wT; respT <- rT
                    else respT <- wT; initT <- rT
            | Some _ ->
                let sendT, recvT = if senderIsInit then initT.Value, respT.Value else respT.Value, initT.Value
                let wire = sendT.WriteMessage payload
                if wire <> expected then err <- Some(sprintf "transport %d ciphertext mismatch" i)
                elif recvT.ReadMessage wire <> payload then err <- Some(sprintf "transport %d payload mismatch" i))
    match err, handshakeHash with
    | Some _, _ -> err
    | None, Some hh when init.HandshakeHash <> hh -> Some "handshake hash mismatch"
    | None, _ -> None

[<Fact>]
let ``25519+448 HFS known-answer vectors pass`` () =
    let path = Path.Combine(AppContext.BaseDirectory, "vectors", "hybrid.txt")
    use doc = JsonDocument.Parse(File.ReadAllText path)

    let str (el: JsonElement) (name: string) =
        match el.TryGetProperty name with
        | true, v when v.ValueKind = JsonValueKind.String -> Some(v.GetString())
        | _ -> None
    let bytes el (name: string) = str el name |> Option.map hexBytes
    let bytesOrEmpty el (name: string) = bytes el name |> Option.defaultValue [||]

    let runVector (el: JsonElement) : string option =
        try
            let name = (str el "name").Value
            let dhName = name.Split('_').[2].Split('+').[0]
            let kemName = name.Split('_').[2].Split('+').[1]
            let dhKp = Noise.keyPairFromPrivate dhName
            let kemKp = kemKeyPairFromPrivate kemName

            let keys (side: string) =
                { LocalStatic = bytes el (side + "_static") |> Option.map dhKp
                  LocalEphemeral = bytes el (side + "_ephemeral") |> Option.map dhKp
                  RemoteStatic = bytes el (side + "_remote_static")
                  RemoteEphemeral = None
                  Psks = []
                  LocalHybridEphemeral = bytes el (side + "_hybrid_ephemeral") |> Option.map kemKp }

            let init = Noise.createHandshake name true (bytesOrEmpty el "init_prologue") (keys "init")
            let resp = Noise.createHandshake name false (bytesOrEmpty el "resp_prologue") (keys "resp")
            let messages =
                [ for m in el.GetProperty("messages").EnumerateArray() -> bytesOrEmpty m "payload", bytesOrEmpty m "ciphertext" ]
            drive init resp messages (bytes el "handshake_hash")
        with ex ->
            Some(sprintf "exception: %s" ex.Message)

    // Only the deterministic DH-based hybrid; skip NewHope and the fallback combo.
    let vectors =
        [ for el in doc.RootElement.GetProperty("vectors").EnumerateArray() do
            let name = (str el "name").Value
            if name.StartsWith "Noise_" && name.Contains "25519+448" && not (name.Contains "fallback") then
                yield el ]

    let failures =
        vectors
        |> List.choose (fun el -> runVector el |> Option.map (fun e -> sprintf "%s: %s" (str el "name").Value e))

    Assert.True(vectors.Length >= 90, sprintf "expected the 25519+448 hybrid vectors, found %d" vectors.Length)
    Assert.True(failures.IsEmpty, sprintf "%d/%d HFS vectors failed:\n%s" failures.Length vectors.Length (failures |> List.truncate 12 |> String.concat "\n"))

[<Theory>]
[<InlineData("Noise_NNhfs_25519+MLKEM768_ChaChaPoly_SHA256")>]
[<InlineData("Noise_XXhfs_25519+MLKEM768_AESGCM_BLAKE2s")>]
[<InlineData("Noise_IKhfs_25519+MLKEM768_ChaChaPoly_SHA512")>]
let ``post-quantum ML-KEM-768 HFS handshake is self-consistent`` (protocol: string) =
    let initStatic = Noise.generateKeyPair "25519"
    let respStatic = Noise.generateKeyPair "25519"
    let init =
        Noise.createHandshake protocol true [||]
            { HandshakeKeys.empty with LocalStatic = Some initStatic; RemoteStatic = Some respStatic.PublicKey }
    let resp =
        Noise.createHandshake protocol false [||]
            { HandshakeKeys.empty with LocalStatic = Some respStatic; RemoteStatic = Some initStatic.PublicKey }

    let mutable initT: Transport option = None
    let mutable respT: Transport option = None
    let mutable i = 0
    while Option.isNone initT do
        let writer, reader = if i % 2 = 0 then init, resp else resp, init
        let wire, wT = writer.WriteMessage [||]
        let _, rT = reader.ReadMessage wire
        if i % 2 = 0 then initT <- wT; respT <- rT else respT <- wT; initT <- rT
        i <- i + 1

    Assert.Equal<byte[]>(init.HandshakeHash, resp.HandshakeHash)
    let msg = Text.Encoding.ASCII.GetBytes "post-quantum hello"
    Assert.Equal<byte[]>(msg, respT.Value.ReadMessage(initT.Value.WriteMessage msg))
