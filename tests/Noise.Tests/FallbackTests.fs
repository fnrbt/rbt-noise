module Noise.Tests.FallbackTests

open System
open System.IO
open System.Text.Json
open Xunit
open Noise

// Validates the `fallback` modifier against the noise-c XXfallback known-answer
// vectors. Each vector models a Noise Pipe: the initiator first sends an IK
// initiation that the responder cannot decrypt; the responder then imports the
// initiator's ephemeral and both fall back to XXfallback (in which the responder
// sends the first message).

let private hexBytes (s: string) = Convert.FromHexString s

[<Fact>]
let ``all XXfallback vectors pass`` () =
    let path = Path.Combine(AppContext.BaseDirectory, "vectors", "fallback.txt")
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
            let parts = name.Split('_')
            let dhName, cipher, hash = parts.[2], parts.[3], parts.[4]
            let ikName = sprintf "Noise_IK_%s_%s_%s" dhName cipher hash
            let kp = Noise.keyPairFromPrivate dhName

            let initStatic = (bytes el "init_static").Value |> kp
            let initEph = (bytes el "init_ephemeral").Value |> kp
            let respStatic = (bytes el "resp_static").Value |> kp
            let respEph = (bytes el "resp_ephemeral").Value |> kp
            let initRemoteStatic = bytes el "init_remote_static"
            let initPrologue = bytesOrEmpty el "init_prologue"
            let respPrologue = bytesOrEmpty el "resp_prologue"

            let messages =
                [ for m in el.GetProperty("messages").EnumerateArray() ->
                    bytesOrEmpty m "payload", bytesOrEmpty m "ciphertext" ]

            // Message 0: the aborted IK initiation, written by the initiator.
            let aliceIk =
                Noise.createHandshake ikName true initPrologue
                    { HandshakeKeys.empty with
                        LocalStatic = Some initStatic
                        LocalEphemeral = Some initEph
                        RemoteStatic = initRemoteStatic }
            let ikMsg, _ = aliceIk.WriteMessage(fst messages.[0])
            if ikMsg <> snd messages.[0] then Some "IK initiation ciphertext mismatch"
            else

            // The responder recovers the initiator's ephemeral from that message
            // (it is the first DHLEN unencrypted bytes).
            let aliceEphemeralPub = ikMsg.[0 .. initEph.PublicKey.Length - 1]

            // Both parties fall back to XXfallback (responder sends first).
            let alice =
                Noise.createHandshake name true initPrologue
                    { HandshakeKeys.empty with LocalStatic = Some initStatic; LocalEphemeral = Some initEph }
            let bob =
                Noise.createHandshake name false respPrologue
                    { HandshakeKeys.empty with
                        LocalStatic = Some respStatic
                        LocalEphemeral = Some respEph
                        RemoteEphemeral = Some aliceEphemeralPub }

            // XXfallback: <- e, ee, s, es   (Bob)  ;  -> s, se   (Alice)
            let m1, _ = bob.WriteMessage(fst messages.[1])
            let p1, _ = alice.ReadMessage m1
            let m2, aliceT = alice.WriteMessage(fst messages.[2])
            let p2, bobT = bob.ReadMessage m2

            let mutable err = None
            if m1 <> snd messages.[1] then err <- Some "fallback message 1 mismatch"
            elif p1 <> fst messages.[1] then err <- Some "fallback message 1 payload mismatch"
            elif m2 <> snd messages.[2] then err <- Some "fallback message 2 mismatch"
            elif p2 <> fst messages.[2] then err <- Some "fallback message 2 payload mismatch"

            // Transport phase: alternates starting with the initiator (Alice).
            let aliceTransport = Option.get aliceT
            let bobTransport = Option.get bobT
            messages
            |> List.iteri (fun i (payload, expected) ->
                if i >= 3 && Option.isNone err then
                    let fromAlice = (i % 2) = 1 // index 3 -> Alice, 4 -> Bob, 5 -> Alice
                    let sendT, recvT = if fromAlice then aliceTransport, bobTransport else bobTransport, aliceTransport
                    let ct = sendT.WriteMessage payload
                    if ct <> expected then err <- Some(sprintf "transport message %d mismatch" i)
                    elif recvT.ReadMessage ct <> payload then err <- Some(sprintf "transport message %d payload mismatch" i))

            match err, bytes el "handshake_hash" with
            | Some _, _ -> err
            | None, Some hh when alice.HandshakeHash <> hh -> Some "handshake hash mismatch"
            | None, _ -> None
        with ex ->
            Some(sprintf "exception: %s" ex.Message)

    // Skip the legacy "NoisePSK_" vectors (pre-rev33 PSK scheme); we implement the
    // modern psk modifiers instead.
    let vectors =
        [ for el in doc.RootElement.GetProperty("vectors").EnumerateArray() do
            if (str el "name").Value.StartsWith "Noise_" then yield el ]

    let failures =
        vectors
        |> List.choose (fun el -> runVector el |> Option.map (fun err -> sprintf "%s: %s" (str el "name").Value err))

    Assert.True(vectors.Length >= 16, sprintf "expected modern XXfallback vectors, found %d" vectors.Length)
    Assert.True(failures.IsEmpty, sprintf "%d fallback vectors failed:\n%s" failures.Length (failures |> List.truncate 10 |> String.concat "\n"))
