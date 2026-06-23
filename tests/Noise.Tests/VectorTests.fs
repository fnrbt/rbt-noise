module Noise.Tests.VectorTests

open System
open System.IO
open System.Text.Json
open Xunit
open Noise

// Known-answer tests against the Cacophony vector set, which exercises every
// fundamental and deferred pattern, the modern PSK modifiers (including combined
// ones such as psk0+psk2), both DH curves, both ciphers, and all four hashes.

type private Vector =
    { Name: string
      InitPrologue: byte[]
      InitStatic: byte[] option
      InitEphemeral: byte[] option
      InitRemoteStatic: byte[] option
      InitPsks: byte[] list
      RespPrologue: byte[]
      RespStatic: byte[] option
      RespEphemeral: byte[] option
      RespRemoteStatic: byte[] option
      RespPsks: byte[] list
      Messages: (byte[] * byte[]) list   // payload, expected ciphertext
      HandshakeHash: byte[] option }

let private hexBytes (s: string) = Convert.FromHexString s

let private loadVectors () =
    let path = Path.Combine(AppContext.BaseDirectory, "vectors", "cacophony.txt")
    use doc = JsonDocument.Parse(File.ReadAllText path)
    let str (el: JsonElement) (name: string) =
        match el.TryGetProperty name with
        | true, v when v.ValueKind = JsonValueKind.String -> Some(v.GetString())
        | _ -> None
    let bytes el (name: string) = str el name |> Option.map hexBytes
    let bytesOrEmpty el (name: string) = bytes el name |> Option.defaultValue [||]
    let psks (el: JsonElement) (name: string) =
        match el.TryGetProperty name with
        | true, v when v.ValueKind = JsonValueKind.Array -> [ for x in v.EnumerateArray() -> hexBytes (x.GetString()) ]
        | _ -> []
    [ for el in doc.RootElement.GetProperty("vectors").EnumerateArray() ->
        { Name = (str el "protocol_name").Value
          InitPrologue = bytesOrEmpty el "init_prologue"
          InitStatic = bytes el "init_static"
          InitEphemeral = bytes el "init_ephemeral"
          InitRemoteStatic = bytes el "init_remote_static"
          InitPsks = psks el "init_psks"
          RespPrologue = bytesOrEmpty el "resp_prologue"
          RespStatic = bytes el "resp_static"
          RespEphemeral = bytes el "resp_ephemeral"
          RespRemoteStatic = bytes el "resp_remote_static"
          RespPsks = psks el "resp_psks"
          Messages =
            [ for m in el.GetProperty("messages").EnumerateArray() ->
                bytesOrEmpty m "payload", bytesOrEmpty m "ciphertext" ]
          HandshakeHash = bytes el "handshake_hash" } ]

/// Run a single vector. Returns None on success, or Some error message on failure.
let private runVector (v: Vector) : string option =
    try
        let dhName = (Noise.parseProtocolName v.Name).Dh
        let kp = Noise.keyPairFromPrivate dhName
        let initKeys =
            { LocalStatic = v.InitStatic |> Option.map kp
              LocalEphemeral = v.InitEphemeral |> Option.map kp
              RemoteStatic = v.InitRemoteStatic
              RemoteEphemeral = None
              Psks = v.InitPsks }
        let respKeys =
            { LocalStatic = v.RespStatic |> Option.map kp
              LocalEphemeral = v.RespEphemeral |> Option.map kp
              RemoteStatic = v.RespRemoteStatic
              RemoteEphemeral = None
              Psks = v.RespPsks }

        let init = Noise.createHandshake v.Name true v.InitPrologue initKeys
        let resp = Noise.createHandshake v.Name false v.RespPrologue respKeys

        let oneWay = (fst (Patterns.parse (v.Name.Split('_').[1]))).Messages.Length = 1
        let mutable initT: Transport option = None
        let mutable respT: Transport option = None
        let mutable error = None

        v.Messages
        |> List.iteri (fun i (payload, expectedCt) ->
            if Option.isNone error then
                let senderIsInit = oneWay || (i % 2 = 0)
                match initT with
                | None ->
                    // Handshake phase.
                    let writer, reader = if senderIsInit then init, resp else resp, init
                    let wire, wT = writer.WriteMessage payload
                    if wire <> expectedCt then
                        error <- Some(sprintf "message %d ciphertext mismatch" i)
                    else
                        let got, rT = reader.ReadMessage wire
                        if got <> payload then error <- Some(sprintf "message %d payload mismatch on read" i)
                        elif senderIsInit then initT <- wT; respT <- rT
                        else respT <- wT; initT <- rT
                | Some _ ->
                    // Transport phase.
                    let sendT, recvT = if senderIsInit then initT.Value, respT.Value else respT.Value, initT.Value
                    let wire = sendT.WriteMessage payload
                    if wire <> expectedCt then error <- Some(sprintf "transport message %d ciphertext mismatch" i)
                    elif recvT.ReadMessage wire <> payload then error <- Some(sprintf "transport message %d payload mismatch" i))

        match error with
        | Some _ -> error
        | None ->
            match v.HandshakeHash with
            | Some hh when init.HandshakeHash <> hh -> Some "handshake hash mismatch"
            | _ -> None
    with ex ->
        Some(sprintf "exception: %s" ex.Message)

[<Fact>]
let ``all Cacophony vectors pass`` () =
    let vectors = loadVectors ()
    Assert.True(vectors.Length > 900, sprintf "expected the full vector set, loaded %d" vectors.Length)

    let failures =
        vectors
        |> List.choose (fun v -> runVector v |> Option.map (fun err -> sprintf "%s: %s" v.Name err))

    if not failures.IsEmpty then
        let shown = failures |> List.truncate 25 |> String.concat "\n"
        Assert.Fail(sprintf "%d/%d vectors failed:\n%s" failures.Length vectors.Length shown)
