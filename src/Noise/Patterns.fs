namespace Noise

/// Handshake patterns (section 7 of the spec) and the parsing of pattern names
/// with modifiers (e.g. "XXpsk3", "XXfallback").
module Patterns =

    /// A handshake token.
    type Token =
        | E
        | S
        | EE
        | ES
        | SE
        | SS
        | PSK

    /// A pre-message line. `FromInitiator` is true for "-> ..." and false for "<- ...".
    type PreMessage =
        { FromInitiator: bool
          Tokens: Token list }

    /// A handshake pattern: its name, pre-messages, and message patterns. Each message
    /// pattern carries the sender direction (true = initiator sends, "->").
    type HandshakePattern =
        { Name: string
          PreMessages: PreMessage list
          Messages: (bool * Token list) list }

    let private pre fromInitiator tokens = { FromInitiator = fromInitiator; Tokens = tokens }

    // Tag message patterns with their sender: the initiator sends the first, then the
    // two parties alternate. (Modifiers like fallback may later change directions.)
    let private alt (tokenLists: Token list list) : (bool * Token list) list =
        tokenLists |> List.mapi (fun i toks -> (i % 2 = 0), toks)

    // ---- One-way patterns (section 7.2) ----
    let N = { Name = "N"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES ] ] }
    let K = { Name = "K"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = alt [ [ E; ES; SS ] ] }
    let X = { Name = "X"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES; S; SS ] ] }

    // ---- Interactive fundamental patterns (section 7.5) ----
    let NN = { Name = "NN"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE ] ] }
    let NK = { Name = "NK"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES ]; [ E; EE ] ] }
    let NX = { Name = "NX"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S; ES ] ] }
    let XN = { Name = "XN"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE ]; [ S; SE ] ] }
    let XK = { Name = "XK"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES ]; [ E; EE ]; [ S; SE ] ] }
    let XX = { Name = "XX"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S; ES ]; [ S; SE ] ] }
    let KN = { Name = "KN"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE; SE ] ] }
    let KK = { Name = "KK"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = alt [ [ E; ES; SS ]; [ E; EE; SE ] ] }
    let KX = { Name = "KX"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE; SE; S; ES ] ] }
    let IN = { Name = "IN"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE; SE ] ] }
    let IK = { Name = "IK"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES; S; SS ]; [ E; EE; SE ] ] }
    let IX = { Name = "IX"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE; SE; S; ES ] ] }

    // ---- Deferred patterns (section 7.6) ----
    // A "1" after a party's letter defers that party's authenticating DH by one message.
    let NK1 = { Name = "NK1"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E ]; [ E; EE; ES ] ] }
    let NX1 = { Name = "NX1"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S ]; [ ES ] ] }
    let X1N = { Name = "X1N"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE ]; [ S ]; [ SE ] ] }
    let X1K = { Name = "X1K"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES ]; [ E; EE ]; [ S ]; [ SE ] ] }
    let XK1 = { Name = "XK1"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E ]; [ E; EE; ES ]; [ S; SE ] ] }
    let X1K1 = { Name = "X1K1"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E ]; [ E; EE; ES ]; [ S ]; [ SE ] ] }
    let X1X = { Name = "X1X"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S; ES ]; [ S ]; [ SE ] ] }
    let XX1 = { Name = "XX1"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S ]; [ ES; S; SE ] ] }
    let X1X1 = { Name = "X1X1"; PreMessages = []; Messages = alt [ [ E ]; [ E; EE; S ]; [ ES; S ]; [ SE ] ] }
    let K1N = { Name = "K1N"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE ]; [ SE ] ] }
    let K1K = { Name = "K1K"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = alt [ [ E; ES ]; [ E; EE ]; [ SE ] ] }
    let KK1 = { Name = "KK1"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = alt [ [ E ]; [ E; EE; SE; ES ] ] }
    let K1K1 = { Name = "K1K1"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = alt [ [ E ]; [ E; EE; ES ]; [ SE ] ] }
    let K1X = { Name = "K1X"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE; S; ES ]; [ SE ] ] }
    let KX1 = { Name = "KX1"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE; SE; S ]; [ ES ] ] }
    let K1X1 = { Name = "K1X1"; PreMessages = [ pre true [ S ] ]; Messages = alt [ [ E ]; [ E; EE; S ]; [ SE; ES ] ] }
    let I1N = { Name = "I1N"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE ]; [ SE ] ] }
    let I1K = { Name = "I1K"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; ES; S ]; [ E; EE ]; [ SE ] ] }
    let IK1 = { Name = "IK1"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; S ]; [ E; EE; SE; ES ] ] }
    let I1K1 = { Name = "I1K1"; PreMessages = [ pre false [ S ] ]; Messages = alt [ [ E; S ]; [ E; EE; ES ]; [ SE ] ] }
    let I1X = { Name = "I1X"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE; S; ES ]; [ SE ] ] }
    let IX1 = { Name = "IX1"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE; SE; S ]; [ ES ] ] }
    let I1X1 = { Name = "I1X1"; PreMessages = []; Messages = alt [ [ E; S ]; [ E; EE; S ]; [ SE; ES ] ] }

    /// Every fundamental and deferred pattern, keyed by name.
    let fundamental =
        [ N; K; X; NN; NK; NX; XN; XK; XX; KN; KK; KX; IN; IK; IX
          NK1; NX1; X1N; X1K; XK1; X1K1; X1X; XX1; X1X1
          K1N; K1K; KK1; K1K1; K1X; KX1; K1X1
          I1N; I1K; IK1; I1K1; I1X; IX1; I1X1 ]
        |> List.map (fun p -> p.Name, p)
        |> Map.ofList

    /// Look up a fundamental pattern by its (unmodified) name.
    let byName name =
        match Map.tryFind name fundamental with
        | Some p -> p
        | None -> failwithf "Unknown handshake pattern: %s" name

    /// Apply a single `pskN` modifier, inserting a PSK token.
    /// psk0 prepends a PSK to the first message; pskN (N>=1) appends one to message N.
    let applyPsk (index: int) (pattern: HandshakePattern) : HandshakePattern =
        let msgs = pattern.Messages |> List.map (fun (dir, toks) -> dir, ResizeArray toks) |> List.toArray
        if index = 0 then msgs.[0] |> snd |> fun r -> r.Insert(0, PSK)
        elif index - 1 < msgs.Length then (snd msgs.[index - 1]).Add PSK
        else failwithf "psk%d is out of range for pattern %s" index pattern.Name
        { pattern with Messages = msgs |> Array.map (fun (dir, r) -> dir, List.ofSeq r) |> List.ofArray }

    /// Apply the `fallback` modifier (section 10.2): the first message must be sent by the
    /// initiator; its tokens are moved into the initiator's pre-message, so the responder
    /// now sends the first remaining message. Used to build Noise Pipes (e.g. XXfallback).
    let applyFallback (pattern: HandshakePattern) : HandshakePattern =
        match pattern.Messages with
        | (true, firstTokens) :: rest ->
            { pattern with
                PreMessages = pattern.PreMessages @ [ pre true firstTokens ]
                Messages = rest }
        | _ -> failwithf "fallback cannot be applied to pattern %s (first message must be initiator-sent)" pattern.Name

    /// Parse a pattern name section (the part between the first two underscores of a
    /// protocol name), e.g. "XX", "IK", "XXpsk3", "XXfallback", "NNpsk0+psk2". Returns
    /// the resolved pattern (with modifiers applied) and whether it uses PSKs.
    let parse (patternName: string) : HandshakePattern * bool =
        // The base pattern name is made of uppercase letters and digits (digits appear
        // in deferred names like "X1X1"); modifiers begin at the first lowercase letter.
        let baseLen =
            patternName
            |> Seq.takeWhile (fun c -> System.Char.IsUpper c || System.Char.IsDigit c)
            |> Seq.length
        let baseName = patternName.Substring(0, baseLen)
        let modifierPart = patternName.Substring(baseLen)
        let mutable pattern = byName baseName
        let mutable isPsk = false

        if modifierPart <> "" then
            for modifier in modifierPart.Split('+') do
                if modifier = "fallback" then
                    pattern <- applyFallback pattern
                elif modifier.StartsWith "psk" then
                    match System.Int32.TryParse(modifier.Substring 3) with
                    | true, n ->
                        pattern <- applyPsk n pattern
                        isPsk <- true
                    | _ -> failwithf "Invalid pattern modifier: %s" modifier
                else
                    failwithf "Unsupported pattern modifier: %s" modifier

        { pattern with Name = patternName }, isPsk
