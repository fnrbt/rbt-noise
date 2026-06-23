namespace Noise

/// Handshake patterns (section 7 of the spec) and the parsing of pattern names
/// with modifiers (e.g. "XXpsk3").
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

    /// A handshake pattern: its name, pre-messages, and message patterns.
    /// Message patterns alternate sender, starting with the initiator.
    type HandshakePattern =
        { Name: string
          PreMessages: PreMessage list
          Messages: Token list list }

    let private pre fromInitiator tokens = { FromInitiator = fromInitiator; Tokens = tokens }

    // ---- One-way patterns (section 7.2) ----
    let N = { Name = "N"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES ] ] }
    let K = { Name = "K"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = [ [ E; ES; SS ] ] }
    let X = { Name = "X"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES; S; SS ] ] }

    // ---- Interactive fundamental patterns (section 7.5) ----
    let NN = { Name = "NN"; PreMessages = []; Messages = [ [ E ]; [ E; EE ] ] }
    let NK = { Name = "NK"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES ]; [ E; EE ] ] }
    let NX = { Name = "NX"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S; ES ] ] }
    let XN = { Name = "XN"; PreMessages = []; Messages = [ [ E ]; [ E; EE ]; [ S; SE ] ] }
    let XK = { Name = "XK"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES ]; [ E; EE ]; [ S; SE ] ] }
    let XX = { Name = "XX"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S; ES ]; [ S; SE ] ] }
    let KN = { Name = "KN"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE; SE ] ] }
    let KK = { Name = "KK"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = [ [ E; ES; SS ]; [ E; EE; SE ] ] }
    let KX = { Name = "KX"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE; SE; S; ES ] ] }
    let IN = { Name = "IN"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE; SE ] ] }
    let IK = { Name = "IK"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES; S; SS ]; [ E; EE; SE ] ] }
    let IX = { Name = "IX"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE; SE; S; ES ] ] }

    // ---- Deferred patterns (section 7.6) ----
    // A "1" after a party's letter defers that party's authenticating DH by one message.
    let NK1 = { Name = "NK1"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E ]; [ E; EE; ES ] ] }
    let NX1 = { Name = "NX1"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S ]; [ ES ] ] }
    let X1N = { Name = "X1N"; PreMessages = []; Messages = [ [ E ]; [ E; EE ]; [ S ]; [ SE ] ] }
    let X1K = { Name = "X1K"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES ]; [ E; EE ]; [ S ]; [ SE ] ] }
    let XK1 = { Name = "XK1"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E ]; [ E; EE; ES ]; [ S; SE ] ] }
    let X1K1 = { Name = "X1K1"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E ]; [ E; EE; ES ]; [ S ]; [ SE ] ] }
    let X1X = { Name = "X1X"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S; ES ]; [ S ]; [ SE ] ] }
    let XX1 = { Name = "XX1"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S ]; [ ES; S; SE ] ] }
    let X1X1 = { Name = "X1X1"; PreMessages = []; Messages = [ [ E ]; [ E; EE; S ]; [ ES; S ]; [ SE ] ] }
    let K1N = { Name = "K1N"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE ]; [ SE ] ] }
    let K1K = { Name = "K1K"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = [ [ E; ES ]; [ E; EE ]; [ SE ] ] }
    let KK1 = { Name = "KK1"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = [ [ E ]; [ E; EE; SE; ES ] ] }
    let K1K1 = { Name = "K1K1"; PreMessages = [ pre true [ S ]; pre false [ S ] ]; Messages = [ [ E ]; [ E; EE; ES ]; [ SE ] ] }
    let K1X = { Name = "K1X"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE; S; ES ]; [ SE ] ] }
    let KX1 = { Name = "KX1"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE; SE; S ]; [ ES ] ] }
    let K1X1 = { Name = "K1X1"; PreMessages = [ pre true [ S ] ]; Messages = [ [ E ]; [ E; EE; S ]; [ SE; ES ] ] }
    let I1N = { Name = "I1N"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE ]; [ SE ] ] }
    let I1K = { Name = "I1K"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; ES; S ]; [ E; EE ]; [ SE ] ] }
    let IK1 = { Name = "IK1"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; S ]; [ E; EE; SE; ES ] ] }
    let I1K1 = { Name = "I1K1"; PreMessages = [ pre false [ S ] ]; Messages = [ [ E; S ]; [ E; EE; ES ]; [ SE ] ] }
    let I1X = { Name = "I1X"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE; S; ES ]; [ SE ] ] }
    let IX1 = { Name = "IX1"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE; SE; S ]; [ ES ] ] }
    let I1X1 = { Name = "I1X1"; PreMessages = []; Messages = [ [ E; S ]; [ E; EE; S ]; [ SE; ES ] ] }

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

    /// Apply one or more `pskN` modifiers, inserting PSK tokens.
    /// psk0 prepends a PSK to the first message; pskN (N>=1) appends one to message N.
    let applyPsk (indices: int list) (pattern: HandshakePattern) : HandshakePattern =
        let msgs = pattern.Messages |> List.map ResizeArray |> List.toArray
        for idx in indices do
            if idx = 0 then
                msgs.[0].Insert(0, PSK)
            elif idx - 1 < msgs.Length then
                msgs.[idx - 1].Add(PSK)
            else
                failwithf "psk%d is out of range for pattern %s" idx pattern.Name
        { pattern with Messages = msgs |> Array.map List.ofSeq |> List.ofArray }

    /// Parse a pattern name section (the part between the first two underscores of a
    /// protocol name), e.g. "XX", "IK", "XXpsk3", "Kpsk0+psk1". Returns the resolved
    /// pattern (with PSK tokens inserted) and whether it uses PSKs.
    let parse (patternName: string) : HandshakePattern * bool =
        // The base pattern name is made of uppercase letters and digits (digits appear
        // in deferred names like "X1X1"); modifiers begin at the first lowercase letter.
        let baseLen =
            patternName
            |> Seq.takeWhile (fun c -> System.Char.IsUpper c || System.Char.IsDigit c)
            |> Seq.length
        let baseName = patternName.Substring(0, baseLen)
        let modifierPart = patternName.Substring(baseLen)
        let basePattern = byName baseName

        if modifierPart = "" then
            basePattern, false
        else
            let pskIndices =
                modifierPart.Split('+')
                |> Array.map (fun m ->
                    if m.StartsWith "psk" then
                        match System.Int32.TryParse(m.Substring 3) with
                        | true, n -> n
                        | _ -> failwithf "Invalid pattern modifier: %s" m
                    else
                        failwithf "Unsupported pattern modifier: %s" m)
                |> Array.toList

            { applyPsk pskIndices basePattern with Name = patternName }, true
