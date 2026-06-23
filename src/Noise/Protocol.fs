namespace Noise

open System.Text
open Noise.Primitives

/// The four function-set names parsed out of a Noise protocol name.
type ProtocolName =
    { Pattern: string
      Dh: string
      Cipher: string
      Hash: string }

    /// Render back to the canonical "Noise_<pattern>_<dh>_<cipher>_<hash>" string.
    override this.ToString() =
        sprintf "Noise_%s_%s_%s_%s" this.Pattern this.Dh this.Cipher this.Hash

/// Keys and PSKs supplied to a handshake. Use HandshakeKeys.empty and override the
/// fields the chosen pattern requires; omitted keys that the pattern needs will
/// surface as an error when the handshake reaches the relevant token.
type HandshakeKeys =
    { /// The local static key pair (s).
      LocalStatic: KeyPair option
      /// A fixed local ephemeral (e). Normally None — ephemerals are generated.
      /// Provided mainly to reproduce test vectors deterministically.
      LocalEphemeral: KeyPair option
      /// The remote static public key (rs), for patterns that know it up front.
      RemoteStatic: byte[] option
      /// The remote ephemeral public key (re), for fallback-style setups.
      RemoteEphemeral: byte[] option
      /// Pre-shared keys, in the order the psk modifiers consume them.
      Psks: byte[] list }

    static member empty =
        { LocalStatic = None
          LocalEphemeral = None
          RemoteStatic = None
          RemoteEphemeral = None
          Psks = [] }

/// Top-level entry point for the library.
[<RequireQualifiedAccess>]
module Noise =

    /// Parse "Noise_XX_25519_ChaChaPoly_SHA256" into its components.
    let parseProtocolName (name: string) : ProtocolName =
        let parts = name.Split('_')
        if parts.Length <> 5 || parts.[0] <> "Noise" then
            failwithf "Invalid Noise protocol name: %s" name
        { Pattern = parts.[1]; Dh = parts.[2]; Cipher = parts.[3]; Hash = parts.[4] }

    /// Generate a fresh static key pair for the named DH function ("25519" or "448").
    let generateKeyPair (dhName: string) : KeyPair = (resolveDh dhName).GenerateKeyPair()

    /// Reconstruct a key pair from a raw private key for the named DH function.
    let keyPairFromPrivate (dhName: string) (privateKey: byte[]) : KeyPair =
        (resolveDh dhName).KeyPairFromPrivate privateKey

    /// Create a HandshakeState for the given protocol name.
    let createHandshake (protocolName: string) (initiator: bool) (prologue: byte[]) (keys: HandshakeKeys) : HandshakeState =
        let parsed = parseProtocolName protocolName
        let pattern, isPsk = Patterns.parse parsed.Pattern
        let dh = resolveDh parsed.Dh
        let cipher = resolveCipher parsed.Cipher
        let hash = resolveHash parsed.Hash
        let protocolBytes = Encoding.ASCII.GetBytes protocolName

        HandshakeState(
            pattern,
            isPsk,
            initiator,
            prologue,
            dh,
            cipher,
            hash,
            protocolBytes,
            keys.LocalStatic,
            keys.LocalEphemeral,
            keys.RemoteStatic,
            keys.RemoteEphemeral,
            keys.Psks
        )
