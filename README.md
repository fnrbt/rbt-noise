# Noise (F#)

An implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
(revision 34) in F#. Everything from the protocol-name parser down to the handshake
state machine — including HMAC and HKDF — is implemented from scratch. The **only**
third-party code is the set of cryptographic primitives, which come from
[BouncyCastle](https://www.bouncycastle.org/) (X25519/X448, ChaCha20-Poly1305,
AES-GCM, SHA-256/512, BLAKE2s/BLAKE2b).

## What's implemented

| Category | Supported |
| --- | --- |
| One-way patterns | `N` `K` `X` |
| Interactive patterns | `NN` `NK` `NX` `XN` `XK` `XX` `KN` `KK` `KX` `IN` `IK` `IX` |
| Deferred patterns | all 23 (`NK1`, `X1X`, `IK1`, `K1K1`, …) |
| Modifiers | PSK (`psk0` … `pskN`, including combinations such as `psk0+psk2`) |
| DH | `25519`, `448` |
| Cipher | `ChaChaPoly`, `AESGCM` |
| Hash | `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b` |

From-scratch building blocks: `CipherState`, `SymmetricState`, `HandshakeState`,
HKDF, HMAC, nonce encoding, REKEY, pattern/protocol-name parsing, and the transport
split.

Not (yet) implemented: the `fallback` and `hfs` modifiers.

## Layout

```
src/Noise/
  Primitives.fs       DH/Cipher/Hash primitives (BouncyCastle) + HMAC/HKDF (from scratch)
  CipherState.fs      AEAD key + nonce (spec §5.1)
  SymmetricState.fs   chaining key + handshake hash (spec §5.2)
  Patterns.fs         all handshake patterns + name/modifier parsing (spec §7)
  HandshakeState.fs   the handshake driver + Transport (spec §5.3)
  Protocol.fs         public entry point (protocol-name parsing, key generation)
tests/Noise.Tests/    HMAC KATs, self-consistency tests, and 944 Cacophony KATs
```

## Build & test

```bash
dotnet build
dotnet test
```

The test suite validates the implementation against the full
[Cacophony](https://github.com/haskell-cryptography/cacophony) known-answer vector
set (944 vectors: every pattern × curve × cipher × hash, plus PSKs), and checks the
from-scratch HMAC against RFC 4231.

## Usage

```fsharp
open Noise

let proto = "Noise_XX_25519_ChaChaPoly_SHA256"

// Long-term static keys (persist and reuse these in a real application).
let initStatic = Noise.generateKeyPair "25519"
let respStatic = Noise.generateKeyPair "25519"

let init = Noise.createHandshake proto true  [||] { HandshakeKeys.empty with LocalStatic = Some initStatic }
let resp = Noise.createHandshake proto false [||] { HandshakeKeys.empty with LocalStatic = Some respStatic }

// XX: -> e ; <- e, ee, s, es ; -> s, se
let m0, _ = init.WriteMessage [||]
resp.ReadMessage m0 |> ignore

let m1, _ = resp.WriteMessage [||]
init.ReadMessage m1 |> ignore

// The final WriteMessage/ReadMessage return Some Transport once the handshake completes.
let m2, initTransport = init.WriteMessage [||]
let _,  respTransport = resp.ReadMessage m2

let initT = Option.get initTransport
let respT = Option.get respTransport

// Encrypted transport phase.
let ciphertext = initT.WriteMessage (System.Text.Encoding.UTF8.GetBytes "hello")
let plaintext  = respT.ReadMessage ciphertext   // "hello"
```

Each handshake message returns `byte[] * Transport option`; the `Transport` is
`Some` exactly on the message that completes the handshake. Supply only the keys a
pattern needs via `HandshakeKeys` (e.g. `RemoteStatic` for `NK`/`IK`, `Psks` for PSK
patterns); unused fields are ignored.

## License

The cryptographic primitives are provided by BouncyCastle (MIT). The rest of this
code is available under the MIT license.
