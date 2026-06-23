module Noise.Tests.PrimitiveTests

open System
open Xunit
open Noise.Primitives

let private hex (s: string) = Convert.FromHexString s
let private toHex (b: byte[]) = Convert.ToHexString(b).ToLowerInvariant()

// HMAC is implemented from scratch, so validate it against RFC 4231 known answers.

[<Fact>]
let ``HMAC-SHA256 matches RFC 4231 test case 2`` () =
    let key = Text.Encoding.ASCII.GetBytes "Jefe"
    let data = Text.Encoding.ASCII.GetBytes "what do ya want for nothing?"
    Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", toHex (sha256.Hmac key data))

[<Fact>]
let ``HMAC-SHA512 matches RFC 4231 test case 2`` () =
    let key = Text.Encoding.ASCII.GetBytes "Jefe"
    let data = Text.Encoding.ASCII.GetBytes "what do ya want for nothing?"
    Assert.Equal(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        toHex (sha512.Hmac key data))

[<Fact>]
let ``HMAC-SHA256 handles keys longer than the block size (RFC 4231 case 6)`` () =
    let key = Array.create 131 0xaauy
    let data = Text.Encoding.ASCII.GetBytes "Test Using Larger Than Block-Size Key - Hash Key First"
    Assert.Equal("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", toHex (sha256.Hmac key data))

[<Fact>]
let ``HKDF produces the requested number of HASHLEN-sized outputs`` () =
    let ck = Array.create 32 0x01uy
    let ikm = Array.create 32 0x02uy
    let two = sha256.Hkdf ck ikm 2
    let three = sha512.Hkdf ck ikm 3
    Assert.Equal(2, two.Length)
    Assert.All(two, fun o -> Assert.Equal(32, o.Length))
    Assert.Equal(3, three.Length)
    Assert.All(three, fun o -> Assert.Equal(64, o.Length))
    // First two outputs are independent of num_outputs (both derive from the same temp key).
    Assert.Equal(toHex (sha512.Hkdf ck ikm 2).[0], toHex three.[0])

[<Theory>]
[<InlineData("25519")>]
[<InlineData("448")>]
let ``DH agreement is symmetric`` (dhName: string) =
    let dh = resolveDh dhName
    let a = dh.GenerateKeyPair()
    let b = dh.GenerateKeyPair()
    Assert.Equal(toHex (dh.Agreement a.PrivateKey b.PublicKey), toHex (dh.Agreement b.PrivateKey a.PublicKey))

[<Theory>]
[<InlineData("ChaChaPoly")>]
[<InlineData("AESGCM")>]
let ``AEAD round-trips and rejects tampering`` (cipherName: string) =
    let cipher = resolveCipher cipherName
    let key = Array.create 32 0x07uy
    let ad = Text.Encoding.ASCII.GetBytes "associated"
    let plaintext = Text.Encoding.ASCII.GetBytes "the quick brown fox"
    let ct = cipher.Encrypt key 5UL ad plaintext
    Assert.Equal(plaintext.Length + 16, ct.Length)
    Assert.Equal<byte[]>(plaintext, cipher.Decrypt key 5UL ad ct)
    // Wrong nonce, tampered ciphertext, and wrong AD must all fail.
    Assert.ThrowsAny<exn>(fun () -> cipher.Decrypt key 6UL ad ct |> ignore) |> ignore
    let tampered = Array.copy ct in tampered.[0] <- tampered.[0] ^^^ 0xffuy
    Assert.ThrowsAny<exn>(fun () -> cipher.Decrypt key 5UL ad tampered |> ignore) |> ignore
    Assert.ThrowsAny<exn>(fun () -> cipher.Decrypt key 5UL [||] ct |> ignore) |> ignore

[<Theory>]
[<InlineData("ChaChaPoly")>]
[<InlineData("AESGCM")>]
let ``Rekey returns a fresh 32-byte key`` (cipherName: string) =
    let cipher = resolveCipher cipherName
    let key = Array.create 32 0x07uy
    let rekeyed = cipher.Rekey key
    Assert.Equal(32, rekeyed.Length)
    Assert.NotEqual<byte[]>(key, rekeyed)
