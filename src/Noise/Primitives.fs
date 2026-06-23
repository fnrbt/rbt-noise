namespace Noise

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Agreement
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Modes
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Security

/// A Diffie-Hellman key pair. Both keys are raw little-endian byte encodings
/// (32 bytes for 25519, 56 bytes for 448).
type KeyPair =
    { PrivateKey: byte[]
      PublicKey: byte[] }

/// A Noise DH function set (section 4.1 of the spec).
type Dh =
    { Name: string
      /// Length in bytes of public keys and DH outputs (DHLEN).
      DhLen: int
      /// GENERATE_KEYPAIR().
      GenerateKeyPair: unit -> KeyPair
      /// Reconstruct a key pair from a raw private key.
      KeyPairFromPrivate: byte[] -> KeyPair
      /// DH(key_pair, public_key) -> shared secret.  Args: privateKey, remotePublicKey.
      Agreement: byte[] -> byte[] -> byte[] }

/// A Noise AEAD cipher function set (section 4.2 of the spec).
type Cipher =
    { Name: string
      /// ENCRYPT(k, n, ad, plaintext).  Args: key, nonce, ad, plaintext.
      Encrypt: byte[] -> uint64 -> byte[] -> byte[] -> byte[]
      /// DECRYPT(k, n, ad, ciphertext).  Args: key, nonce, ad, ciphertext.  Throws on auth failure.
      Decrypt: byte[] -> uint64 -> byte[] -> byte[] -> byte[]
      /// REKEY(k).
      Rekey: byte[] -> byte[] }

/// A Noise hash function set (section 4.3 of the spec), together with the
/// HMAC and HKDF constructions Noise builds on top of it.
type Hash =
    { Name: string
      /// HASHLEN.
      HashLen: int
      /// BLOCKLEN (the hash's internal block size, used by HMAC).
      BlockLen: int
      /// HASH(data).
      Hash: byte[] -> byte[]
      /// HMAC-HASH(key, data).
      Hmac: byte[] -> byte[] -> byte[]
      /// HKDF(chaining_key, input_key_material, num_outputs) -> num_outputs HASHLEN-byte slices.
      Hkdf: byte[] -> byte[] -> int -> byte[][] }

/// Cryptographic primitives. These are the *only* pieces backed by a third-party
/// library (BouncyCastle): the raw DH, AEAD and hash primitives. Everything Noise
/// layers on top of them — HMAC, HKDF, the state machine — is implemented here.
module Primitives =

    // ----------------------------------------------------------------------
    // Diffie-Hellman
    // ----------------------------------------------------------------------

    let private rng = SecureRandom()

    let dh25519: Dh =
        { Name = "25519"
          DhLen = 32
          GenerateKeyPair = fun () ->
            let priv = X25519PrivateKeyParameters(rng)
            { PrivateKey = priv.GetEncoded(); PublicKey = priv.GeneratePublicKey().GetEncoded() }
          KeyPairFromPrivate = fun privateKey ->
            let priv = X25519PrivateKeyParameters(privateKey, 0)
            { PrivateKey = priv.GetEncoded(); PublicKey = priv.GeneratePublicKey().GetEncoded() }
          Agreement = fun privateKey remotePublicKey ->
            let priv = X25519PrivateKeyParameters(privateKey, 0)
            let pub = X25519PublicKeyParameters(remotePublicKey, 0)
            let agreement = X25519Agreement()
            agreement.Init(priv)
            let secret = Array.zeroCreate agreement.AgreementSize
            agreement.CalculateAgreement(pub, secret, 0)
            secret }

    let dh448: Dh =
        { Name = "448"
          DhLen = 56
          GenerateKeyPair = fun () ->
            let priv = X448PrivateKeyParameters(rng)
            { PrivateKey = priv.GetEncoded(); PublicKey = priv.GeneratePublicKey().GetEncoded() }
          KeyPairFromPrivate = fun privateKey ->
            let priv = X448PrivateKeyParameters(privateKey, 0)
            { PrivateKey = priv.GetEncoded(); PublicKey = priv.GeneratePublicKey().GetEncoded() }
          Agreement = fun privateKey remotePublicKey ->
            let priv = X448PrivateKeyParameters(privateKey, 0)
            let pub = X448PublicKeyParameters(remotePublicKey, 0)
            let agreement = X448Agreement()
            agreement.Init(priv)
            let secret = Array.zeroCreate agreement.AgreementSize
            agreement.CalculateAgreement(pub, secret, 0)
            secret }

    // ----------------------------------------------------------------------
    // AEAD ciphers
    // ----------------------------------------------------------------------

    /// ChaChaPoly nonce: 4 zero bytes followed by the 8-byte little-endian encoding of n.
    let private nonceLittleEndian (n: uint64) =
        let b = Array.zeroCreate 12
        let mutable v = n
        for i in 0 .. 7 do
            b.[4 + i] <- byte (v &&& 0xFFUL)
            v <- v >>> 8
        b

    /// AESGCM nonce: 4 zero bytes followed by the 8-byte big-endian encoding of n.
    let private nonceBigEndian (n: uint64) =
        let b = Array.zeroCreate 12
        let mutable v = n
        for i in 0 .. 7 do
            b.[11 - i] <- byte (v &&& 0xFFUL)
            v <- v >>> 8
        b

    let private aeadEncrypt (factory: unit -> IAeadCipher) (nonce: byte[]) (key: byte[]) (ad: byte[]) (plaintext: byte[]) =
        let cipher = factory ()
        cipher.Init(true, AeadParameters(KeyParameter(key), 128, nonce))
        if ad.Length > 0 then cipher.ProcessAadBytes(ad, 0, ad.Length)
        let output = Array.zeroCreate (cipher.GetOutputSize(plaintext.Length))
        let mutable len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0)
        cipher.DoFinal(output, len) |> ignore
        output

    let private aeadDecrypt (factory: unit -> IAeadCipher) (nonce: byte[]) (key: byte[]) (ad: byte[]) (ciphertext: byte[]) =
        let cipher = factory ()
        cipher.Init(false, AeadParameters(KeyParameter(key), 128, nonce))
        if ad.Length > 0 then cipher.ProcessAadBytes(ad, 0, ad.Length)
        let output = Array.zeroCreate (cipher.GetOutputSize(ciphertext.Length))
        let len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0)
        cipher.DoFinal(output, len) |> ignore
        output

    let private maxNonce = System.UInt64.MaxValue

    let private mkCipher name (encodeNonce: uint64 -> byte[]) (factory: unit -> IAeadCipher) : Cipher =
        { Name = name
          Encrypt = fun key n ad pt -> aeadEncrypt factory (encodeNonce n) key ad pt
          Decrypt = fun key n ad ct -> aeadDecrypt factory (encodeNonce n) key ad ct
          // REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32]), truncated to the first 32 bytes.
          Rekey = fun key -> (aeadEncrypt factory (encodeNonce maxNonce) key [||] (Array.zeroCreate 32)).[0..31] }

    let chaChaPoly: Cipher =
        mkCipher "ChaChaPoly" nonceLittleEndian (fun () -> ChaCha20Poly1305() :> IAeadCipher)

    let aesGcm: Cipher =
        mkCipher "AESGCM" nonceBigEndian (fun () -> GcmBlockCipher(AesEngine()) :> IAeadCipher)

    // ----------------------------------------------------------------------
    // Hashes (+ HMAC and HKDF built from scratch on the raw hash)
    // ----------------------------------------------------------------------

    let private mkHash name hashLen (newDigest: unit -> IDigest) : Hash =
        let blockLen = (newDigest ()).GetByteLength()

        let hashOf (parts: byte[] list) =
            let d = newDigest ()
            for p in parts do
                if p.Length > 0 then d.BlockUpdate(p, 0, p.Length)
            let out = Array.zeroCreate (d.GetDigestSize())
            d.DoFinal(out, 0) |> ignore
            out

        let hash data = hashOf [ data ]

        // HMAC per RFC 2104, built only from the raw hash primitive.
        let hmac (key: byte[]) (data: byte[]) =
            let k =
                if key.Length > blockLen then
                    let h = hash key
                    Array.append h (Array.zeroCreate (blockLen - h.Length))
                else
                    Array.append key (Array.zeroCreate (blockLen - key.Length))
            let ipad = Array.map (fun b -> b ^^^ 0x36uy) k
            let opad = Array.map (fun b -> b ^^^ 0x5cuy) k
            hashOf [ opad; hashOf [ ipad; data ] ]

        // HKDF per the Noise spec (section 4.3), built from HMAC.
        let hkdf (chainingKey: byte[]) (ikm: byte[]) (numOutputs: int) =
            let tempKey = hmac chainingKey ikm
            let output1 = hmac tempKey [| 0x01uy |]
            let output2 = hmac tempKey (Array.append output1 [| 0x02uy |])
            if numOutputs = 2 then
                [| output1; output2 |]
            else
                let output3 = hmac tempKey (Array.append output2 [| 0x03uy |])
                [| output1; output2; output3 |]

        { Name = name; HashLen = hashLen; BlockLen = blockLen; Hash = hash; Hmac = hmac; Hkdf = hkdf }

    let sha256: Hash = mkHash "SHA256" 32 (fun () -> Sha256Digest() :> IDigest)
    let sha512: Hash = mkHash "SHA512" 64 (fun () -> Sha512Digest() :> IDigest)
    let blake2s: Hash = mkHash "BLAKE2s" 32 (fun () -> Blake2sDigest() :> IDigest)
    let blake2b: Hash = mkHash "BLAKE2b" 64 (fun () -> Blake2bDigest() :> IDigest)

    // ----------------------------------------------------------------------
    // Resolution by name (as found in a protocol name)
    // ----------------------------------------------------------------------

    let resolveDh =
        function
        | "25519" -> dh25519
        | "448" -> dh448
        | name -> failwithf "Unknown DH function: %s" name

    let resolveCipher =
        function
        | "ChaChaPoly" -> chaChaPoly
        | "AESGCM" -> aesGcm
        | name -> failwithf "Unknown cipher function: %s" name

    let resolveHash =
        function
        | "SHA256" -> sha256
        | "SHA512" -> sha512
        | "BLAKE2s" -> blake2s
        | "BLAKE2b" -> blake2b
        | name -> failwithf "Unknown hash function: %s" name
