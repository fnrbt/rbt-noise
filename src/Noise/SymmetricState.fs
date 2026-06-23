namespace Noise

/// SymmetricState (section 5.2 of the spec): wraps a CipherState and maintains
/// the chaining key `ck` and handshake hash `h`.
type SymmetricState(cipher: Cipher, hash: Hash) =
    let cipherState = CipherState(cipher)
    let mutable ck: byte[] = [||]
    let mutable h: byte[] = [||]

    // temp keys produced by HKDF are HASHLEN bytes; the cipher needs exactly 32.
    let truncateKey (k: byte[]) = if hash.HashLen = 64 then k.[0..31] else k

    /// The underlying CipherState.
    member _.CipherState = cipherState

    /// Whether the underlying CipherState currently holds a key.
    member _.HasKey = cipherState.HasKey

    /// InitializeSymmetric(protocol_name).
    member _.InitializeSymmetric(protocolName: byte[]) =
        h <-
            if protocolName.Length <= hash.HashLen then
                Array.append protocolName (Array.zeroCreate (hash.HashLen - protocolName.Length))
            else
                hash.Hash protocolName
        ck <- h
        cipherState.InitializeKey(None)

    /// MixKey(input_key_material).
    member _.MixKey(ikm: byte[]) =
        let out = hash.Hkdf ck ikm 2
        ck <- out.[0]
        cipherState.InitializeKey(Some(truncateKey out.[1]))

    /// MixHash(data).
    member _.MixHash(data: byte[]) = h <- hash.Hash(Array.append h data)

    /// MixKeyAndHash(input_key_material).  Used for PSKs.
    member _.MixKeyAndHash(ikm: byte[]) =
        let out = hash.Hkdf ck ikm 3
        ck <- out.[0]
        h <- hash.Hash(Array.append h out.[1])
        cipherState.InitializeKey(Some(truncateKey out.[2]))

    /// GetHandshakeHash().
    member _.GetHandshakeHash() = h

    /// EncryptAndHash(plaintext).
    member _.EncryptAndHash(plaintext: byte[]) : byte[] =
        let ciphertext = cipherState.EncryptWithAd(h, plaintext)
        h <- hash.Hash(Array.append h ciphertext)
        ciphertext

    /// DecryptAndHash(ciphertext).
    member _.DecryptAndHash(ciphertext: byte[]) : byte[] =
        let plaintext = cipherState.DecryptWithAd(h, ciphertext)
        h <- hash.Hash(Array.append h ciphertext)
        plaintext

    /// Split() -> the two transport CipherStates (c1 for initiator->responder).
    member _.Split() : CipherState * CipherState =
        let out = hash.Hkdf ck [||] 2
        let c1 = CipherState(cipher)
        let c2 = CipherState(cipher)
        c1.InitializeKey(Some(truncateKey out.[0]))
        c2.InitializeKey(Some(truncateKey out.[1]))
        c1, c2
