namespace Noise

/// CipherState (section 5.1 of the spec): an AEAD key together with a 64-bit
/// nonce counter. Used both during the handshake and for the transport phase.
type CipherState(cipher: Cipher) =
    let mutable key: byte[] option = None
    let mutable nonce: uint64 = 0UL

    // 2^64-1 is reserved (it is the nonce used by REKEY); it must never be used
    // to encrypt or decrypt a real message.
    static let maxNonce = System.UInt64.MaxValue

    /// The cipher function set this state uses.
    member _.Cipher = cipher

    /// InitializeKey(key).  Pass None to clear the key (the "empty" state).
    member _.InitializeKey(k: byte[] option) =
        key <- k
        nonce <- 0UL

    /// HasKey().
    member _.HasKey = key.IsSome

    /// SetNonce(n).
    member _.SetNonce(n: uint64) = nonce <- n

    /// The current nonce value.
    member _.Nonce = nonce

    /// EncryptWithAd(ad, plaintext).  Returns the plaintext unchanged if no key is set.
    member _.EncryptWithAd(ad: byte[], plaintext: byte[]) : byte[] =
        match key with
        | None -> plaintext
        | Some k ->
            if nonce = maxNonce then raise (System.OverflowException "Noise: nonce space exhausted")
            let ciphertext = cipher.Encrypt k nonce ad plaintext
            nonce <- nonce + 1UL
            ciphertext

    /// DecryptWithAd(ad, ciphertext).  Returns the ciphertext unchanged if no key is set.
    /// Throws on authentication failure; the nonce is only advanced on success.
    member _.DecryptWithAd(ad: byte[], ciphertext: byte[]) : byte[] =
        match key with
        | None -> ciphertext
        | Some k ->
            if nonce = maxNonce then raise (System.OverflowException "Noise: nonce space exhausted")
            let plaintext = cipher.Decrypt k nonce ad ciphertext
            nonce <- nonce + 1UL
            plaintext

    /// Rekey().  No-op if no key is set.
    member _.Rekey() =
        match key with
        | None -> ()
        | Some k -> key <- Some(cipher.Rekey k)
