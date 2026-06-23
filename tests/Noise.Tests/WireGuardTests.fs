module Noise.Tests.WireGuardTests

open System
open Xunit
open Noise
open WireGuard

// A self-contained WireGuard handshake + transport between the F# initiator and
// the F# responder (no network, no root). The live interoperability test against
// wireguard-go lives in tests/wg-interop/run-interop.sh.

let private newKey () = Noise.generateKeyPair "25519"

[<Fact>]
let ``initiator and responder complete a handshake and exchange transport data`` () =
    let initStatic = newKey ()
    let respStatic = newKey ()
    let psk = Array.create 32 0x42uy

    let initiator = Protocol.InitiatorSession(initStatic, respStatic.PublicKey, psk)
    let responder = Protocol.ResponderSession(respStatic, psk)

    // Handshake: initiation (148 bytes) -> response (92 bytes).
    let initiation = initiator.CreateInitiation()
    Assert.Equal(148, initiation.Length)
    Assert.Equal(Protocol.MsgInitiation, initiation.[0])

    let timestamp = responder.ReadInitiation initiation
    Assert.Equal(12, timestamp.Length)

    let response = responder.CreateResponse()
    Assert.Equal(92, response.Length)
    Assert.Equal(Protocol.MsgResponse, response.[0])

    initiator.ReadResponse response

    // Both sides established, agree on the handshake hash, and the responder learned
    // the initiator's static key.
    Assert.True(initiator.IsEstablished && responder.IsEstablished)
    Assert.Equal<byte[]>(initiator.HandshakeHash, responder.HandshakeHash)
    Assert.Equal<byte[]>(initStatic.PublicKey, Option.get responder.RemoteStaticPublic)

    // Transport data flows both ways. (Payloads are zero-padded to a 16-byte multiple.)
    let msg = Text.Encoding.ASCII.GetBytes "hello over wireguard"
    let onWire = initiator.EncryptTransport msg
    Assert.Equal(Protocol.MsgTransport, onWire.[0])
    let received = responder.DecryptTransport onWire
    Assert.Equal<byte[]>(msg, received.[0 .. msg.Length - 1])

    let reply = Text.Encoding.ASCII.GetBytes "and back from the responder"
    let decoded = initiator.DecryptTransport(responder.EncryptTransport reply)
    Assert.Equal<byte[]>(reply, decoded.[0 .. reply.Length - 1])

[<Fact>]
let ``a mismatched pre-shared key prevents the handshake`` () =
    let initStatic = newKey ()
    let respStatic = newKey ()
    let initiator = Protocol.InitiatorSession(initStatic, respStatic.PublicKey, Array.create 32 0x01uy)
    let responder = Protocol.ResponderSession(respStatic, Array.create 32 0x02uy)

    // In IKpsk2 the PSK is mixed in the *response* (message 2), so the initiation is
    // read fine but the initiator cannot authenticate the response under its own PSK.
    let initiation = initiator.CreateInitiation()
    responder.ReadInitiation initiation |> ignore
    let response = responder.CreateResponse()
    Assert.ThrowsAny<exn>(fun () -> initiator.ReadResponse response |> ignore) |> ignore
