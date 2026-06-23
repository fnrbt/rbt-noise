namespace WireGuard

open System
open System.Collections.Concurrent
open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices

/// A tunnel device: a source/sink of raw IP packets (the data plane). The real VPN
/// uses a TUN device; tests use an in-memory implementation.
type ITunnel =
    /// Block until one outbound IP packet is available; return it (or [||] when closed).
    abstract member ReadPacket: unit -> byte[]
    /// Inject one inbound IP packet.
    abstract member WritePacket: byte[] -> unit
    abstract member Close: unit -> unit

/// A UDP transport (the encrypted wire). Default implementation binds a socket.
type IBind =
    /// Block until a datagram arrives; return its bytes and source endpoint.
    abstract member Receive: unit -> byte[] * IPEndPoint
    abstract member Send: byte[] -> IPEndPoint -> unit
    abstract member Close: unit -> unit


/// An in-memory tunnel for tests: outbound packets are pushed in, inbound packets
/// are collected for inspection.
type MockTunnel() =
    let outbound = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>())
    let inbound = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>())

    /// Queue an IP packet for the device to send through the tunnel.
    member _.InjectOutbound(packet: byte[]) = outbound.Add packet

    /// Take an IP packet the device decrypted and delivered (blocks up to timeout).
    member _.TryTakeInbound(timeoutMs: int) =
        let mutable item = Unchecked.defaultof<byte[]>
        if inbound.TryTake(&item, timeoutMs) then Some item else None

    interface ITunnel with
        member _.ReadPacket() =
            try outbound.Take()
            with :? InvalidOperationException -> [||]
        member _.WritePacket(packet) = inbound.Add packet
        member _.Close() =
            outbound.CompleteAdding()
            inbound.CompleteAdding()


/// A UDP bind over a real socket.
type UdpBind(listenPort: int) =
    let socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
    do socket.Bind(IPEndPoint(IPAddress.Any, listenPort))

    /// The port actually bound (useful when listenPort was 0).
    member _.Port = (socket.LocalEndPoint :?> IPEndPoint).Port

    interface IBind with
        member _.Receive() =
            let buffer = Array.zeroCreate 65535
            let mutable remote: EndPoint = IPEndPoint(IPAddress.Any, 0)
            let n = socket.ReceiveFrom(buffer, &remote)
            buffer.[0 .. n - 1], (remote :?> IPEndPoint)
        member _.Send packet endpoint = socket.SendTo(packet, endpoint) |> ignore
        member _.Close() = socket.Dispose()


/// libc P/Invoke for the TUN device.
module private Libc =
    [<DllImport("libc", SetLastError = true, EntryPoint = "open")>]
    extern int openDevice(string path, int flags)

    [<DllImport("libc", SetLastError = true, EntryPoint = "close")>]
    extern int closeFd(int fd)

    [<DllImport("libc", SetLastError = true, EntryPoint = "ioctl")>]
    extern int ioctl(int fd, uint64 request, byte[] argp)

    [<DllImport("libc", SetLastError = true, EntryPoint = "read")>]
    extern nativeint readFd(int fd, byte[] buf, nativeint count)

    [<DllImport("libc", SetLastError = true, EntryPoint = "write")>]
    extern nativeint writeFd(int fd, byte[] buf, nativeint count)


/// A Linux TUN device (the default real data-plane adapter), created via ioctl on
/// /dev/net/tun. The interface must already exist (e.g. `ip tuntap add`) or be
/// creatable (requires CAP_NET_ADMIN); addressing/routing is configured externally.
type LinuxTun(name: string, mtu: int) =
    static let O_RDWR = 2
    static let TUNSETIFF = 0x400454caUL
    static let IFF_TUN = 0x0001us
    static let IFF_NO_PI = 0x1000us

    let fd =
        let fd = Libc.openDevice ("/dev/net/tun", O_RDWR)
        if fd < 0 then failwith "WireGuard: cannot open /dev/net/tun"
        // struct ifreq: 16-byte name, then flags as a short.
        let ifreq = Array.zeroCreate<byte> 40
        let nameBytes = Text.Encoding.ASCII.GetBytes name
        Array.blit nameBytes 0 ifreq 0 (min nameBytes.Length 15)
        let flags = IFF_TUN ||| IFF_NO_PI
        ifreq.[16] <- byte flags
        ifreq.[17] <- byte (flags >>> 8)
        if Libc.ioctl (fd, TUNSETIFF, ifreq) < 0 then
            Libc.closeFd fd |> ignore
            failwithf "WireGuard: TUNSETIFF(%s) failed (errno %d)" name (Marshal.GetLastWin32Error())
        fd

    interface ITunnel with
        member _.ReadPacket() =
            let buffer = Array.zeroCreate (mtu + 4)
            let n = int (Libc.readFd (fd, buffer, nativeint buffer.Length))
            if n <= 0 then [||] else buffer.[0 .. n - 1]
        member _.WritePacket(packet) = Libc.writeFd (fd, packet, nativeint packet.Length) |> ignore
        member _.Close() = Libc.closeFd fd |> ignore
