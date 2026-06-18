import Foundation
import NIOCore
import NIOPosix

public struct ObservedAddress: Sendable, Equatable, Hashable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

public actor STUNClient {
    private let group: EventLoopGroup
    private let servers: [(String, Int)]

    public static let defaultServers: [(String, Int)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478),
    ]

    public init(group: EventLoopGroup, servers: [(String, Int)] = STUNClient.defaultServers) {
        self.group = group
        self.servers = servers
    }

    public func discoverPublicAddress() async -> ObservedAddress? {
        for (host, port) in servers {
            if let addr = await query(host: host, port: port) {
                return addr
            }
        }
        return nil
    }

    private func query(host: String, port: Int) async -> ObservedAddress? {
        do {
            var txnID = [UInt8](repeating: 0, count: 12)
            for i in 0..<12 { txnID[i] = UInt8.random(in: 0...255) }

            let remoteAddr = try SocketAddress.makeAddressResolvingHost(host, port: port)
            let handler = STUNResponseHandler(
                expectedTransactionID: txnID,
                expectedRemoteAddress: remoteAddr
            )
            let bootstrap = DatagramBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHandler(handler)
                }
            let channel = try await bootstrap.bind(host: "0.0.0.0", port: 0).get()
            defer { channel.close(promise: nil) }

            var request = Data(capacity: 20)
            request.appendUInt16(0x0001)
            request.appendUInt16(0x0000)
            request.appendUInt32(0x2112A442)
            request.append(contentsOf: txnID)

            var buf = channel.allocator.buffer(capacity: 20)
            buf.writeBytes(request)
            let envelope = AddressedEnvelope(remoteAddress: remoteAddr, data: buf)
            try await channel.writeAndFlush(envelope).get()

            return await withTaskGroup(of: ObservedAddress?.self) { group in
                group.addTask { await handler.waitForResponse() }
                group.addTask {
                    try? await Task.sleep(for: .seconds(3))
                    return nil
                }
                // Take the FIRST result from either task. If the timeout fires
                // first (returns nil), cancelAll so waitForResponse() isn't left
                // suspended forever with an unresumable continuation.
                for await result in group {
                    group.cancelAll()
                    return result
                }
                return nil
            }
        } catch {
            return nil
        }
    }
}

final class STUNResponseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let expectedTransactionID: [UInt8]?
    private let expectedRemoteAddress: SocketAddress?
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ObservedAddress?, Never>?

    init(expectedTransactionID: [UInt8]? = nil, expectedRemoteAddress: SocketAddress? = nil) {
        self.expectedTransactionID = expectedTransactionID
        self.expectedRemoteAddress = expectedRemoteAddress
    }

    func waitForResponse() async -> ObservedAddress? {
        await withTaskCancellationHandler {
            await withCheckedContinuation { cont in
                lock.lock()
                if Task.isCancelled {
                    continuation = nil
                    lock.unlock()
                    cont.resume(returning: nil)
                } else {
                    continuation = cont
                    lock.unlock()
                }
            }
        } onCancel: {
            lock.lock()
            let cont = continuation
            continuation = nil
            lock.unlock()
            cont?.resume(returning: nil)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        if let expectedRemoteAddress, envelope.remoteAddress != expectedRemoteAddress {
            return
        }
        var buf = envelope.data
        guard let addr = Self.parseResponse(&buf, expectedTransactionID: expectedTransactionID) else { return }
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(returning: addr)
    }

    static func parseResponse(_ buf: inout ByteBuffer, expectedTransactionID: [UInt8]? = nil) -> ObservedAddress? {
        guard buf.readableBytes >= 20,
              let msgType: UInt16 = buf.readInteger(endianness: .big),
              let msgLen: UInt16 = buf.readInteger(endianness: .big),
              let magic: UInt32 = buf.readInteger(endianness: .big),
              msgType == 0x0101,
              magic == 0x2112A442 else { return nil }

        guard let txnID = buf.readBytes(length: 12) else { return nil }
        if let expectedTransactionID, txnID != expectedTransactionID {
            return nil
        }

        var bytesLeft = Int(msgLen)
        while bytesLeft >= 4, buf.readableBytes >= 4 {
            guard let attrType: UInt16 = buf.readInteger(endianness: .big),
                  let attrLen: UInt16 = buf.readInteger(endianness: .big) else { return nil }
            let paddedLen = (Int(attrLen) + 3) & ~3
            bytesLeft -= 4 + paddedLen
            guard buf.readableBytes >= paddedLen,
                  var attrBuf = buf.readSlice(length: paddedLen) else { return nil }

            if attrType == 0x0020, attrLen >= 8 {
                attrBuf.moveReaderIndex(forwardBy: 1)
                guard let family: UInt8 = attrBuf.readInteger(),
                      let xPort: UInt16 = attrBuf.readInteger(endianness: .big) else { continue }
                if family == 0x01, let xAddr: UInt32 = attrBuf.readInteger(endianness: .big) {
                    let port = xPort ^ 0x2112
                    let addr = xAddr ^ 0x2112A442
                    return ObservedAddress(
                        host: "\(addr >> 24 & 0xFF).\(addr >> 16 & 0xFF).\(addr >> 8 & 0xFF).\(addr & 0xFF)",
                        port: port
                    )
                }
            } else if attrType == 0x0001, attrLen >= 8 {
                attrBuf.moveReaderIndex(forwardBy: 1)
                guard let family: UInt8 = attrBuf.readInteger(),
                      let port: UInt16 = attrBuf.readInteger(endianness: .big) else { continue }
                if family == 0x01, let addr: UInt32 = attrBuf.readInteger(endianness: .big) {
                    return ObservedAddress(
                        host: "\(addr >> 24 & 0xFF).\(addr >> 16 & 0xFF).\(addr >> 8 & 0xFF).\(addr & 0xFF)",
                        port: port
                    )
                }
            }
        }
        return nil
    }
}
