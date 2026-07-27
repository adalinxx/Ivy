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

actor STUNClient {
    private let group: EventLoopGroup
    private let servers: [(String, Int)]

    init(group: EventLoopGroup, servers: [(String, Int)] = IvyConfig.defaultSTUNServers) {
        self.group = group
        self.servers = servers
    }

    func discoverPublicAddress() async -> ObservedAddress? {
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
            let bindHost = remoteAddr.protocol == .inet6 ? "::" : "0.0.0.0"
            let channel = try await bootstrap.bind(host: bindHost, port: 0).get()
            defer { channel.close(promise: nil) }

            var request = Data(capacity: 20)
            request.appendUInt16(0x0001)
            request.appendUInt16(0x0000)
            request.appendUInt32(0x2112A442)
            request.append(contentsOf: txnID)
            let encodedRequest = request

            var buf = channel.allocator.buffer(capacity: 20)
            buf.writeBytes(encodedRequest)
            let envelope = AddressedEnvelope(remoteAddress: remoteAddr, data: buf)
            try await channel.writeAndFlush(envelope).get()

            let firstRetry = channel.eventLoop.scheduleTask(in: .milliseconds(500)) {
                var retry = channel.allocator.buffer(capacity: encodedRequest.count)
                retry.writeBytes(encodedRequest)
                channel.writeAndFlush(
                    AddressedEnvelope(remoteAddress: remoteAddr, data: retry),
                    promise: nil
                )
            }
            let secondRetry = channel.eventLoop.scheduleTask(in: .milliseconds(1_500)) {
                var retry = channel.allocator.buffer(capacity: encodedRequest.count)
                retry.writeBytes(encodedRequest)
                channel.writeAndFlush(
                    AddressedEnvelope(remoteAddress: remoteAddr, data: retry),
                    promise: nil
                )
            }
            defer {
                firstRetry.cancel()
                secondRetry.cancel()
            }

            let timeout = channel.eventLoop.scheduleTask(in: .seconds(3)) {
                handler.finishWithoutResponse()
            }
            defer { timeout.cancel() }
            return await handler.waitForResponse()
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
    private var response: ObservedAddress?
    private var finished = false

    init(expectedTransactionID: [UInt8]? = nil, expectedRemoteAddress: SocketAddress? = nil) {
        self.expectedTransactionID = expectedTransactionID
        self.expectedRemoteAddress = expectedRemoteAddress
    }

    func waitForResponse() async -> ObservedAddress? {
        await withTaskCancellationHandler {
            await withCheckedContinuation { cont in
                lock.lock()
                if let response {
                    self.response = nil
                    lock.unlock()
                    cont.resume(returning: response)
                } else if Task.isCancelled || finished {
                    lock.unlock()
                    cont.resume(returning: nil)
                } else {
                    continuation = cont
                    lock.unlock()
                }
            }
        } onCancel: {
            finishWithoutResponse()
        }
    }

    func finishWithoutResponse() {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(returning: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        if let expectedRemoteAddress, envelope.remoteAddress != expectedRemoteAddress {
            return
        }
        var buf = envelope.data
        guard let addr = Self.parseResponse(&buf, expectedTransactionID: expectedTransactionID) else { return }
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let cont = continuation
        continuation = nil
        if cont == nil, response == nil {
            response = addr
        }
        lock.unlock()
        cont?.resume(returning: addr)
    }

    static func parseResponse(_ buf: inout ByteBuffer, expectedTransactionID: [UInt8]? = nil) -> ObservedAddress? {
        guard let messageBytes = buf.getBytes(at: buf.readerIndex, length: buf.readableBytes),
              buf.readableBytes >= 20,
              let msgType: UInt16 = buf.readInteger(endianness: .big),
              let msgLen: UInt16 = buf.readInteger(endianness: .big),
              let magic: UInt32 = buf.readInteger(endianness: .big),
              msgType == 0x0101,
              magic == 0x2112A442 else { return nil }

        guard let txnID = buf.readBytes(length: 12) else { return nil }
        if let expectedTransactionID, txnID != expectedTransactionID {
            return nil
        }

        let bodyLength = Int(msgLen)
        guard bodyLength.isMultiple(of: 4),
              buf.readableBytes == bodyLength,
              var attributes = buf.readSlice(length: bodyLength) else { return nil }
        var xorMappedAddress: ObservedAddress?
        while attributes.readableBytes > 0 {
            let attributeOffset = bodyLength - attributes.readableBytes
            guard attributes.readableBytes >= 4,
                  let attrType: UInt16 = attributes.readInteger(endianness: .big),
                  let attrLen: UInt16 = attributes.readInteger(endianness: .big) else { return nil }
            let paddedLen = (Int(attrLen) + 3) & ~3
            guard attributes.readableBytes >= paddedLen,
                  var attrBuf = attributes.readSlice(length: paddedLen) else { return nil }

            if attrType == 0x0020 {
                guard (attrLen == 8 || attrLen == 20),
                      let reserved: UInt8 = attrBuf.readInteger(),
                      reserved == 0,
                      let family: UInt8 = attrBuf.readInteger(),
                      let xPort: UInt16 = attrBuf.readInteger(endianness: .big) else { return nil }
                let port = xPort ^ 0x2112
                if family == 0x01, attrLen == 8,
                   let xAddr: UInt32 = attrBuf.readInteger(endianness: .big) {
                    let addr = xAddr ^ 0x2112A442
                    xorMappedAddress = ObservedAddress(
                        host: "\(addr >> 24 & 0xFF).\(addr >> 16 & 0xFF).\(addr >> 8 & 0xFF).\(addr & 0xFF)",
                        port: port
                    )
                } else if family == 0x02, attrLen == 20,
                          let encoded = attrBuf.readBytes(length: 16) {
                    let mask = [UInt8(0x21), 0x12, 0xa4, 0x42] + txnID
                    let address = zip(encoded, mask).map { pair in pair.0 ^ pair.1 }
                    let host = stride(from: 0, to: address.count, by: 2).map { index in
                        String(format: "%x", UInt16(address[index]) << 8 | UInt16(address[index + 1]))
                    }.joined(separator: ":")
                    xorMappedAddress = ObservedAddress(host: host, port: port)
                } else {
                    return nil
                }
            } else if attrType == 0x0001 {
                // RFC 8489 requires XOR-MAPPED-ADDRESS. Never advertise a
                // legacy MAPPED-ADDRESS value that an ALG may have rewritten.
            } else if attrType == 0x8028 {
                guard attrLen == 4,
                      attributes.readableBytes == 0,
                      let fingerprint: UInt32 = attrBuf.readInteger(endianness: .big),
                      fingerprint == (crc32(messageBytes.prefix(20 + attributeOffset)) ^ 0x5354554e)
                else { return nil }
            } else if attrType == 0x0008 || attrType == 0x001c {
                // Known MESSAGE-INTEGRITY attributes are harmless when this
                // unauthenticated Binding usage receives them unexpectedly.
            } else if attrType < 0x8000 {
                return nil
            }
        }
        return xorMappedAddress
    }

    static func crc32(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc >> 1) ^ (crc & 1 == 1 ? 0xedb88320 : 0)
            }
        }
        return ~crc
    }
}
