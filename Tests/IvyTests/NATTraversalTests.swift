import Testing
import Foundation
@testable import Ivy
import NIOCore
import NIOEmbedded

@Suite("STUN Response Parsing")
struct STUNParsingTests {

    @Test("RFC 5769 IPv4 response vector referenced by RFC 8489")
    func rfcIPv4ResponseVector() throws {
        let vector = try #require(Data(hexString:
            "0101003c2112a442b7e7a701bc34d686fa87dfae"
                + "8022000b7465737420766563746f7220"
                + "002000080001a147e112a643"
                + "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
                + "80280004c07d4c96"))
        var buffer = ByteBuffer(bytes: vector)

        let address = STUNResponseHandler.parseResponse(
            &buffer,
            expectedTransactionID: [
                0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
                0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
            ])

        #expect(address == ObservedAddress(host: "192.0.2.1", port: 32_853))
    }

    @Test("A present FINGERPRINT must contain the correct CRC")
    func corruptedFingerprintIsRejected() throws {
        let data = try #require(Data(hexString:
            "0101003c2112a442b7e7a701bc34d686fa87dfae"
                + "8022000b7465737420766563746f7220"
                + "002000080001a147e112a643"
                + "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
                + "80280004c07d4c97"))
        var buffer = ByteBuffer(bytes: data)

        #expect(STUNResponseHandler.parseResponse(&buffer) == nil)
    }

    @Test("FINGERPRINT must be the final attribute")
    func fingerprintBeforeAnotherAttributeIsRejected() {
        var buffer = buildSTUNResponse(
            attrType: 0x0020,
            xorMapped: true,
            ip: "203.0.113.5",
            port: 4001)
        buffer.setInteger(UInt16(24), at: 2, endianness: .big)
        let fingerprintOffset = buffer.writerIndex
        let message = Array(buffer.readableBytesView)
        let fingerprint = STUNResponseHandler.crc32(message.prefix(fingerprintOffset))
            ^ 0x5354554e
        buffer.writeInteger(UInt16(0x8028), endianness: .big)
        buffer.writeInteger(UInt16(4), endianness: .big)
        buffer.writeInteger(fingerprint, endianness: .big)
        buffer.writeInteger(UInt16(0x8022), endianness: .big)
        buffer.writeInteger(UInt16(0), endianness: .big)

        #expect(STUNResponseHandler.parseResponse(&buffer) == nil)
    }

    @Test("Unknown comprehension-required attributes reject the response")
    func unknownRequiredAttributeIsRejected() throws {
        let data = try #require(Data(hexString:
            "010100102112a4420102030405060708090a0b0c"
                + "0020000800012eb3ea12d547"
                + "7ffe0000"))
        var buffer = ByteBuffer(bytes: data)

        #expect(STUNResponseHandler.parseResponse(&buffer) == nil)
    }

    @Test("Parse XOR-MAPPED-ADDRESS IPv4")
    func testXorMappedAddress() {
        let txnID = Array(UInt8(1)...UInt8(12))
        var buf = buildSTUNResponse(attrType: 0x0020, xorMapped: true, ip: "203.0.113.5", port: 4001, transactionID: txnID)
        let addr = STUNResponseHandler.parseResponse(&buf, expectedTransactionID: txnID)
        #expect(addr != nil)
        #expect(addr?.host == "203.0.113.5")
        #expect(addr?.port == 4001)
    }

    @Test("Parse XOR-MAPPED-ADDRESS IPv6")
    func xorMappedIPv6() {
        let transactionID = Array(UInt8(1)...UInt8(12))
        let address: [UInt8] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]
        let mask = [UInt8(0x21), 0x12, 0xa4, 0x42] + transactionID
        let encoded = zip(address, mask).map { pair in pair.0 ^ pair.1 }

        var buffer = ByteBuffer()
        buffer.writeInteger(UInt16(0x0101), endianness: .big)
        buffer.writeInteger(UInt16(24), endianness: .big)
        buffer.writeInteger(UInt32(0x2112a442), endianness: .big)
        buffer.writeBytes(transactionID)
        buffer.writeInteger(UInt16(0x0020), endianness: .big)
        buffer.writeInteger(UInt16(20), endianness: .big)
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(UInt8(0x02))
        buffer.writeInteger(UInt16(4001) ^ 0x2112, endianness: .big)
        buffer.writeBytes(encoded)

        #expect(STUNResponseHandler.parseResponse(
            &buffer,
            expectedTransactionID: transactionID)
            == ObservedAddress(host: "2001:db8:0:0:0:0:0:1", port: 4001))
    }

    @Test("legacy MAPPED-ADDRESS is not accepted as a public route")
    func mappedAddressIsRejected() {
        let txnID = Array(UInt8(13)...UInt8(24))
        var buf = buildSTUNResponse(attrType: 0x0001, xorMapped: false, ip: "192.168.1.1", port: 8080, transactionID: txnID)
        #expect(STUNResponseHandler.parseResponse(
            &buf,
            expectedTransactionID: txnID) == nil)
    }

    @Test("Mismatched transaction ID returns nil")
    func testMismatchedTransactionID() {
        let txnID = Array(UInt8(1)...UInt8(12))
        let otherTxnID = Array(UInt8(21)...UInt8(32))
        var buf = buildSTUNResponse(attrType: 0x0020, xorMapped: true, ip: "203.0.113.5", port: 4001, transactionID: txnID)
        #expect(STUNResponseHandler.parseResponse(&buf, expectedTransactionID: otherTxnID) == nil)
    }

    @Test("Unexpected STUN message classes are rejected")
    func testUnexpectedMessageTypeRejected() {
        let txnID = Array(UInt8(1)...UInt8(12))
        var buf = buildSTUNResponse(attrType: 0x0020, xorMapped: true, ip: "203.0.113.5", port: 4001, transactionID: txnID)
        buf.setInteger(UInt16(0x0001), at: 0, endianness: .big)
        #expect(STUNResponseHandler.parseResponse(&buf, expectedTransactionID: txnID) == nil)
    }

    @Test("Malformed mapped-address attributes are rejected")
    func testMalformedMappedAddressRejected() {
        let txnID = Array(UInt8(1)...UInt8(12))
        var shortValue = buildSTUNResponse(
            attrType: 0x0020,
            xorMapped: true,
            ip: "203.0.113.5",
            port: 4001,
            transactionID: txnID,
            attrLength: 7
        )
        #expect(STUNResponseHandler.parseResponse(&shortValue, expectedTransactionID: txnID) == nil)

        var ipv6Value = buildSTUNResponse(
            attrType: 0x0020,
            xorMapped: true,
            ip: "203.0.113.5",
            port: 4001,
            transactionID: txnID,
            family: 0x02
        )
        #expect(STUNResponseHandler.parseResponse(&ipv6Value, expectedTransactionID: txnID) == nil)
    }

    @Test("Invalid magic cookie returns nil")
    func testBadMagic() {
        var buf = ByteBuffer()
        buf.writeInteger(UInt16(0x0101), endianness: .big)
        buf.writeInteger(UInt16(0), endianness: .big)
        buf.writeInteger(UInt32(0xDEADBEEF), endianness: .big)
        buf.writeRepeatingByte(0, count: 12)
        #expect(STUNResponseHandler.parseResponse(&buf) == nil)
    }

    @Test("Truncated response returns nil")
    func testTruncated() {
        var buf = ByteBuffer()
        buf.writeBytes([0x01, 0x01, 0x00])
        #expect(STUNResponseHandler.parseResponse(&buf) == nil)
    }

    @Test("attributes outside the declared STUN body are rejected")
    func testAttributeBeyondDeclaredBody() {
        let txnID = Array(UInt8(1)...UInt8(12))
        var buf = buildSTUNResponse(
            attrType: 0x0020,
            xorMapped: true,
            ip: "203.0.113.5",
            port: 4001,
            transactionID: txnID)
        buf.setInteger(UInt16(4), at: 2, endianness: .big)

        #expect(STUNResponseHandler.parseResponse(&buf, expectedTransactionID: txnID) == nil)
    }

    private func buildSTUNResponse(
        attrType: UInt16,
        xorMapped: Bool,
        ip: String,
        port: UInt16,
        transactionID: [UInt8] = Array(repeating: 0, count: 12),
        attrLength: UInt16 = 8,
        family: UInt8 = 0x01
    ) -> ByteBuffer {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        let ipNum = UInt32(parts[0]) << 24 | UInt32(parts[1]) << 16 | UInt32(parts[2]) << 8 | UInt32(parts[3])

        let magic: UInt32 = 0x2112A442

        let xPort: UInt16 = xorMapped ? (port ^ 0x2112) : port
        let xAddr: UInt32 = xorMapped ? (ipNum ^ magic) : ipNum

        var attrBuf = ByteBuffer()
        attrBuf.writeInteger(attrType, endianness: .big)
        attrBuf.writeInteger(attrLength, endianness: .big)
        attrBuf.writeInteger(UInt8(0))
        attrBuf.writeInteger(family)
        attrBuf.writeInteger(xPort, endianness: .big)
        attrBuf.writeInteger(xAddr, endianness: .big)

        var buf = ByteBuffer()
        buf.writeInteger(UInt16(0x0101), endianness: .big)
        buf.writeInteger(UInt16(attrBuf.readableBytes), endianness: .big)
        buf.writeInteger(magic, endianness: .big)
        buf.writeBytes(transactionID)
        buf.writeBuffer(&attrBuf)

        return buf
    }
}

///: STUN responses are only honored when they arrive from the exact
/// server address we sent the binding request to. A spoofed reply from an
/// unexpected source — even one carrying a valid transaction ID and a
/// well-formed XOR-MAPPED-ADDRESS — must be dropped, otherwise an off-path
/// attacker could inject a bogus public address into NAT discovery.
@Suite("STUN source-address validation")
struct STUNSourceAddressTests {

    private func makeSTUNResponse(ip: String, port: UInt16, transactionID: [UInt8]) -> ByteBuffer {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        let ipNum = UInt32(parts[0]) << 24 | UInt32(parts[1]) << 16 | UInt32(parts[2]) << 8 | UInt32(parts[3])
        let magic: UInt32 = 0x2112A442
        let xPort = port ^ 0x2112
        let xAddr = ipNum ^ magic

        var attrBuf = ByteBuffer()
        attrBuf.writeInteger(UInt16(0x0020), endianness: .big)
        attrBuf.writeInteger(UInt16(8), endianness: .big)
        attrBuf.writeInteger(UInt8(0))
        attrBuf.writeInteger(UInt8(0x01))
        attrBuf.writeInteger(xPort, endianness: .big)
        attrBuf.writeInteger(xAddr, endianness: .big)

        var buf = ByteBuffer()
        buf.writeInteger(UInt16(0x0101), endianness: .big)
        buf.writeInteger(UInt16(attrBuf.readableBytes), endianness: .big)
        buf.writeInteger(magic, endianness: .big)
        buf.writeBytes(transactionID)
        buf.writeBuffer(&attrBuf)
        return buf
    }

    @Test("Valid response from the expected server is accepted")
    func validResponseFromExpectedAddressAccepted() async throws {
        let txnID = Array(UInt8(1)...UInt8(12))
        let expected = try SocketAddress(ipAddress: "203.0.113.10", port: 3478)
        let handler = STUNResponseHandler(
            expectedTransactionID: txnID,
            expectedRemoteAddress: expected
        )
        let channel = await NIOAsyncTestingChannel(handler: handler)

        let payload = makeSTUNResponse(ip: "198.51.100.5", port: 4001, transactionID: txnID)
        try await channel.writeInbound(AddressedEnvelope(remoteAddress: expected, data: payload))
        handler.finishWithoutResponse()

        let result = await handler.waitForResponse()
        #expect(result == ObservedAddress(host: "198.51.100.5", port: 4001))
        _ = try? await channel.finish()
    }

    @Test("Valid response after timeout is ignored")
    func validResponseAfterTimeoutIsIgnored() async throws {
        let txnID = Array(UInt8(1)...UInt8(12))
        let expected = try SocketAddress(ipAddress: "203.0.113.10", port: 3478)
        let handler = STUNResponseHandler(
            expectedTransactionID: txnID,
            expectedRemoteAddress: expected
        )
        let channel = await NIOAsyncTestingChannel(handler: handler)

        handler.finishWithoutResponse()
        let payload = makeSTUNResponse(ip: "198.51.100.5", port: 4001, transactionID: txnID)
        try await channel.writeInbound(AddressedEnvelope(remoteAddress: expected, data: payload))

        #expect(await handler.waitForResponse() == nil)
        _ = try? await channel.finish()
    }

    @Test("Valid-looking response from an UNEXPECTED address is dropped")
    func validResponseFromUnexpectedAddressDropped() async throws {
        let txnID = Array(UInt8(1)...UInt8(12))
        let expected = try SocketAddress(ipAddress: "203.0.113.10", port: 3478)
        let spoofer = try SocketAddress(ipAddress: "203.0.113.99", port: 3478)
        let handler = STUNResponseHandler(
            expectedTransactionID: txnID,
            expectedRemoteAddress: expected
        )
        let channel = await NIOAsyncTestingChannel(handler: handler)

        let waiter = Task { await handler.waitForResponse() }
        try await Task.sleep(for: .milliseconds(20))

        // Same valid txn ID + well-formed mapped address, but from a different
        // source address. The guard in channelRead must reject it.
        let spoofed = makeSTUNResponse(ip: "10.0.0.1", port: 4001, transactionID: txnID)
        try await channel.writeInbound(AddressedEnvelope(remoteAddress: spoofer, data: spoofed))

        // The spoofed datagram must NOT resolve the continuation. Then the
        // legitimate reply from the expected address must still be accepted,
        // proving the handler dropped (not consumed) the spoof.
        try await Task.sleep(for: .milliseconds(30))
        let legit = makeSTUNResponse(ip: "198.51.100.5", port: 4001, transactionID: txnID)
        try await channel.writeInbound(AddressedEnvelope(remoteAddress: expected, data: legit))

        let result = await waiter.value
        #expect(result == ObservedAddress(host: "198.51.100.5", port: 4001),
                "handler must drop the spoofed reply and accept only the expected-source reply")
        _ = try? await channel.finish()
    }
}

@Suite("STUN response completion")
struct STUNResponseCompletionTests {
    @Test("timeout completes a waiter that has not received a response")
    func timeoutCompletesPendingWaiter() async {
        let handler = STUNResponseHandler()
        let waiter = Task { await handler.waitForResponse() }
        await Task.yield()

        handler.finishWithoutResponse()

        #expect(await waiter.value == nil)
    }

    @Test("timeout remains terminal when it wins before a waiter is installed")
    func timeoutBeforeWaiterIsTerminal() async {
        let handler = STUNResponseHandler()
        handler.finishWithoutResponse()

        #expect(await handler.waitForResponse() == nil)
    }
}

@Suite("ObservedAddress")
struct ObservedAddressTests {

    @Test("Equality")
    func testEquality() {
        let a = ObservedAddress(host: "1.2.3.4", port: 4001)
        let b = ObservedAddress(host: "1.2.3.4", port: 4001)
        let c = ObservedAddress(host: "1.2.3.4", port: 4002)
        #expect(a == b)
        #expect(a != c)
    }

    @Test("Hashing")
    func testHashing() {
        let a = ObservedAddress(host: "1.2.3.4", port: 4001)
        let b = ObservedAddress(host: "1.2.3.4", port: 4001)
        var set: Set<ObservedAddress> = [a]
        set.insert(b)
        #expect(set.count == 1)
    }
}

@Suite("STUN advertisement")
struct STUNAdvertisementTests {
    @Test("STUN contributes the observed host, not its UDP source port")
    func observedUDPPortIsNotAdvertisedAsTCP() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "stun-advertisement",
            listenPort: 4001,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        await node.setPublicAddressForTesting(ObservedAddress(
            host: "8.8.8.8",
            port: 59_999))

        #expect(await node.advertisedListenAddressesForTesting() == [
            ListenAddress(host: "8.8.8.8", port: 4001),
        ])
        #expect(await node.localProviderEndpoint()?.port == 4001)
    }

    @Test("a new run does not retain an old observed address")
    func observedAddressIsRunScoped() async throws {
        let port = TransportTestHarness.nextPort()
        let node = Ivy(config: IvyConfig(
            publicKey: "stun-run-scope",
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        await node.setPublicAddressForTesting(ObservedAddress(
            host: "8.8.8.8",
            port: 59_999))

        try await node.start()

        #expect(await node.publicAddress == nil)
        await node.stop()
    }
}

@Suite("PeerEndpoint Hashable")
struct PeerEndpointHashableTests {

    @Test("PeerEndpoint in Set")
    func testPeerEndpointSet() {
        let a = PeerEndpoint(publicKey: "k1", host: "1.2.3.4", port: 4001)
        let b = PeerEndpoint(publicKey: "k1", host: "1.2.3.4", port: 4001)
        var set: Set<PeerEndpoint> = [a]
        set.insert(b)
        #expect(set.count == 1)
    }
}
