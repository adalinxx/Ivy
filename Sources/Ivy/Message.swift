import Foundation

public struct ContentEntry: Sendable, Equatable {
    public let cid: String
    public let data: Data

    public init(cid: String, data: Data) {
        self.cid = cid
        self.data = data
    }
}

struct ProviderRecord: Sendable, Equatable {
    let endpoint: PeerEndpoint
    let expiresAt: UInt64
}

enum Message: Sendable {
    case ping(nonce: UInt64)
    case pong(nonce: UInt64)
    case findNode(target: Data, nonce: UInt64 = 0)
    case neighbors([PeerEndpoint], nonce: UInt64 = 0)

    case contentRequest(requestID: UInt64, rootCID: String, cids: [String])
    case contentResponse(requestID: UInt64, entries: [ContentEntry])
    case contentUnavailable(requestID: UInt64)

    case findProviders(rootCID: String, requestID: UInt64)
    case providers(rootCID: String, requestID: UInt64, records: [ProviderRecord])
    case announceProvider(rootCID: String, expiresAt: UInt64)

    case relayOpen(routeID: Data, targetKey: PeerKey)
    case relayOffer(routeID: Data, sourceKey: PeerKey)
    case relayAccept(routeID: Data, status: UInt8)
    case relayReady(routeID: Data, status: UInt8)
    case relayPacket(routeID: Data, opaqueEndpointRecord: Data)
    case relayClose(routeID: Data)

    case peerMessage(topic: String, payload: Data)

    private enum Tag: UInt8 {
        case ping = 0
        case pong = 1
        case findNode = 5
        case neighbors = 6
        case contentRequest = 26
        case findProviders = 40
        case providers = 41
        case announceProvider = 42
        case peerMessage = 49
        case contentResponse = 50
        case contentUnavailable = 58
        case relayOpen = 60
        case relayOffer = 61
        case relayAccept = 62
        case relayReady = 63
        case relayPacket = 64
        case relayClose = 65
    }

    var isKeepalive: Bool {
        switch self {
        case .ping, .pong: return true
        default: return false
        }
    }

    static func contentResponseDataBudget(
        for cids: [String],
        maxFrameSize: UInt32,
        relayed: Bool
    ) -> Int? {
        var remaining = Int(maxFrameSize)
        guard consume(SessionWireRecord.dataRecordOverhead, from: &remaining) else { return nil }
        if relayed {
            // relayPacket tag, route ID, and endpoint-record length, then the carrier record.
            guard consume(1 + 32 + 4, from: &remaining),
                  consume(SessionWireRecord.dataRecordOverhead, from: &remaining) else { return nil }
        }
        return contentResponsePayloadBudget(for: cids, within: remaining)
    }

    func serialize(maxFrameSize: UInt32 = IvyConfig.protocolMaxFrameSize) -> Data {
        var bytes = Data()
        guard encode(into: &bytes, maxDataPayload: maxFrameSize),
              bytes.count <= Int(maxFrameSize) else { return Data() }
        return bytes
    }

    private func encode(into bytes: inout Data, maxDataPayload: UInt32) -> Bool {
        switch self {
        case .ping(let nonce):
            bytes.append(Tag.ping.rawValue)
            bytes.appendUInt64(nonce)
        case .pong(let nonce):
            bytes.append(Tag.pong.rawValue)
            bytes.appendUInt64(nonce)
        case .findNode(let target, let nonce):
            guard target.count == 32 else { return false }
            bytes.append(Tag.findNode.rawValue)
            guard bytes.appendLengthPrefixedData(target, maxDataPayload: maxDataPayload) else { return false }
            bytes.appendUInt64(nonce)
        case .neighbors(let peers, let nonce):
            bytes.append(Tag.neighbors.rawValue)
            guard bytes.appendEndpoints(peers) else { return false }
            bytes.appendUInt64(nonce)
        case .contentRequest(let requestID, let rootCID, let cids):
            guard requestID != 0,
                  MessageLimits.accepts(rootCID),
                  cids.allSatisfy(MessageLimits.accepts) else { return false }
            bytes.append(Tag.contentRequest.rawValue)
            bytes.appendUInt64(requestID)
            guard bytes.appendLengthPrefixedString(rootCID),
                  bytes.appendCount(cids.count, max: MessageLimits.maxContentCIDCount) else { return false }
            for cid in cids {
                guard bytes.appendLengthPrefixedString(cid) else { return false }
            }
        case .contentResponse(let requestID, let entries):
            guard requestID != 0,
                  Self.contentResponseFits(entries, maxFrameSize: maxDataPayload) else { return false }
            bytes.append(Tag.contentResponse.rawValue)
            bytes.appendUInt64(requestID)
            guard bytes.appendCount(entries.count, max: MessageLimits.maxContentEntryCount) else { return false }
            for entry in entries {
                guard bytes.appendLengthPrefixedString(entry.cid),
                      bytes.appendLengthPrefixedData(entry.data, maxDataPayload: maxDataPayload) else { return false }
            }
        case .contentUnavailable(let requestID):
            guard requestID != 0 else { return false }
            bytes.append(Tag.contentUnavailable.rawValue)
            bytes.appendUInt64(requestID)
        case .findProviders(let rootCID, let requestID):
            guard MessageLimits.accepts(rootCID), requestID != 0 else { return false }
            bytes.append(Tag.findProviders.rawValue)
            guard bytes.appendLengthPrefixedString(rootCID) else { return false }
            bytes.appendUInt64(requestID)
        case .providers(let rootCID, let requestID, let records):
            guard MessageLimits.accepts(rootCID), requestID != 0 else { return false }
            bytes.append(Tag.providers.rawValue)
            guard bytes.appendLengthPrefixedString(rootCID),
                  bytes.appendProviderRecords(records) else { return false }
            bytes.appendUInt64(requestID)
        case .announceProvider(let rootCID, let expiresAt):
            guard MessageLimits.accepts(rootCID) else { return false }
            bytes.append(Tag.announceProvider.rawValue)
            guard bytes.appendLengthPrefixedString(rootCID) else { return false }
            bytes.appendUInt64(expiresAt)
        case .relayOpen(let routeID, let targetKey):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayOpen.rawValue)
            bytes.append(routeID)
            bytes.append(targetKey.rawRepresentation)
        case .relayOffer(let routeID, let sourceKey):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayOffer.rawValue)
            bytes.append(routeID)
            bytes.append(sourceKey.rawRepresentation)
        case .relayAccept(let routeID, let status):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayAccept.rawValue)
            bytes.append(routeID)
            bytes.appendUInt8(status)
        case .relayReady(let routeID, let status):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayReady.rawValue)
            bytes.append(routeID)
            bytes.appendUInt8(status)
        case .relayPacket(let routeID, let record):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayPacket.rawValue)
            bytes.append(routeID)
            guard bytes.appendLengthPrefixedData(record, maxDataPayload: maxDataPayload) else { return false }
        case .relayClose(let routeID):
            guard routeID.count == 32 else { return false }
            bytes.append(Tag.relayClose.rawValue)
            bytes.append(routeID)
        case .peerMessage(let topic, let payload):
            guard !topic.isEmpty else { return false }
            bytes.append(Tag.peerMessage.rawValue)
            guard bytes.appendLengthPrefixedString(topic),
                  bytes.appendLengthPrefixedData(payload, maxDataPayload: maxDataPayload) else { return false }
        }
        return true
    }

    private static func contentResponseFits(
        _ entries: [ContentEntry],
        maxFrameSize: UInt32
    ) -> Bool {
        guard var remaining = contentResponsePayloadBudget(
            for: entries.map(\.cid),
            within: Int(maxFrameSize)
        ) else { return false }
        for entry in entries {
            guard consume(entry.data.count, from: &remaining) else { return false }
        }
        return true
    }

    private static func contentResponsePayloadBudget(
        for cids: [String],
        within byteLimit: Int
    ) -> Int? {
        guard cids.count <= Int(MessageLimits.maxContentEntryCount) else { return nil }
        var remaining = byteLimit
        guard consume(1 + 8 + 2, from: &remaining) else { return nil }
        for cid in cids {
            let cidSize = cid.utf8.count
            guard MessageLimits.accepts(cid),
                  consume(2, from: &remaining),
                  consume(cidSize, from: &remaining),
                  consume(4, from: &remaining) else { return nil }
        }
        return remaining
    }

    private static func consume(_ count: Int, from remaining: inout Int) -> Bool {
        guard count >= 0, count <= remaining else { return false }
        remaining -= count
        return true
    }

    static func deserialize(
        _ data: Data,
        maxDataPayload: UInt32 = IvyConfig.protocolMaxFrameSize
    ) -> Message? {
        guard let message = decode(data, maxDataPayload: maxDataPayload),
              message.serialize(maxFrameSize: maxDataPayload) == data else { return nil }
        return message
    }

    private static func decode(_ data: Data, maxDataPayload: UInt32) -> Message? {
        var reader = DataReader(data, maxDataPayload: maxDataPayload)
        guard let rawTag = reader.readUInt8(), let tag = Tag(rawValue: rawTag) else { return nil }
        switch tag {
        case .ping:
            guard let nonce = reader.readUInt64() else { return nil }
            return .ping(nonce: nonce)
        case .pong:
            guard let nonce = reader.readUInt64() else { return nil }
            return .pong(nonce: nonce)
        case .findNode:
            guard let target = reader.readData(), let nonce = reader.readUInt64() else { return nil }
            return .findNode(target: target, nonce: nonce)
        case .neighbors:
            guard let peers = reader.readEndpoints(), let nonce = reader.readUInt64() else { return nil }
            return .neighbors(peers, nonce: nonce)
        case .contentRequest:
            guard let requestID = reader.readUInt64(), requestID != 0,
                  let rootCID = reader.readString(),
                  let cids = reader.readStrings(max: MessageLimits.maxContentCIDCount) else { return nil }
            return .contentRequest(requestID: requestID, rootCID: rootCID, cids: cids)
        case .contentResponse:
            guard let requestID = reader.readUInt64(), requestID != 0,
                  let count = reader.readUInt16(), count <= MessageLimits.maxContentEntryCount else { return nil }
            var entries: [ContentEntry] = []
            entries.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString(), let data = reader.readData() else { return nil }
                entries.append(ContentEntry(cid: cid, data: data))
            }
            return .contentResponse(requestID: requestID, entries: entries)
        case .contentUnavailable:
            guard let requestID = reader.readUInt64(), requestID != 0 else { return nil }
            return .contentUnavailable(requestID: requestID)
        case .findProviders:
            guard let rootCID = reader.readString(),
                  let requestID = reader.readUInt64(), requestID != 0 else { return nil }
            return .findProviders(rootCID: rootCID, requestID: requestID)
        case .providers:
            guard let rootCID = reader.readString(),
                  let records = reader.readProviderRecords(),
                  let requestID = reader.readUInt64(), requestID != 0 else { return nil }
            return .providers(rootCID: rootCID, requestID: requestID, records: records)
        case .announceProvider:
            guard let rootCID = reader.readString(), let expiresAt = reader.readUInt64() else { return nil }
            return .announceProvider(rootCID: rootCID, expiresAt: expiresAt)
        case .relayOpen:
            guard let routeID = reader.readFixedData(count: 32),
                  let targetBytes = reader.readFixedData(count: 32),
                  let target = try? PeerKey(rawRepresentation: targetBytes) else { return nil }
            return .relayOpen(routeID: routeID, targetKey: target)
        case .relayOffer:
            guard let routeID = reader.readFixedData(count: 32),
                  let sourceBytes = reader.readFixedData(count: 32),
                  let source = try? PeerKey(rawRepresentation: sourceBytes) else { return nil }
            return .relayOffer(routeID: routeID, sourceKey: source)
        case .relayAccept:
            guard let routeID = reader.readFixedData(count: 32), let status = reader.readUInt8() else { return nil }
            return .relayAccept(routeID: routeID, status: status)
        case .relayReady:
            guard let routeID = reader.readFixedData(count: 32), let status = reader.readUInt8() else { return nil }
            return .relayReady(routeID: routeID, status: status)
        case .relayPacket:
            guard let routeID = reader.readFixedData(count: 32), let record = reader.readData() else { return nil }
            return .relayPacket(routeID: routeID, opaqueEndpointRecord: record)
        case .relayClose:
            guard let routeID = reader.readFixedData(count: 32) else { return nil }
            return .relayClose(routeID: routeID)
        case .peerMessage:
            guard let topic = reader.readString(), let payload = reader.readData() else { return nil }
            return .peerMessage(topic: topic, payload: payload)
        }
    }

}

public struct PeerEndpoint: Sendable, Equatable, Hashable {
    public let publicKey: String
    public let host: String
    public let port: UInt16

    public init(publicKey: String, host: String, port: UInt16) {
        self.publicKey = publicKey
        self.host = host
        self.port = port
    }
}

private extension Data {
    mutating func appendEndpoints(_ endpoints: [PeerEndpoint]) -> Bool {
        guard appendCount(endpoints.count, max: MessageLimits.maxNeighborCount) else { return false }
        for endpoint in endpoints {
            guard appendLengthPrefixedString(endpoint.publicKey),
                  appendLengthPrefixedString(endpoint.host) else { return false }
            appendUInt16(endpoint.port)
        }
        return true
    }

    mutating func appendProviderRecords(_ records: [ProviderRecord]) -> Bool {
        guard appendCount(records.count, max: MessageLimits.maxNeighborCount) else { return false }
        for record in records {
            let endpoint = record.endpoint
            guard appendLengthPrefixedString(endpoint.publicKey),
                  appendLengthPrefixedString(endpoint.host) else { return false }
            appendUInt16(endpoint.port)
            appendUInt64(record.expiresAt)
        }
        return true
    }
}

private extension DataReader {
    mutating func readEndpoints() -> [PeerEndpoint]? {
        guard let count = readUInt16(), count <= MessageLimits.maxNeighborCount else { return nil }
        var endpoints: [PeerEndpoint] = []
        endpoints.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let publicKey = readString(), let host = readString(), let port = readUInt16() else { return nil }
            endpoints.append(PeerEndpoint(publicKey: publicKey, host: host, port: port))
        }
        return endpoints
    }

    mutating func readProviderRecords() -> [ProviderRecord]? {
        guard let count = readUInt16(), count <= MessageLimits.maxNeighborCount else { return nil }
        var records: [ProviderRecord] = []
        records.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let publicKey = readString(),
                  let host = readString(),
                  let port = readUInt16(),
                  let expiresAt = readUInt64() else { return nil }
            records.append(ProviderRecord(
                endpoint: PeerEndpoint(publicKey: publicKey, host: host, port: port),
                expiresAt: expiresAt))
        }
        return records
    }

    mutating func readStrings(max: UInt16) -> [String]? {
        guard let count = readUInt16(), count <= max else { return nil }
        var strings: [String] = []
        strings.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let value = readString() else { return nil }
            strings.append(value)
        }
        return strings
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }

    @inline(__always)
    mutating func appendUInt8(_ value: UInt8) {
        append(value)
    }

    @inline(__always)
    mutating func appendUInt16(_ value: UInt16) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    @inline(__always)
    mutating func appendUInt32(_ value: UInt32) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    @inline(__always)
    mutating func appendUInt64(_ value: UInt64) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    @discardableResult
    @inline(__always)
    mutating func appendCount(_ count: Int, max: UInt16) -> Bool {
        guard count >= 0, count <= Int(max) else { return false }
        appendUInt16(UInt16(count))
        return true
    }

    @discardableResult
    @inline(__always)
    mutating func appendLengthPrefixedString(_ string: String) -> Bool {
        let utf8 = string.utf8
        guard utf8.count <= Int(MessageLimits.maxStringLength) else { return false }
        appendUInt16(UInt16(utf8.count))
        append(contentsOf: utf8)
        return true
    }

    @discardableResult
    @inline(__always)
    mutating func appendLengthPrefixedData(
        _ data: Data,
        maxDataPayload: UInt32 = IvyConfig.protocolMaxFrameSize
    ) -> Bool {
        guard data.count <= Int(maxDataPayload) else { return false }
        appendUInt32(UInt32(data.count))
        append(data)
        return true
    }
}

struct DataReader {
    private let data: Data
    private let maxDataPayload: UInt32
    private var offset = 0

    init(_ data: Data, maxDataPayload: UInt32 = IvyConfig.protocolMaxFrameSize) {
        self.data = data
        self.maxDataPayload = maxDataPayload
    }

    var remaining: Int { data.count - offset }

    mutating func readUInt8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { offset += 1 }
        return data[data.startIndex + offset]
    }

    mutating func readUInt16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        defer { offset += 2 }
        let start = data.startIndex + offset
        var value: UInt16 = 0
        _ = withUnsafeMutableBytes(of: &value) { data.copyBytes(to: $0, from: start..<start + 2) }
        return value.bigEndian
    }

    mutating func readUInt32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        defer { offset += 4 }
        let start = data.startIndex + offset
        var value: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &value) { data.copyBytes(to: $0, from: start..<start + 4) }
        return value.bigEndian
    }

    mutating func readUInt64() -> UInt64? {
        guard remaining >= 8 else { return nil }
        defer { offset += 8 }
        let start = data.startIndex + offset
        var value: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &value) { data.copyBytes(to: $0, from: start..<start + 8) }
        return value.bigEndian
    }

    mutating func readString() -> String? {
        guard let length = readUInt16(), length <= MessageLimits.maxStringLength,
              remaining >= Int(length) else { return nil }
        defer { offset += Int(length) }
        let start = data.startIndex + offset
        return String(data: data[start..<start + Int(length)], encoding: .utf8)
    }

    mutating func readData() -> Data? {
        guard let length = readUInt32(), length <= maxDataPayload,
              remaining >= Int(length) else { return nil }
        defer { offset += Int(length) }
        let start = data.startIndex + offset
        return Data(data[start..<start + Int(length)])
    }

    mutating func readFixedData(count: Int) -> Data? {
        guard count >= 0, remaining >= count else { return nil }
        defer { offset += count }
        let start = data.startIndex + offset
        return Data(data[start..<start + count])
    }
}
