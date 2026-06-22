import Foundation

public enum Message: Sendable {
    case ping(nonce: UInt64)
    case pong(nonce: UInt64)
    case block(cid: String, data: Data)
    case dontHave(cid: String)
    case findNode(target: Data, fee: UInt64 = 0, nonce: UInt64 = 0)
    case neighbors([PeerEndpoint], nonce: UInt64 = 0)
    case announceBlock(cid: String)

    case identify(publicKey: String, observedHost: String, observedPort: UInt16, listenAddrs: [(String, UInt16)], chainPorts: [String: UInt16], signature: Data)
    /// Spawn-tree provenance presented right after `identify`: the chain of
    /// spawn certificates from a trusted root down to THIS connection's
    /// authenticated identity. Transport only — the receiver verifies it with
    /// its own `trustedRoot` step 2a). Absent ⇒ federated peer.
    case spawnCertPresentation(chain: [SpawnCertificate])
    case dhtForward(cid: String, ttl: UInt8)

    // NAT traversal Phase 1 — circuit relay (carries identify/want/sync
    // transparently between peers that have no direct link).
    /// Establish a relayed circuit src↔dst through this relay.
    case relayConnect(srcKey: String, dstKey: String, nonce: UInt64 = 0)
    /// Relay control reply: 0 = ok, 1 = refused/unreachable target, 2 = at capacity.
    case relayStatus(code: UInt8, nonce: UInt64 = 0)
    /// One framed peer message carried over a circuit (peerKey = the OTHER endpoint).
    case relayData(peerKey: String, data: Data)

    case want(rootCIDs: [String])
    case wantVolume(rootCID: String, cids: [String])

    case pexRequest(nonce: UInt64)
    case pexResponse(nonce: UInt64, peers: [PeerEndpoint])

    // Ivy economic layer
    case findPins(cid: String)
    case pins(cid: String, providers: [String])
    case pinAnnounce(rootCID: String, publicKey: String, expiry: UInt64, signature: Data, fee: UInt64)
    case pinStored(rootCID: String)
    // tags 44, 47, 48, 51 removed (feeExhausted, balanceCheck, balanceLog, settlementProof)
    case deliveryAck(requestId: UInt64)
    case peerMessage(topic: String, payload: Data)
    case blocks(rootCID: String, items: [(cid: String, data: Data)])

    // Volume-aware fetching
    /// Negative response to want: sender cannot serve this rootCID.
    /// Requester tracks candidate exhaustion and resolves early when all candidates notHave.
    case notHave(rootCID: String)
    case announceVolume(rootCID: String, childCIDs: [String], totalSize: UInt64)
    case pushVolume(rootCID: String, items: [(cid: String, data: Data)])

    private enum Tag: UInt8 {
        case ping = 0
        case pong = 1
        // tag 2 removed (wantBlock → use dhtForward with ttl:0)
        case block = 3
        case dontHave = 4
        case findNode = 5
        case neighbors = 6
        case announceBlock = 7
        case identify = 8
        // NAT traversal Phase 1 — circuit relay (tags 9, 10, 14, 15 remain free).
        case relayConnect = 11
        case relayStatus = 12
        case relayData = 13
        case dhtForward = 16
        // tags 17-31 free (removed chain-specific messages)
        case want = 26
        // tags 35-36 removed (miningChallenge, miningChallengeSolution)
        case pexRequest = 37
        case pexResponse = 38
        // Ivy economic layer (tags 40-55)
        case findPins = 40
        case pins = 41
        case pinAnnounce = 42
        case pinStored = 43
        // tags 44, 45 removed (feeExhausted, directOffer)
        case deliveryAck = 46
        // tags 47, 48 removed (balanceCheck, balanceLog)
        case peerMessage = 49
        case blocks = 50
        // tag 51 removed (settlementProof)
        case wantVolume = 53
        case notHave = 58
        case announceVolume = 54
        case pushVolume = 55
        // tags 56, 57 removed (nodeRecord, getNodeRecord — node-record subsystem deleted)
        case spawnCertPresentation = 59
    }

    /// True for messages that keep the connection alive — always sent regardless of budget.
    public var isKeepalive: Bool {
        switch self {
        case .ping, .pong, .identify: return true
        default: return false
        }
    }

    public func estimatedSize() -> Int {
        switch self {
        case .ping, .pong: return 9
        case .block(let cid, let data): return 7 + cid.utf8.count + data.count
        case .dontHave(let cid): return 3 + cid.utf8.count
        case .announceBlock(let cid): return 3 + cid.utf8.count
        case .want(let rootCIDs): return 3 + rootCIDs.reduce(0) { $0 + 2 + $1.utf8.count }
        case .wantVolume(let rootCID, let cids):
            return 5 + rootCID.utf8.count + cids.reduce(0) { $0 + 2 + $1.utf8.count }
        case .dhtForward(let cid, _): return 4 + cid.utf8.count
        case .blocks(let rootCID, let items):
            return 5 + rootCID.utf8.count + items.reduce(0) { $0 + 6 + $1.cid.utf8.count + $1.data.count }
        case .pushVolume(let rootCID, let items):
            return 7 + rootCID.utf8.count + items.reduce(0) { $0 + 6 + $1.cid.utf8.count + $1.data.count }
        case .peerMessage(let topic, let payload):
            return 5 + topic.utf8.count + payload.count
        default: return 256
        }
    }

    public func serialize(maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize) -> Data {
        var buf = Data(capacity: min(estimatedSize(), Int(maxFrameSize)))
        guard encodePayload(into: &buf, maxDataPayload: maxFrameSize),
              buf.count <= Int(maxFrameSize) else { return Data() }
        return buf
    }

    private func encodePayload(into buf: inout Data, maxDataPayload: UInt32) -> Bool {
        switch self {
        case .ping(let nonce):
            buf.append(Tag.ping.rawValue)
            buf.appendUInt64(nonce)
        case .pong(let nonce):
            buf.append(Tag.pong.rawValue)
            buf.appendUInt64(nonce)
        case .block(let cid, let data):
            buf.append(Tag.block.rawValue)
            guard buf.appendLengthPrefixedString(cid),
                  buf.appendLengthPrefixedData(data, maxDataPayload: maxDataPayload) else { return false }
        case .dontHave(let cid):
            buf.append(Tag.dontHave.rawValue)
            guard buf.appendLengthPrefixedString(cid) else { return false }
        case .findNode(let target, let fee, let nonce):
            buf.append(Tag.findNode.rawValue)
            guard buf.appendLengthPrefixedData(target, maxDataPayload: maxDataPayload) else { return false }
            buf.appendUInt64(fee)
            buf.appendUInt64(nonce)
        case .neighbors(let peers, let nonce):
            buf.append(Tag.neighbors.rawValue)
            guard buf.appendCount(peers.count, max: MessageLimits.maxNeighborCount) else { return false }
            for peer in peers {
                guard buf.appendLengthPrefixedString(peer.publicKey),
                      buf.appendLengthPrefixedString(peer.host) else { return false }
                buf.appendUInt16(peer.port)
            }
            buf.appendUInt64(nonce)
        case .announceBlock(let cid):
            buf.append(Tag.announceBlock.rawValue)
            guard buf.appendLengthPrefixedString(cid) else { return false }
        case .identify(let publicKey, let observedHost, let observedPort, let listenAddrs, let chainPorts, let signature):
            buf.append(Tag.identify.rawValue)
            guard buf.appendLengthPrefixedString(publicKey),
                  buf.appendLengthPrefixedString(observedHost) else { return false }
            buf.appendUInt16(observedPort)
            guard buf.appendCount(listenAddrs.count, max: MessageLimits.maxListenAddrs) else { return false }
            for (host, port) in listenAddrs {
                guard buf.appendLengthPrefixedString(host) else { return false }
                buf.appendUInt16(port)
            }
            guard buf.appendCount(chainPorts.count, max: MessageLimits.maxChainPorts) else { return false }
            for (chain, port) in chainPorts.sorted(by: { $0.key < $1.key }) {
                guard buf.appendLengthPrefixedString(chain) else { return false }
                buf.appendUInt16(port)
            }
            guard buf.appendLengthPrefixedData(signature, maxDataPayload: maxDataPayload) else { return false }
        case .spawnCertPresentation(let chain):
            buf.append(Tag.spawnCertPresentation.rawValue)
            guard buf.appendCount(chain.count, max: MessageLimits.maxSpawnCertChain) else { return false }
            for cert in chain {
                guard buf.appendLengthPrefixedString(cert.childPublicKey),
                      buf.appendCount(cert.chainPath.count, max: UInt16(SpawnCertificate.maxChainPathDepth)) else { return false }
                for element in cert.chainPath {
                    guard buf.appendLengthPrefixedString(element) else { return false }
                }
                guard buf.appendLengthPrefixedString(cert.issuerPublicKey),
                      buf.appendLengthPrefixedData(cert.signature, maxDataPayload: maxDataPayload) else { return false }
            }
        case .dhtForward(let cid, let ttl):
            buf.append(Tag.dhtForward.rawValue)
            guard buf.appendLengthPrefixedString(cid) else { return false }
            buf.appendUInt8(ttl)
        case .relayConnect(let srcKey, let dstKey, let nonce):
            buf.append(Tag.relayConnect.rawValue)
            guard buf.appendLengthPrefixedString(srcKey),
                  buf.appendLengthPrefixedString(dstKey) else { return false }
            buf.appendUInt64(nonce)
        case .relayStatus(let code, let nonce):
            buf.append(Tag.relayStatus.rawValue)
            buf.appendUInt8(code)
            buf.appendUInt64(nonce)
        case .relayData(let peerKey, let data):
            buf.append(Tag.relayData.rawValue)
            guard buf.appendLengthPrefixedString(peerKey),
                  buf.appendLengthPrefixedData(data, maxDataPayload: maxDataPayload) else { return false }
        case .want(let rootCIDs):
            buf.append(Tag.want.rawValue)
            guard buf.appendCount(rootCIDs.count, max: MessageLimits.maxTxCIDCount) else { return false }
            for cid in rootCIDs {
                guard buf.appendLengthPrefixedString(cid) else { return false }
            }
        case .wantVolume(let rootCID, let cids):
            buf.append(Tag.wantVolume.rawValue)
            guard buf.appendLengthPrefixedString(rootCID),
                  buf.appendCount(cids.count, max: MessageLimits.maxTxCIDCount) else { return false }
            for cid in cids {
                guard buf.appendLengthPrefixedString(cid) else { return false }
            }
        case .pexRequest(let nonce):
            buf.append(Tag.pexRequest.rawValue)
            buf.appendUInt64(nonce)
        case .pexResponse(let nonce, let peers):
            buf.append(Tag.pexResponse.rawValue)
            buf.appendUInt64(nonce)
            guard buf.appendCount(peers.count, max: MessageLimits.maxPexPeerCount) else { return false }
            for peer in peers {
                guard buf.appendLengthPrefixedString(peer.publicKey),
                      buf.appendLengthPrefixedString(peer.host) else { return false }
                buf.appendUInt16(peer.port)
            }
        case .findPins(let cid):
            buf.append(Tag.findPins.rawValue)
            guard buf.appendLengthPrefixedString(cid) else { return false }
        case .pins(let cid, let providers):
            buf.append(Tag.pins.rawValue)
            guard buf.appendLengthPrefixedString(cid),
                  buf.appendCount(providers.count, max: MessageLimits.maxNeighborCount) else { return false }
            for pk in providers {
                guard buf.appendLengthPrefixedString(pk) else { return false }
            }
        case .pinAnnounce(let rootCID, let publicKey, let expiry, let signature, let fee):
            buf.append(Tag.pinAnnounce.rawValue)
            guard buf.appendLengthPrefixedString(rootCID),
                  buf.appendLengthPrefixedString(publicKey) else { return false }
            buf.appendUInt64(expiry)
            guard buf.appendLengthPrefixedData(signature, maxDataPayload: maxDataPayload) else { return false }
            buf.appendUInt64(fee)
        case .pinStored(let rootCID):
            buf.append(Tag.pinStored.rawValue)
            guard buf.appendLengthPrefixedString(rootCID) else { return false }
        case .deliveryAck(let requestId):
            buf.append(Tag.deliveryAck.rawValue)
            buf.appendUInt64(requestId)
        case .peerMessage(let topic, let payload):
            buf.append(Tag.peerMessage.rawValue)
            guard buf.appendLengthPrefixedString(topic),
                  buf.appendLengthPrefixedData(payload, maxDataPayload: maxDataPayload) else { return false }
        case .blocks(let rootCID, let items):
            buf.append(Tag.blocks.rawValue)
            guard buf.appendLengthPrefixedString(rootCID),
                  buf.appendCount(items.count, max: MessageLimits.maxTransactionCount) else { return false }
            for item in items {
                guard buf.appendLengthPrefixedString(item.cid),
                      buf.appendLengthPrefixedData(item.data, maxDataPayload: maxDataPayload) else { return false }
            }
        case .notHave(let rootCID):
            buf.append(Tag.notHave.rawValue)
            guard buf.appendLengthPrefixedString(rootCID) else { return false }
        case .announceVolume(let rootCID, let childCIDs, let totalSize):
            buf.append(Tag.announceVolume.rawValue)
            guard buf.appendLengthPrefixedString(rootCID),
                  buf.appendCount(childCIDs.count, max: MessageLimits.maxTxCIDCount) else { return false }
            for cid in childCIDs {
                guard buf.appendLengthPrefixedString(cid) else { return false }
            }
            buf.appendUInt64(totalSize)
        case .pushVolume(let rootCID, let items):
            buf.append(Tag.pushVolume.rawValue)
            guard buf.appendLengthPrefixedString(rootCID),
                  buf.appendCount(items.count, max: MessageLimits.maxTransactionCount) else { return false }
            for item in items {
                guard buf.appendLengthPrefixedString(item.cid),
                      buf.appendLengthPrefixedData(item.data, maxDataPayload: maxDataPayload) else { return false }
            }
        }
        return true
    }

    public static func deserialize(
        _ data: Data,
        maxDataPayload: UInt32 = IvyConfig.defaultMaxFrameSize
    ) -> Message? {
        var reader = DataReader(data, maxDataPayload: maxDataPayload)
        guard let rawTag = reader.readUInt8(),
              let tag = Tag(rawValue: rawTag) else { return nil }
        switch tag {
        case .ping:
            guard let nonce = reader.readUInt64() else { return nil }
            return .ping(nonce: nonce)
        case .pong:
            guard let nonce = reader.readUInt64() else { return nil }
            return .pong(nonce: nonce)
        case .block:
            guard let cid = reader.readString(),
                  let payload = reader.readData() else { return nil }
            return .block(cid: cid, data: payload)
        case .dontHave:
            guard let cid = reader.readString() else { return nil }
            return .dontHave(cid: cid)
        case .findNode:
            guard let target = reader.readData() else { return nil }
            let fee = reader.readUInt64() ?? 0
            let nonce = reader.readUInt64() ?? 0
            return .findNode(target: target, fee: fee, nonce: nonce)
        case .neighbors:
            guard let count = reader.readUInt16(), count <= MessageLimits.maxNeighborCount else { return nil }
            var peers = [PeerEndpoint]()
            peers.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let key = reader.readString(),
                      let host = reader.readString(),
                      let port = reader.readUInt16() else { return nil }
                peers.append(PeerEndpoint(publicKey: key, host: host, port: port))
            }
            let nonce = reader.readUInt64() ?? 0
            return .neighbors(peers, nonce: nonce)
        case .announceBlock:
            guard let cid = reader.readString() else { return nil }
            return .announceBlock(cid: cid)
        case .identify:
            guard let publicKey = reader.readString(),
                  let observedHost = reader.readString(),
                  let observedPort = reader.readUInt16(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxListenAddrs else { return nil }
            var addrs = [(String, UInt16)]()
            for _ in 0..<count {
                guard let host = reader.readString(),
                      let port = reader.readUInt16() else { return nil }
                addrs.append((host, port))
            }
            var chainPorts = [String: UInt16]()
            if let cpCount = reader.readUInt16(), cpCount <= MessageLimits.maxChainPorts {
                for _ in 0..<cpCount {
                    guard let chain = reader.readString(),
                          let port = reader.readUInt16() else { return nil }
                    chainPorts[chain] = port
                }
            }
            guard let signature = reader.readData() else { return nil }
            return .identify(publicKey: publicKey, observedHost: observedHost, observedPort: observedPort, listenAddrs: addrs, chainPorts: chainPorts, signature: signature)
        case .spawnCertPresentation:
            guard let count = reader.readUInt16(), count <= MessageLimits.maxSpawnCertChain else { return nil }
            var chain: [SpawnCertificate] = []
            for _ in 0..<count {
                guard let childPublicKey = reader.readString(),
                      let pathCount = reader.readUInt16(), pathCount <= UInt16(SpawnCertificate.maxChainPathDepth) else { return nil }
                var chainPath: [String] = []
                for _ in 0..<pathCount {
                    guard let element = reader.readString() else { return nil }
                    chainPath.append(element)
                }
                guard let issuerPublicKey = reader.readString(),
                      let sig = reader.readData() else { return nil }
                chain.append(SpawnCertificate(childPublicKey: childPublicKey, chainPath: chainPath, issuerPublicKey: issuerPublicKey, signature: sig))
            }
            return .spawnCertPresentation(chain: chain)
        case .dhtForward:
            guard let cid = reader.readString(),
                  let ttl = reader.readUInt8() else { return nil }
            return .dhtForward(cid: cid, ttl: ttl)
        case .relayConnect:
            guard let srcKey = reader.readString(),
                  let dstKey = reader.readString() else { return nil }
            let nonce = reader.readUInt64() ?? 0
            return .relayConnect(srcKey: srcKey, dstKey: dstKey, nonce: nonce)
        case .relayStatus:
            guard let code = reader.readUInt8() else { return nil }
            let nonce = reader.readUInt64() ?? 0
            return .relayStatus(code: code, nonce: nonce)
        case .relayData:
            guard let peerKey = reader.readString(),
                  let payload = reader.readData() else { return nil }
            return .relayData(peerKey: peerKey, data: payload)
        case .want:
            guard let count = reader.readUInt16(), count <= MessageLimits.maxTxCIDCount else { return nil }
            var cids = [String]()
            cids.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString() else { return nil }
                cids.append(cid)
            }
            return .want(rootCIDs: cids)
        case .wantVolume:
            guard let rootCID = reader.readString(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxTxCIDCount else { return nil }
            var cids = [String]()
            cids.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString() else { return nil }
                cids.append(cid)
            }
            return .wantVolume(rootCID: rootCID, cids: cids)
        case .pexRequest:
            guard let nonce = reader.readUInt64() else { return nil }
            return .pexRequest(nonce: nonce)
        case .pexResponse:
            guard let nonce = reader.readUInt64(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxPexPeerCount else { return nil }
            var peers = [PeerEndpoint]()
            peers.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let key = reader.readString(),
                      let host = reader.readString(),
                      let port = reader.readUInt16() else { return nil }
                peers.append(PeerEndpoint(publicKey: key, host: host, port: port))
            }
            return .pexResponse(nonce: nonce, peers: peers)
        case .findPins:
            guard let cid = reader.readString() else { return nil }
            return .findPins(cid: cid)
        case .pins:
            guard let cid = reader.readString(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxNeighborCount else { return nil }
            var providers = [String]()
            providers.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let pk = reader.readString() else { return nil }
                providers.append(pk)
            }
            return .pins(cid: cid, providers: providers)
        case .pinAnnounce:
            guard let rootCID = reader.readString(),
                  let publicKey = reader.readString(),
                  let expiry = reader.readUInt64(),
                  let signature = reader.readData(),
                  let fee = reader.readUInt64() else { return nil }
            return .pinAnnounce(rootCID: rootCID, publicKey: publicKey, expiry: expiry, signature: signature, fee: fee)
        case .pinStored:
            guard let rootCID = reader.readString() else { return nil }
            return .pinStored(rootCID: rootCID)
        case .deliveryAck:
            guard let requestId = reader.readUInt64() else { return nil }
            return .deliveryAck(requestId: requestId)
        case .peerMessage:
            guard let topic = reader.readString(),
                  let payload = reader.readData() else { return nil }
            return .peerMessage(topic: topic, payload: payload)
        case .blocks:
            guard let rootCID = reader.readString(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxTransactionCount else { return nil }
            var items = [(cid: String, data: Data)]()
            items.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString(),
                      let data = reader.readData() else { return nil }
                items.append((cid: cid, data: data))
            }
            return .blocks(rootCID: rootCID, items: items)
        case .notHave:
            guard let rootCID = reader.readString() else { return nil }
            return .notHave(rootCID: rootCID)
        case .announceVolume:
            guard let rootCID = reader.readString(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxTxCIDCount else { return nil }
            var cids = [String]()
            cids.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString() else { return nil }
                cids.append(cid)
            }
            let totalSize = reader.readUInt64() ?? 0
            return .announceVolume(rootCID: rootCID, childCIDs: cids, totalSize: totalSize)
        case .pushVolume:
            guard let rootCID = reader.readString(),
                  let count = reader.readUInt16(), count <= MessageLimits.maxTransactionCount else { return nil }
            var items = [(cid: String, data: Data)]()
            items.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let cid = reader.readString(),
                      let data = reader.readData() else { return nil }
                items.append((cid: cid, data: data))
            }
            return .pushVolume(rootCID: rootCID, items: items)
        }
    }

    public static func frame(_ message: Message, maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize) -> Data {
        let payload = message.serialize(maxFrameSize: maxFrameSize)
        guard !payload.isEmpty,
              payload.count <= Int(maxFrameSize) else { return Data() }
        var frame = Data(capacity: 4 + payload.count)
        frame.appendUInt32(UInt32(payload.count))
        frame.append(payload)
        return frame
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

extension Data {
    /// Strict hex decoding: requires an even-length string of hex digits.
    /// Single shared implementation for all key/signature decoding in Ivy.
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
        maxDataPayload: UInt32 = IvyConfig.defaultMaxFrameSize
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
    private var offset: Int = 0

    init(_ data: Data, maxDataPayload: UInt32 = IvyConfig.defaultMaxFrameSize) {
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
        var v: UInt16 = 0
        _ = withUnsafeMutableBytes(of: &v) { data.copyBytes(to: $0, from: start..<start+2) }
        return v.bigEndian
    }

    mutating func readUInt32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        defer { offset += 4 }
        let start = data.startIndex + offset
        var v: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &v) { data.copyBytes(to: $0, from: start..<start+4) }
        return v.bigEndian
    }

    mutating func readUInt64() -> UInt64? {
        guard remaining >= 8 else { return nil }
        defer { offset += 8 }
        let start = data.startIndex + offset
        var v: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &v) { data.copyBytes(to: $0, from: start..<start+8) }
        return v.bigEndian
    }

    mutating func readString() -> String? {
        guard let len = readUInt16(), len <= MessageLimits.maxStringLength else { return nil }
        guard remaining >= Int(len) else { return nil }
        defer { offset += Int(len) }
        let start = data.startIndex + offset
        return String(data: data[start..<start+Int(len)], encoding: .utf8)
    }

    mutating func readData() -> Data? {
        guard let len = readUInt32(), len <= maxDataPayload else { return nil }
        guard remaining >= Int(len) else { return nil }
        defer { offset += Int(len) }
        let start = data.startIndex + offset
        return Data(data[start..<start+Int(len)])
    }
}
