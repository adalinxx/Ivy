import Crypto
import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import Ivy
import Tally

func deterministicTestSigningKey(_ label: String) -> Curve25519.Signing.PrivateKey {
    try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
}

func deterministicTestPeerKey(_ label: String) -> String {
    try! PeerKey(rawRepresentation: deterministicTestSigningKey(label).publicKey.rawRepresentation).hex
}

final class TestWireSink: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let lock = NSLock()
    private var bytes: [UInt8] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        let incoming = buffer.readBytes(length: buffer.readableBytes) ?? []
        lock.withLock { bytes.append(contentsOf: incoming) }
    }

    var byteCount: Int { lock.withLock { bytes.count } }

    var hasRelayClose: Bool {
        let snapshot = lock.withLock { bytes }
        var offset = 0
        while offset + 4 <= snapshot.count {
            let length = snapshot[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
            let end = offset + 4 + length
            guard end <= snapshot.count else { return false }
            if let wire = try? SessionWireRecord.deserialize(Data(snapshot[offset + 4..<end])),
               case .data(let record) = wire,
               case .relayClose? = Message.deserialize(record.payload) {
                return true
            }
            offset = end
        }
        return false
    }
}

final class TestChannelRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var channel: Channel?

    func store(_ channel: Channel) { lock.withLock { self.channel = channel } }
    var isActive: Bool { lock.withLock { channel?.isActive == true } }
}

struct TestLoopback {
    let listener: Channel
    let client: Channel
    let sink: TestWireSink
    let port: UInt16

    static func open() async throws -> Self {
        let sink = TestWireSink()
        let listener = try await ServerBootstrap(
            group: MultiThreadedEventLoopGroup.singleton
        ).childChannelInitializer { channel in
            channel.pipeline.addHandler(sink)
        }.bind(host: "127.0.0.1", port: 0).get()
        let address = try #require(listener.localAddress)
        let rawPort = try #require(address.port)
        let port = try #require(UInt16(exactly: rawPort))
        let client = try await ClientBootstrap(
            group: MultiThreadedEventLoopGroup.singleton
        ).connect(to: address).get()
        return Self(listener: listener, client: client, sink: sink, port: port)
    }

    func close() async {
        try? await client.close().get()
        try? await listener.close().get()
    }
}

enum TestSynchronizationError: Error, CustomStringConvertible {
    case cancelled(String)
    case timedOut(String)

    var description: String {
        switch self {
        case .cancelled(let operation):
            "Cancelled while waiting for \(operation)"
        case .timedOut(let operation):
            "Timed out after 5 seconds waiting for \(operation)"
        }
    }
}

enum TestSynchronization {
    static func wait(
        for operation: String,
        condition: @escaping @Sendable () async -> Bool
    ) async throws {
        for _ in 0..<250 {
            if await condition() { return }
            do {
                try await Task.sleep(for: .milliseconds(20))
            } catch {
                throw TestSynchronizationError.cancelled(operation)
            }
        }
        throw TestSynchronizationError.timedOut(operation)
    }
}

private final class BoundedTestTaskState<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Value?

    func store(_ value: Value) {
        lock.withLock { result = value }
    }

    func snapshot() -> Value? {
        lock.withLock { result }
    }
}

struct BoundedTestTask<Value: Sendable>: Sendable {
    private let state: BoundedTestTaskState<Value>
    private let task: Task<Void, Never>

    init(_ operation: @escaping @Sendable () async -> Value) {
        let state = BoundedTestTaskState<Value>()
        self.state = state
        self.task = Task {
            state.store(await operation())
        }
    }

    func value(waitingFor description: String) async throws -> Value {
        do {
            try await TestSynchronization.wait(for: description) {
                state.snapshot() != nil
            }
        } catch {
            task.cancel()
            throw error
        }
        return state.snapshot()!
    }

    func cancel() {
        task.cancel()
    }
}

actor TestBarrier {
    private let name: String
    private var arrivals = 0
    private var isOpen = false

    init(_ name: String = "test barrier") {
        self.name = name
    }

    func arriveAndWait() async throws {
        arrivals += 1
        try await TestSynchronization.wait(for: "\(name) release") {
            await self.opened()
        }
    }

    func waitForArrivals(_ count: Int = 1) async throws {
        try await TestSynchronization.wait(for: "\(name) to receive \(count) arrival(s)") {
            await self.hasArrivals(count)
        }
    }

    func release() {
        isOpen = true
    }

    private func opened() -> Bool { isOpen }
    private func hasArrivals(_ count: Int) -> Bool { arrivals >= count }
}

final class TestContinuousClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.Instant.now

    var now: ContinuousClock.Instant { lock.withLock { instant } }

    func advance(by duration: Duration) {
        lock.withLock { instant = instant.advanced(by: duration) }
    }
}

struct TestSeededGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        guard let raw = ProcessInfo.processInfo.environment["IVY_TEST_SEED"] else {
            state = seed
            return
        }
        let value = raw.lowercased()
        state = if value.hasPrefix("0x") {
            UInt64(value.dropFirst(2), radix: 16) ?? seed
        } else {
            UInt64(value) ?? seed
        }
    }

    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return state
    }

    mutating func shuffled<T>(_ values: [T]) -> [T] {
        var result = values
        guard result.count > 1 else { return result }
        for index in stride(from: result.count - 1, through: 1, by: -1) {
            result.swapAt(index, Int(next() % UInt64(index + 1)))
        }
        return result
    }
}

extension IvyConfig {
    init(
        publicKey: String,
        listenPort: UInt16 = 4001,
        bootstrapPeers: [PeerEndpoint] = [],
        tallyConfig: TallyConfig = .default,
        kBucketSize: Int = 20,
        requestTimeout: Duration = .seconds(15),
        relayTimeout: Duration = .seconds(5),
        stunServers: [(String, Int)] = IvyConfig.defaultSTUNServers,
        healthConfig: PeerHealthConfig = .default,
        routingRefreshInterval: Duration = .seconds(120),
        signingKey: Data = Data(),
        logger: any IvyLogger = NullLogger(),
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        reservedOutboundConnectionSlots: Int = 0,
        maxConnectionsPerNetgroup: Int = 2,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerRequest: Int = 64,
        maxConcurrentContentRequests: Int = 64,
        minPeerKeyBits: Int = 0,
        maxContentCandidates: Int = 8,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
        privateContentExchangeEnabled: Bool = false,
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay
    ) {
        let privateKey: Curve25519.Signing.PrivateKey
        if let supplied = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingKey) {
            privateKey = supplied
        } else {
            privateKey = deterministicTestSigningKey(publicKey)
        }
        self.init(
            signingKey: privateKey,
            listenPort: listenPort,
            bootstrapPeers: bootstrapPeers,
            tallyConfig: tallyConfig,
            kBucketSize: kBucketSize,
            requestTimeout: requestTimeout,
            relayTimeout: relayTimeout,
            stunServers: stunServers,
            healthConfig: healthConfig,
            routingRefreshInterval: routingRefreshInterval,
            logger: logger,
            maxConnections: maxConnections,
            reservedOutboundConnectionSlots: reservedOutboundConnectionSlots,
            maxConnectionsPerNetgroup: maxConnectionsPerNetgroup,
            maxPendingRequests: maxPendingRequests,
            maxWaitersPerRequest: maxWaitersPerRequest,
            maxConcurrentContentRequests: maxConcurrentContentRequests,
            minPeerKeyBits: minPeerKeyBits,
            maxContentCandidates: maxContentCandidates,
            externalAddress: externalAddress,
            relayEnabled: relayEnabled,
            privateContentExchangeEnabled: privateContentExchangeEnabled,
            carriers: carriers,
            mode: mode)
    }
}
