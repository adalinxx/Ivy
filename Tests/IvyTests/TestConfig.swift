import Crypto
import Foundation
@testable import Ivy
import Tally

func deterministicTestSigningKey(_ label: String) -> Curve25519.Signing.PrivateKey {
    try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
}

func deterministicTestPeerKey(_ label: String) -> String {
    try! PeerKey(rawRepresentation: deterministicTestSigningKey(label).publicKey.rawRepresentation).hex
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
        maxConnectionsPerNetgroup: Int = 2,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerRequest: Int = 64,
        maxConcurrentContentRequests: Int = 64,
        minPeerKeyBits: Int = 0,
        maxContentCandidates: Int = 8,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
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
            maxConnectionsPerNetgroup: maxConnectionsPerNetgroup,
            maxPendingRequests: maxPendingRequests,
            maxWaitersPerRequest: maxWaitersPerRequest,
            maxConcurrentContentRequests: maxConcurrentContentRequests,
            minPeerKeyBits: minPeerKeyBits,
            maxContentCandidates: maxContentCandidates,
            externalAddress: externalAddress,
            relayEnabled: relayEnabled,
            carriers: carriers,
            mode: mode)
    }
}
