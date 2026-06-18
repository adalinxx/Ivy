import Foundation
import DequeModule

struct BoundedSet<Element: Hashable & Sendable>: Sendable {
    private var storage: Set<Element>
    private var insertionOrder: Deque<Element>
    private var tombstones: [Element: Int]
    private var tombstoneCount: Int
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
        self.storage = Set(minimumCapacity: min(capacity, 1024))
        self.insertionOrder = Deque()
        self.insertionOrder.reserveCapacity(min(capacity, 1024))
        self.tombstones = Dictionary(minimumCapacity: min(capacity, 1024))
        self.tombstoneCount = 0
    }

    var count: Int { storage.count }
    var isEmpty: Bool { storage.isEmpty }

    func contains(_ element: Element) -> Bool {
        storage.contains(element)
    }

    @discardableResult
    mutating func insert(_ element: Element) -> Bool {
        guard capacity > 0 else { return false }
        if storage.contains(element) { return false }

        if storage.count >= capacity {
            let evictCount = max(capacity / 4, 1)
            var evicted = 0
            while storage.count >= capacity || evicted < evictCount {
                guard removeOldestTracked() else { break }
                evicted += 1
            }
        }

        storage.insert(element)
        insertionOrder.append(element)
        return true
    }

    mutating func removeAll() {
        storage.removeAll()
        insertionOrder.removeAll()
        tombstones.removeAll()
        tombstoneCount = 0
    }

    @discardableResult
    mutating func remove(_ element: Element) -> Bool {
        guard storage.remove(element) != nil else { return false }
        markRemoved(element)
        return true
    }

    private mutating func markRemoved(_ element: Element) {
        tombstones[element, default: 0] += 1
        tombstoneCount += 1
        compactOrderIfNeeded()
    }

    @discardableResult
    private mutating func removeOldestTracked() -> Bool {
        while let oldest = insertionOrder.popFirst() {
            if let count = tombstones[oldest], count > 0 {
                if count == 1 {
                    tombstones.removeValue(forKey: oldest)
                } else {
                    tombstones[oldest] = count - 1
                }
                tombstoneCount -= 1
                continue
            }
            if storage.remove(oldest) != nil {
                return true
            }
        }
        return false
    }

    private mutating func compactOrderIfNeeded() {
        guard tombstoneCount > Swift.max(insertionOrder.count / 2, capacity) else { return }
        var pending = tombstones
        var compacted = Deque<Element>()
        compacted.reserveCapacity(min(storage.count, 1024))
        while let element = insertionOrder.popFirst() {
            if let count = pending[element], count > 0 {
                if count == 1 {
                    pending.removeValue(forKey: element)
                } else {
                    pending[element] = count - 1
                }
                continue
            }
            if storage.contains(element) {
                compacted.append(element)
            }
        }
        insertionOrder = compacted
        tombstones.removeAll()
        tombstoneCount = 0
    }
}

struct BoundedDictionary<Key: Hashable & Sendable, Value: Sendable>: Sendable {
    private var storage: [Key: Value]
    private var keyOrder: Deque<Key>
    private var tombstones: [Key: Int]
    private var tombstoneCount: Int
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
        self.storage = Dictionary(minimumCapacity: min(capacity, 1024))
        self.keyOrder = Deque()
        self.keyOrder.reserveCapacity(min(capacity, 1024))
        self.tombstones = Dictionary(minimumCapacity: min(capacity, 1024))
        self.tombstoneCount = 0
    }

    var count: Int { storage.count }
    var isEmpty: Bool { storage.isEmpty }
    var keys: Dictionary<Key, Value>.Keys { storage.keys }
    var values: Dictionary<Key, Value>.Values { storage.values }

    subscript(key: Key) -> Value? {
        get { storage[key] }
        set {
            if let value = newValue {
                guard capacity > 0 else { return }
                if storage[key] == nil {
                    if storage.count >= capacity {
                        // Fallback eviction: shed oldest entries to make room.
                        // Callers (e.g. ProfitWeightedStore) should make explicit
                        // room via `removeValue` before inserting; this path is a
                        // safety valve.
                        let evictCount = Swift.max(capacity / 4, 1)
                        var evicted = 0
                        while storage.count >= capacity || evicted < evictCount {
                            guard removeOldestKeyTracking() else { break }
                            evicted += 1
                        }
                    }
                    keyOrder.append(key)
                }
                storage[key] = value
            } else {
                if storage.removeValue(forKey: key) != nil {
                    removeKeyTracking(key)
                }
            }
        }
    }

    @discardableResult
    mutating func removeValue(forKey key: Key) -> Value? {
        guard let removed = storage.removeValue(forKey: key) else { return nil }
        removeKeyTracking(key)
        return removed
    }

    mutating func removeAll() {
        storage.removeAll()
        keyOrder.removeAll()
        tombstones.removeAll()
        tombstoneCount = 0
    }

    mutating func removeAll(where predicate: (Key, Value) -> Bool) {
        let toRemove = storage.filter(predicate).map(\.key)
        for key in toRemove {
            removeKeyTracking(key)
            storage.removeValue(forKey: key)
        }
    }

    func filter(_ isIncluded: (Key, Value) -> Bool) -> [(Key, Value)] {
        storage.filter { isIncluded($0.key, $0.value) }.map { ($0.key, $0.value) }
    }

    func max(by areInIncreasingOrder: ((key: Key, value: Value), (key: Key, value: Value)) -> Bool) -> (key: Key, value: Value)? {
        storage.max(by: areInIncreasingOrder)
    }

    func contains(key: Key) -> Bool {
        storage[key] != nil
    }

    private mutating func removeKeyTracking(_ key: Key) {
        tombstones[key, default: 0] += 1
        tombstoneCount += 1
        compactOrderIfNeeded()
    }

    @discardableResult
    private mutating func removeOldestKeyTracking() -> Bool {
        while let oldest = keyOrder.popFirst() {
            if let count = tombstones[oldest], count > 0 {
                if count == 1 {
                    tombstones.removeValue(forKey: oldest)
                } else {
                    tombstones[oldest] = count - 1
                }
                tombstoneCount -= 1
                continue
            }
            if storage.removeValue(forKey: oldest) != nil {
                return true
            }
        }
        return false
    }

    private mutating func compactOrderIfNeeded() {
        guard tombstoneCount > Swift.max(keyOrder.count / 2, capacity) else { return }
        var pending = tombstones
        var compacted = Deque<Key>()
        compacted.reserveCapacity(min(storage.count, 1024))
        while let key = keyOrder.popFirst() {
            if let count = pending[key], count > 0 {
                if count == 1 {
                    pending.removeValue(forKey: key)
                } else {
                    pending[key] = count - 1
                }
                continue
            }
            if storage[key] != nil {
                compacted.append(key)
            }
        }
        keyOrder = compacted
        tombstones.removeAll()
        tombstoneCount = 0
    }
}

/// Lazy-refill token bucket for per-peer rate limiting.
/// `tryConsume` returns false when starved; state is updated on every call
/// so idle peers retain their full capacity until the next message.
struct TokenBucket: Sendable {
    var tokens: Double
    var lastRefill: ContinuousClock.Instant
    let capacity: Double
    let refillPerSec: Double

    init(capacity: Double, refillPerSec: Double) {
        self.tokens = capacity
        self.lastRefill = .now
        self.capacity = capacity
        self.refillPerSec = refillPerSec
    }

    mutating func tryConsume(_ cost: Double = 1) -> Bool {
        let now = ContinuousClock.Instant.now
        let elapsed = Double((now - lastRefill).components.seconds)
            + Double((now - lastRefill).components.attoseconds) / 1e18
        if elapsed > 0 {
            tokens = min(capacity, tokens + elapsed * refillPerSec)
            lastRefill = now
        }
        guard tokens >= cost else { return false }
        tokens -= cost
        return true
    }
}
