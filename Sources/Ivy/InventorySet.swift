import Foundation

public struct InventorySet: Sendable {
    private var recent: BoundedSet<String>

    public init(capacity: Int = 65_536) {
        self.recent = BoundedSet(capacity: capacity)
    }

    public mutating func insert(_ cid: String) {
        recent.insert(cid)
    }

    public func contains(_ cid: String) -> Bool {
        recent.contains(cid)
    }

    @discardableResult
    public mutating func remove(_ cid: String) -> Bool {
        recent.remove(cid)
    }

    public var count: Int { recent.count }
}
