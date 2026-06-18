import Foundation
#if canImport(os)
import os
#endif

#if canImport(os)
struct LockedState<State: Sendable>: Sendable {
    private let _lock: OSAllocatedUnfairLock<State>

    init(initialState: State) {
        _lock = OSAllocatedUnfairLock(initialState: initialState)
    }

    @inline(__always)
    func withLock<T: Sendable>(_ body: @Sendable (inout State) throws -> T) rethrows -> T {
        try _lock.withLock(body)
    }
}
#else
final class LockedState<State: Sendable>: @unchecked Sendable {
    private var _state: State
    private let _lock = NSLock()

    init(initialState: State) {
        _state = initialState
    }

    @inline(__always)
    func withLock<T>(_ body: (inout State) throws -> T) rethrows -> T {
        _lock.lock()
        defer { _lock.unlock() }
        return try body(&_state)
    }
}
#endif
