import Foundation

public enum IvyLogLevel: Int, Sendable, Comparable {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3

    public static func < (lhs: IvyLogLevel, rhs: IvyLogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public protocol IvyLogger: Sendable {
    func log(_ level: IvyLogLevel, _ message: @autoclosure () -> String, file: String, line: Int)
}

public extension IvyLogger {
    func debug(_ message: @autoclosure () -> String, file: String = #file, line: Int = #line) {
        log(.debug, message(), file: file, line: line)
    }
    func info(_ message: @autoclosure () -> String, file: String = #file, line: Int = #line) {
        log(.info, message(), file: file, line: line)
    }
    func warning(_ message: @autoclosure () -> String, file: String = #file, line: Int = #line) {
        log(.warning, message(), file: file, line: line)
    }
    func error(_ message: @autoclosure () -> String, file: String = #file, line: Int = #line) {
        log(.error, message(), file: file, line: line)
    }
}

public struct PrintLogger: IvyLogger {
    public let minLevel: IvyLogLevel

    public init(minLevel: IvyLogLevel = .info) {
        self.minLevel = minLevel
    }

    public func log(_ level: IvyLogLevel, _ message: @autoclosure () -> String, file: String, line: Int) {
        guard level >= minLevel else { return }
        let label: String
        switch level {
        case .debug: label = "DEBUG"
        case .info: label = "INFO"
        case .warning: label = "WARN"
        case .error: label = "ERROR"
        }
        let filename = (file as NSString).lastPathComponent
        print("[\(label)] \(filename):\(line) \(message())")
    }
}

public struct NullLogger: IvyLogger {
    public init() {}
    public func log(_ level: IvyLogLevel, _ message: @autoclosure () -> String, file: String, line: Int) {}
}
