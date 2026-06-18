import Foundation

struct BenchmarkResult: Codable, Sendable {
    let name: String
    let iterations: Int
    let samples: [Double]

    var min: Double { samples.min() ?? 0 }
    var max: Double { samples.max() ?? 0 }
    var mean: Double { samples.reduce(0, +) / Double(samples.count) }
    var median: Double { percentile(0.5) }
    var p95: Double { percentile(0.95) }
    var p99: Double { percentile(0.99) }
    var stddev: Double {
        let m = mean
        let variance = samples.map { ($0 - m) * ($0 - m) }.reduce(0, +) / Double(samples.count)
        return variance.squareRoot()
    }

    func percentile(_ p: Double) -> Double {
        let sorted = samples.sorted()
        guard !sorted.isEmpty else { return 0 }
        let index = p * Double(sorted.count - 1)
        let lower = Int(index)
        let upper = Swift.min(lower + 1, sorted.count - 1)
        let fraction = index - Double(lower)
        return sorted[lower] * (1 - fraction) + sorted[upper] * fraction
    }
}

func formatMicros(_ us: Double) -> String {
    if us >= 1_000_000 {
        return String(format: "%.1fs", us / 1_000_000)
    } else if us >= 1_000 {
        return String(format: "%.1fms", us / 1_000)
    } else if us >= 1 {
        return String(format: "%.1fus", us)
    } else {
        return String(format: "%.0fns", us * 1000)
    }
}

func pad(_ s: String, width: Int, right: Bool = false) -> String {
    if s.count >= width { return s }
    let padding = String(repeating: " ", count: width - s.count)
    return right ? (padding + s) : (s + padding)
}

func printReport(_ results: [BenchmarkResult]) {
    let nameWidth = max(results.map(\.name.count).max() ?? 0, 9)
    let cols = [
        pad("Benchmark", width: nameWidth),
        pad("Min", width: 10, right: true),
        pad("Median", width: 10, right: true),
        pad("Mean", width: 10, right: true),
        pad("P95", width: 10, right: true),
        pad("P99", width: 10, right: true),
        pad("StdDev", width: 10, right: true)
    ]
    let header = cols.joined(separator: " ")
    let separator = String(repeating: "-", count: header.count)
    print("\n\(separator)")
    print(header)
    print(separator)
    for r in results {
        let row = [
            pad(r.name, width: nameWidth),
            pad(formatMicros(r.min), width: 10, right: true),
            pad(formatMicros(r.median), width: 10, right: true),
            pad(formatMicros(r.mean), width: 10, right: true),
            pad(formatMicros(r.p95), width: 10, right: true),
            pad(formatMicros(r.p99), width: 10, right: true),
            pad(formatMicros(r.stddev), width: 10, right: true)
        ]
        print(row.joined(separator: " "))
    }
    print(separator)
    print("All times in microseconds (us) per operation.\n")
}
