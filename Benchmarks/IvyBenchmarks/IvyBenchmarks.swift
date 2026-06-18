import Foundation
import Ivy
import Tally

@main
struct IvyBenchmarks {
    static func main() {
        let samples = 50
        let opsPerSample = 1000
        var results: [BenchmarkResult] = []
        let clock = ContinuousClock()

        // --- Message: ping serialize ---
        do {
            var timings: [Double] = []
            for _ in 0..<samples {
                let msg = Message.ping(nonce: 42)
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = msg.serialize()
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg serialize (ping)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: block serialize (4KB) ---
        do {
            var timings: [Double] = []
            let payload = Data(repeating: 0xAB, count: 4096)
            for _ in 0..<samples {
                let msg = Message.block(cid: "QmTestCID123456", data: payload)
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = msg.serialize()
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg serialize (4KB block)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: block serialize (256KB) ---
        do {
            var timings: [Double] = []
            let payload = Data(repeating: 0xCD, count: 256 * 1024)
            for _ in 0..<samples {
                let msg = Message.block(cid: "QmLargeBlock", data: payload)
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = msg.serialize()
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg serialize (256KB block)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: ping deserialize ---
        do {
            var timings: [Double] = []
            let data = Message.ping(nonce: 42).serialize()
            for _ in 0..<samples {
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = Message.deserialize(data)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg deserialize (ping)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: block deserialize (4KB) ---
        do {
            var timings: [Double] = []
            let data = Message.block(cid: "QmTestCID123456", data: Data(repeating: 0xAB, count: 4096)).serialize()
            for _ in 0..<samples {
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = Message.deserialize(data)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg deserialize (4KB block)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: neighbors serialize (20 peers) ---
        do {
            var timings: [Double] = []
            var peers: [PeerEndpoint] = []
            for i in 0..<20 {
                peers.append(PeerEndpoint(publicKey: "pk\(String(format: "%040d", i))", host: "192.168.1.\(i)", port: UInt16(4000 + i)))
            }
            for _ in 0..<samples {
                let msg = Message.neighbors(peers)
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = msg.serialize()
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg serialize (20 neighbors)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: frame (ping) ---
        do {
            var timings: [Double] = []
            for _ in 0..<samples {
                let msg = Message.ping(nonce: 42)
                let start = clock.now
                for _ in 0..<opsPerSample {
                    _ = Message.frame(msg)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg frame (ping)", iterations: opsPerSample, samples: timings))
        }

        // --- Router: SHA256 hash ---
        do {
            var timings: [Double] = []
            for _ in 0..<samples {
                let start = clock.now
                for i in 0..<opsPerSample {
                    _ = Router.hash("peer-key-\(i)")
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "router hash (SHA256)", iterations: opsPerSample, samples: timings))
        }

        // --- Router: common prefix length ---
        do {
            var timings: [Double] = []
            let hashes = (0..<100).map { Router.hash("key-\($0)") }
            for _ in 0..<samples {
                let start = clock.now
                for i in 0..<opsPerSample {
                    let a = hashes[i % hashes.count]
                    let b = hashes[(i + 1) % hashes.count]
                    _ = Router.commonPrefixLength(a, b)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "router CPL", iterations: opsPerSample, samples: timings))
        }

        // --- Router: addPeer ---
        do {
            var timings: [Double] = []
            for _ in 0..<samples {
                let tally = Tally()
                let router = Router(localID: PeerID(publicKey: "local-bench"), k: 20)
                let start = clock.now
                for i in 0..<opsPerSample {
                    let key = "bench-peer-\(i)"
                    let ep = PeerEndpoint(publicKey: key, host: "10.0.0.\(i % 256)", port: 4001)
                    router.addPeer(PeerID(publicKey: key), endpoint: ep, tally: tally)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "router addPeer", iterations: opsPerSample, samples: timings))
        }

        // --- Router: closestPeers (100 peers, find 10) ---
        do {
            var timings: [Double] = []
            let tally = Tally()
            let router = Router(localID: PeerID(publicKey: "local-bench"), k: 20)
            for i in 0..<100 {
                let key = "closest-peer-\(i)"
                let ep = PeerEndpoint(publicKey: key, host: "10.0.0.\(i % 256)", port: 4001)
                router.addPeer(PeerID(publicKey: key), endpoint: ep, tally: tally)
            }
            let targets = (0..<50).map { Router.hash("target-\($0)") }
            for _ in 0..<samples {
                let start = clock.now
                for i in 0..<opsPerSample {
                    _ = router.closestPeers(to: targets[i % targets.count], count: 10)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "router closestPeers (100→10)", iterations: opsPerSample, samples: timings))
        }

        // --- Router: closestPeers (1000 peers, find 20) ---
        do {
            var timings: [Double] = []
            let tally = Tally()
            let router = Router(localID: PeerID(publicKey: "local-1k"), k: 100)
            for i in 0..<1000 {
                let key = "peer1k-\(i)"
                let ep = PeerEndpoint(publicKey: key, host: "10.0.\(i / 256).\(i % 256)", port: 4001)
                router.addPeer(PeerID(publicKey: key), endpoint: ep, tally: tally)
            }
            let targets = (0..<50).map { Router.hash("target1k-\($0)") }
            for _ in 0..<samples {
                let start = clock.now
                for i in 0..<opsPerSample {
                    _ = router.closestPeers(to: targets[i % targets.count], count: 20)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "router closestPeers (1000→20)", iterations: opsPerSample, samples: timings))
        }

        // --- Message: full roundtrip (serialize + deserialize) ---
        do {
            var timings: [Double] = []
            let payload = Data(repeating: 0xEF, count: 4096)
            for _ in 0..<samples {
                let start = clock.now
                for _ in 0..<opsPerSample {
                    let msg = Message.block(cid: "QmRoundtrip", data: payload)
                    let serialized = msg.serialize()
                    _ = Message.deserialize(serialized)
                }
                let elapsed = start.duration(to: clock.now)
                let us = Double(elapsed.components.attoseconds) / 1e12 + Double(elapsed.components.seconds) * 1e6
                timings.append(us / Double(opsPerSample))
            }
            results.append(BenchmarkResult(name: "msg roundtrip (4KB block)", iterations: opsPerSample, samples: timings))
        }

        printReport(results)
    }
}
