// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Ivy",
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10), .visionOS(.v1)],
    products: [
        .library(name: "Ivy", targets: ["Ivy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/adalinxx/Tally.git", from: "2.0.0"),
        .package(url: "https://github.com/swift-libp2p/swift-cid.git", from: "0.0.1"),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", from: "0.0.1"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    ],
    targets: [
        .target(
            name: "Ivy",
            dependencies: [
                "Tally",
                .product(name: "CID", package: "swift-cid"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "IvyTests",
            dependencies: [
                "Ivy",
                .product(name: "CID", package: "swift-cid"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
        .executableTarget(
            name: "IvyBenchmarks",
            dependencies: ["Ivy"],
            path: "Benchmarks/IvyBenchmarks"
        ),
    ]
)
