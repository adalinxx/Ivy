// swift-tools-version: 6.3
import PackageDescription

// Kept separate from the Ivy package: swift-nio-quic requires a Swift 6.3
// toolchain and macOS 26, floors that would otherwise propagate to every Ivy
// consumer. Ivy itself stays on Swift 6.0 / macOS 14.
let package = Package(
    name: "IvyQUIC",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "IvyQUIC", targets: ["IvyQUIC"]),
    ],
    dependencies: [
        .package(path: ".."),
        .package(url: "https://github.com/apple/swift-nio-quic.git", from: "0.1.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.19.3"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.101.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "IvyQUIC",
            dependencies: [
                .product(name: "Ivy", package: "Ivy"),
                .product(name: "NIOQUIC", package: "swift-nio-quic"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
    ]
)
