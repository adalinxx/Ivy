// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Ivy",
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10), .visionOS(.v1)],
    products: [
        .library(name: "Ivy", targets: ["Ivy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/adalinxx/Tally.git", from: "3.0.0"),
        // The lower bound carries a prerelease so a graph that also contains a
        // package pinning a swift-crypto prerelease can resolve; SwiftPM never
        // matches a prerelease against a range whose bounds are all releases.
        // Ordinary builds still take the newest stable release.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0-a"..<"6.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    ],
    targets: [
        .target(
            name: "Ivy",
            dependencies: [
                "Tally",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "IvyTests",
            dependencies: [
                "Ivy",
                "Tally",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
    ]
)
