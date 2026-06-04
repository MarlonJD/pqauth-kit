// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PQAuthKitSwift",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PQAuthKitSwift", targets: ["PQAuthKitSwift"])
    ],
    targets: [
        .target(name: "PQAuthKitSwift"),
        .testTarget(
            name: "PQAuthKitSwiftTests",
            dependencies: ["PQAuthKitSwift"]
        )
    ]
)
