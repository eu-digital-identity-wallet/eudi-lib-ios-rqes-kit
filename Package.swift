// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RqesKit",
    defaultLocalization: "en",
    platforms: [.iOS(.v16)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "RqesKit",
            targets: ["RqesKit"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-rqes-csc-swift.git", exact: "0.7.1"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.3"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "RqesKit", dependencies: [
                .product(name: "RQESLib", package: "eudi-lib-ios-rqes-csc-swift"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Logging", package: "swift-log")
            ]),
        .testTarget(
            name: "RqesKitTests",
            dependencies: ["RqesKit"]
        ),
    ]
)
