// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CognitoAuth",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "CognitoAuth",
            targets: ["CognitoAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/adam-fowler/big-num", .upToNextMajor(from: "2.0.0")),
        .package(url: "https://github.com/apple/swift-crypto", .upToNextMajor(from: "1.1.6")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "CognitoAuth",
            dependencies: [
               .product(name: "BigNum", package: "big-num"),
               .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "CognitoAuthTests",
            dependencies: ["CognitoAuth"]),
    ]
)
