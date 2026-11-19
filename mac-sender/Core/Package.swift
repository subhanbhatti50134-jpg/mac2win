// swift-tools-version: 6.0
import PackageDescription

// UI-free core of the Mac2Win Transfer Mac sender (SPEC §3: UI depends on core, never the reverse).
// Tests run on macOS (ADR-010) and consume the shared golden vectors in protocol/vectors/.
// The SwiftUI sender UI lives in ../App/Sources/Mac2WinSender and is NOT part of this
// package: SwiftPM rejects targets whose path is outside the package root (CI caught that:
// "target 'Mac2WinSender' in package 'core' is outside the package root"). The UI is
// compiled by the Xcode project and packaged into a universal .app + DMG by
// mac-sender/App/build_dmg.sh instead.
let package = Package(
    name: "Mac2WinSenderCore",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "Mac2WinSenderCore", targets: ["Mac2WinSenderCore"])
    ],
    targets: [
        .target(
            name: "Mac2WinSenderCore",
            path: "Sources/Mac2WinSenderCore"
        ),
        .testTarget(
            name: "Mac2WinSenderCoreTests",
            dependencies: ["Mac2WinSenderCore"],
            path: "Tests/Mac2WinSenderCoreTests"
        ),
    ]
)
