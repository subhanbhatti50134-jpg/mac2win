// swift-tools-version: 6.0
import PackageDescription

// UI-free core of the Mac2Win Transfer Mac sender (SPEC §3: UI depends on core, never the reverse).
// Tests run on macOS (ADR-010) and consume the shared golden vectors in protocol/vectors/.
// The SwiftUI sender UI lives in ../App/Sources/Mac2WinSender (built as the Mac2WinSender
// executable target) and is packaged into a universal .app + DMG by mac-sender/App/build_dmg.sh.
let package = Package(
    name: "Mac2WinSenderCore",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "Mac2WinSenderCore", targets: ["Mac2WinSenderCore"]),
        .executable(name: "Mac2WinSender", targets: ["Mac2WinSender"])
    ],
    targets: [
        .target(
            name: "Mac2WinSenderCore",
            path: "Sources/Mac2WinSenderCore"
        ),
        .executableTarget(
            name: "Mac2WinSender",
            dependencies: ["Mac2WinSenderCore"],
            path: "../App/Sources/Mac2WinSender"
        ),
        .testTarget(
            name: "Mac2WinSenderCoreTests",
            dependencies: ["Mac2WinSenderCore"],
            path: "Tests/Mac2WinSenderCoreTests"
        ),
    ]
)
