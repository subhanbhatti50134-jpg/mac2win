import CryptoKit
import Foundation
import XCTest
@testable import Mac2WinSenderCore

/// End-to-end cross-implementation test: the real Swift sender talking to the real .NET
/// receiver over loopback TLS (SPEC §1.2/§10, ADR-010: runs on macOS only).
///
/// Skips (XCTSkip) unless a running receiver is provided:
///   M2W_RECEIVER_URL   e.g. https://127.0.0.1:48610
///   M2W_FINGERPRINT    receiver cert sha256 hex ("cert: sha256:…" line of ReceiverHost)
///   M2W_PIN            fixed PIN (ReceiverHost --pin)
///   M2W_DESTINATION    destination root — optional; enables on-disk byte assertions
///
/// The `cross-impl` job in .github/workflows/ci.yml starts ReceiverHost with
/// --auto-approve and exports these. Without them this test skips and `swift test`
/// still passes for pure unit runs.
///
/// Invariants asserted here mirror docs/VERIFICATION.md:
///   * on-disk SHA-256 == source for every transferred file
///   * no `*.m2wpart` anywhere under the destination
///   * source files byte-identical after the transfer
///   * ledger totals reconcile (Σ outcomes == items, one terminal outcome each)
final class CrossImplTransferTests: XCTestCase {

    private struct SourceFile {
        let path: String // NFC, '/'-separated, relative to source/destination root
        let bytes: Data
        let mtimeUtcNs: String
    }

    func testEndToEndTransferVerifiesAgainstDotNetReceiver() async throws {
        let baseURLString = try Self.env("M2W_RECEIVER_URL")
        let fingerprint = try Self.env("M2W_FINGERPRINT").lowercased()
        let pin = try Self.env("M2W_PIN")
        let destination = ProcessInfo.processInfo.environment["M2W_DESTINATION"]

        guard let baseURL = URL(string: baseURLString) else {
            throw XCTSkip("M2W_RECEIVER_URL is not a valid URL: \(baseURLString)")
        }

        // --- source tree: multi-chunk (> default 4 MiB), empty file, nested, unicode ---
        let mtime = String(Int64(Date().timeIntervalSince1970 * 1_000_000_000))
        var big = Data(capacity: 4 * 1024 * 1024 + 123)
        var state: UInt8 = 0x5A
        while big.count < 4 * 1024 * 1024 + 123 {
            big.append(state)
            state = state &* 31 &+ 7
        }
        var files: [SourceFile] = [
            SourceFile(path: "hello.txt", bytes: Data("Hello, Windows!\n".utf8), mtimeUtcNs: mtime),
            SourceFile(path: "empty.dat", bytes: Data(), mtimeUtcNs: mtime),
            SourceFile(path: "docs/notes.md", bytes: Data("# notes\n".utf8), mtimeUtcNs: mtime),
            SourceFile(path: "résumé.txt", bytes: Data("unicode name\n".utf8), mtimeUtcNs: mtime),
            SourceFile(path: "big.bin", bytes: big, mtimeUtcNs: mtime),
        ]

        // sources live on disk (a real Mac volume in production): write then read back so
        // every byte we declare is exactly what a later byte-identity check re-reads
        let sourceRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("m2w-crossimpl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: sourceRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: sourceRoot) }
        for f in files {
            let url = sourceRoot.appendingPathComponent(f.path)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try f.bytes.write(to: url)
        }
        files = try files.map {
            SourceFile(path: $0.path, bytes: try Data(contentsOf:
                    sourceRoot.appendingPathComponent($0.path)), mtimeUtcNs: $0.mtimeUtcNs)
        }
        let originalBytes = Dictionary(uniqueKeysWithValues: files.map { ($0.path, $0.bytes) })

        // --- manifest: dirs first, then files; digest over the same ordered list ---
        var wireEntries: [ProtocolClient.ManifestEntry] = []
        var digestEntries: [ManifestDigest.Entry] = []
        func add(path: String, type: String, size: Int64, mode: Int64) {
            wireEntries.append(ProtocolClient.ManifestEntry(
                path: path, type: type, size: size, mtimeUtcNs: mtime, mode: mode))
            digestEntries.append(ManifestDigest.Entry(
                path: path, type: type, size: size, mtimeUtcNs: mtime, mode: mode))
        }
        add(path: "docs", type: "dir", size: 0, mode: 493)
        for f in files {
            add(path: f.path, type: "file", size: Int64(f.bytes.count), mode: 420)
        }
        let digest = ManifestDigest.computeHex(digestEntries)
        XCTAssertEqual(wireEntries.count, digestEntries.count)

        // --- authenticate (TLS pin → pair → hello) ---
        let client = ProtocolClient(baseURL: baseURL, pinnedFingerprint: fingerprint)
        try await client.authenticate(pin: pin, deviceName: "cross-impl-test")

        // --- session + approval ---
        let summary = ProtocolClient.SessionSummaryBody(
            summary: .init(
                fileCount: files.count, dirCount: 1, symlinkCount: 0,
                totalBytes: Int64(files.reduce(0) { $0 + $1.bytes.count })),
            sourceDevice: .init(name: "mac-sender-test"))
        let sessionId = try await client.createSession(summary)
        let token = try await client.awaitApproval(sessionId, timeout: 30)

        // --- manifest in two batches; merge planned fileIds across responses (§2.7) ---
        let firstBatch = Array(wireEntries.prefix(2))
        let finalBatch = Array(wireEntries.dropFirst(2))
        let b0 = try await client.sendManifestBatch(
            sessionId: sessionId, batchIndex: 0, entries: firstBatch,
            final: false, sessionToken: token)
        XCTAssertTrue(b0.batchAccepted)
        XCTAssertEqual(b0.status, "MANIFEST_RECEIVING")
        XCTAssertEqual(b0.planned.count, firstBatch.count)

        let b1 = try await client.sendManifestBatch(
            sessionId: sessionId, batchIndex: 1, entries: finalBatch,
            final: true, manifestDigest: digest, sessionToken: token)
        XCTAssertEqual(b1.status, "PREFLIGHT_READY")
        XCTAssertEqual(b1.manifestDigest, digest)
        XCTAssertEqual(b1.totals?.files, Int64(files.count))
        XCTAssertEqual(b1.totals?.dirs, 1)
        XCTAssertEqual(b1.totals?.bytes, Int64(files.reduce(0) { $0 + $1.bytes.count }))
        XCTAssertEqual(b1.destination?.writable, true)
        XCTAssertEqual(b1.conflicts?.count, 0)
        XCTAssertEqual(b1.rejected?.count, 0)

        var fileIds: [String: String] = [:] // manifest path → fileId
        for planned in b0.planned + b1.planned where planned.action != "EXCLUDED_BY_POLICY" {
            if let id = planned.fileId { fileIds[planned.path] = id }
        }
        XCTAssertEqual(fileIds.count, files.count)

        // --- preflight state, then confirm ---
        let pre = try await client.state(sessionId: sessionId, sessionToken: token)
        XCTAssertEqual(pre.status, "PREFLIGHT_READY")
        XCTAssertNil(pre.cursor)

        let confirmed = try await client.confirm(sessionId: sessionId, sessionToken: token)
        XCTAssertEqual(confirmed.status, "TRANSFERRING")
        let chunkSize = confirmed.chunkSize
        XCTAssertGreaterThan(chunkSize, 0)

        // --- upload chunks + commit every file ---
        for f in files {
            let fileId = try XCTUnwrap(fileIds[f.path], "no fileId planned for \(f.path)")
            let chunkCount = f.bytes.isEmpty
                ? 0 : (f.bytes.count + chunkSize - 1) / chunkSize
            for index in 0..<chunkCount {
                let start = index * chunkSize
                let end = min(start + chunkSize, f.bytes.count)
                let slice = f.bytes.subdata(in: start..<end)
                let result = try await client.putChunk(
                    sessionId: sessionId, fileId: fileId, index: index, data: slice,
                    sha256Hex: ProtocolClient.sha256Hex(slice), sessionToken: token)
                XCTAssertEqual(result.status, "VERIFIED", "\(f.path)#\(index)")
            }
            let commit = try await client.commit(
                sessionId: sessionId, fileId: fileId,
                fileSha256: ProtocolClient.sha256Hex(f.bytes),
                size: Int64(f.bytes.count), mtimeUtcNs: f.mtimeUtcNs, sessionToken: token)
            XCTAssertTrue(
                ["VERIFIED", "RENAMED", "REPLACED"].contains(commit.outcome),
                "unexpected outcome \(commit.outcome) for \(f.path)")
        }

        // --- complete: final ledger (exactly one terminal outcome per item) ---
        let report = try await client.complete(sessionId: sessionId, sessionToken: token)
        XCTAssertEqual(report.status, "COMPLETED")
        let totals = report.totals
        XCTAssertEqual(totals.items, Int64(files.count + 1)) // + docs dir
        XCTAssertEqual(totals.verified, Int64(files.count + 1))
        XCTAssertEqual(totals.failed, 0)
        XCTAssertEqual(totals.changed, 0)
        XCTAssertEqual(totals.excluded, 0)
        XCTAssertEqual(totals.bytesVerified, Int64(files.reduce(0) { $0 + $1.bytes.count }))
        XCTAssertEqual(report.items.count, files.count + 1)

        for f in files {
            let item = try XCTUnwrap(report.items.first { $0.path == f.path })
            XCTAssertEqual(item.outcome, "VERIFIED", f.path)
            XCTAssertEqual(item.fileSha256, ProtocolClient.sha256Hex(f.bytes), f.path)
            XCTAssertEqual(item.size, Int64(f.bytes.count), f.path)
        }
        let dirItem = try XCTUnwrap(report.items.first { $0.path == "docs" })
        XCTAssertEqual(dirItem.outcome, "VERIFIED")

        // --- invariants: destination bytes, no partials, source untouched ---
        if let destination {
            let destRoot = URL(fileURLWithPath: destination)
            for f in files {
                let onDisk = try Data(contentsOf: destRoot.appendingPathComponent(f.path))
                XCTAssertEqual(onDisk, f.bytes, "destination bytes differ for \(f.path)")
            }
            let enumerator = FileManager.default.enumerator(
                at: destRoot, includingPropertiesForKeys: nil)
            while let item = enumerator?.nextObject() as? URL {
                XCTAssertFalse(
                    item.lastPathComponent.hasSuffix(".m2wpart"),
                    "partial file left at \(item.path)")
            }
        }
        for f in files {
            let reRead = try Data(contentsOf: sourceRoot.appendingPathComponent(f.path))
            XCTAssertEqual(reRead, originalBytes[f.path], "source changed: \(f.path)")
        }

        // report endpoint still serves the terminal ledger (§2.13)
        let fetched = try await client.report(sessionId: sessionId, sessionToken: token)
        XCTAssertEqual(fetched.totals.items, report.totals.items)
        XCTAssertEqual(fetched.status, report.status)
    }

    private static func env(_ name: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
            throw XCTSkip(
                "\(name) not set — cross-implementation receiver not running; " +
                "see the `cross-impl` job in .github/workflows/ci.yml")
        }
        return value
    }
}
