import CryptoKit
import Foundation
import XCTest
@testable import Mac2WinSenderCore

/// Protocol conformance against the committed golden vectors (ADR-011).
/// AUTOMATED on macOS (CI: macos-latest). NOT RUN on Windows dev machines (ADR-010).
final class VectorTests: XCTestCase {

    /// repo root: .../mac-sender/Core/Tests/Mac2WinSenderCoreTests/VectorTests.swift → 5 levels up.
    static var vectorsDir: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Mac2WinSenderCoreTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // Core
            .deletingLastPathComponent()  // mac-sender
            .deletingLastPathComponent()  // repo root
            .appendingPathComponent("protocol/vectors")
    }

    private func loadJSON(_ name: String) throws -> [String: Any] {
        let url = Self.vectorsDir.appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - pairing

    func testPairingProofMatchesGoldenTranscript() throws {
        let json = try loadJSON("pairing_transcript.json")
        let pin = try XCTUnwrap(json["pin"] as? String)
        let fp = try XCTUnwrap(json["certFingerprintSha256"] as? String)
        let serverNonce = try XCTUnwrap(json["serverNonceB64"] as? String)
        let clientNonce = try XCTUnwrap(json["clientNonceB64"] as? String)
        let pubkey = try XCTUnwrap(json["devicePublicKeyB64"] as? String)
        let expectedKey = try XCTUnwrap(json["pinKeyHex"] as? String)
        let expectedProof = try XCTUnwrap(json["pinProofHex"] as? String)

        let pinKey = PairingProof.derivePinKey(pin: pin, certFingerprintHex: fp)
        XCTAssertEqual(expectedKey, PairingProof.hexString(Data(pinKey.withUnsafeBytes { Data($0) })))

        let proof = PairingProof.computeProof(
            pin: pin, certFingerprintHex: fp,
            clientNonceB64: clientNonce, serverNonceB64: serverNonce,
            devicePublicKeyB64: pubkey)
        XCTAssertEqual(expectedProof, PairingProof.hexString(proof))

        // negative: wrong PIN and tampered nonce must fail
        XCTAssertFalse(PairingProof.verify(
            pin: "000000", certFingerprintHex: fp,
            clientNonceB64: clientNonce, serverNonceB64: serverNonce,
            devicePublicKeyB64: pubkey, presentedProof: proof))
        XCTAssertFalse(PairingProof.verify(
            pin: pin, certFingerprintHex: fp,
            clientNonceB64: clientNonce, serverNonceB64: serverNonce + "x",
            devicePublicKeyB64: pubkey, presentedProof: proof))
    }

    func testDeviceAuthSignedMessageMatchesGoldenTranscript() throws {
        let json = try loadJSON("pairing_transcript.json")
        let auth = try XCTUnwrap(json["deviceAuth"] as? [String: Any])
        let expected = try XCTUnwrap(auth["signedMessageUtf8"] as? String)
        let clientNonce = try XCTUnwrap(json["clientNonceB64"] as? String)
        let serverNonce = try XCTUnwrap(json["serverNonceB64"] as? String)
        XCTAssertEqual(expected, "\(clientNonce)|\(serverNonce)")
    }

    // MARK: - manifest

    func testManifestDigestMatchesGoldenVector() throws {
        let json = try loadJSON("manifest_digest.json")
        let rawEntries = try XCTUnwrap(json["entries"] as? [[String: Any]])
        let entries: [ManifestDigest.Entry] = try rawEntries.map { e in
            ManifestDigest.Entry(
                path: try XCTUnwrap(e["path"] as? String),
                type: try XCTUnwrap(e["type"] as? String),
                size: try XCTUnwrap(e["size"] as? Int64),
                mtimeUtcNs: try XCTUnwrap(e["mtimeUtcNs"] as? String),
                mode: try XCTUnwrap(e["mode"] as? Int64))
        }
        let expectedBytesHex = try XCTUnwrap(json["canonicalBytesHex"] as? String)
        let expectedDigest = try XCTUnwrap(json["manifestDigest"] as? String)

        let bytes = ManifestDigest.canonicalBytes(entries)
        XCTAssertEqual(expectedBytesHex, bytes.map { String(format: "%02x", $0) }.joined())
        XCTAssertEqual(expectedDigest, ManifestDigest.computeHex(entries))
    }

    // MARK: - chunk hashing

    func testChunkHashesMatchDeterministicRecipe() throws {
        let json = try loadJSON("chunk_hashes.json")
        let seed = Data(try XCTUnwrap(json["seed"] as? String).utf8)

        for c in try XCTUnwrap(json["cases"] as? [[String: Any]]) {
            let size = try XCTUnwrap(c["size"] as? Int)
            let expected = try XCTUnwrap(c["sha256"] as? String)
            let data = Self.genBytes(seed: seed, n: size)
            XCTAssertEqual(size, data.count)
            XCTAssertEqual(expected, Self.sha256Hex(data))
        }

        let helloHex = try XCTUnwrap((try XCTUnwrap(json["hello"] as? [String: Any]))["bytesHex"] as? String)
        let hello = try XCTUnwrap(Data(hexString: helloHex))
        let helloSha = try XCTUnwrap((try XCTUnwrap(json["hello"] as? [String: Any]))["sha256"] as? String)
        XCTAssertEqual(helloSha, Self.sha256Hex(hello))

        let emptySha = try XCTUnwrap(json["emptyFileSha256"] as? String)
        XCTAssertEqual(emptySha, Self.sha256Hex(Data()))
    }

    func testChunkBoundariesMathMatchesVector() throws {
        let json = try loadJSON("chunk_hashes.json")
        let cb = try XCTUnwrap(json["chunkBoundaries"] as? [String: Any])
        let chunkSize = try XCTUnwrap(cb["chunkSize"] as? Int64)
        let fileSize = try XCTUnwrap(cb["fileSize"] as? Int64)
        let expectedCount = try XCTUnwrap(cb["expectedChunkCount"] as? Int)
        let expectedSizes = try XCTUnwrap(cb["chunkSizes"] as? [Int64])

        let count = fileSize == 0 ? 0 : Int((fileSize + chunkSize - 1) / chunkSize)
        XCTAssertEqual(expectedCount, count)
        let sizes = (0..<count).map { i in min(chunkSize, fileSize - Int64(i) * chunkSize) }
        XCTAssertEqual(expectedSizes, sizes)
    }

    // MARK: - helpers (deterministic data recipe, must match tools/gen_vectors.py)

    static func genBytes(seed: Data, n: Int) -> Data {
        var out = Data()
        var counter: UInt64 = 0
        while out.count < n {
            var hasher = SHA256()
            hasher.update(data: seed)
            var be = counter.bigEndian
            withUnsafeBytes(of: &be) { hasher.update(data: Data($0)) }
            out.append(Data(hasher.finalize()))
            counter += 1
        }
        if out.count > n {
            out = Data(out.prefix(n))
        }
        return out
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data()
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
