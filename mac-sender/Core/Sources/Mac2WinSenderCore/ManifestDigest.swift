import CryptoKit
import Foundation

/// Canonical manifest digest (protocol/PROTOCOL.md §2.7.1):
/// for each entry in batch order: UTF8(path) || 0x00 || ASCII(type) || 0x00 ||
/// ASCII(size) || 0x00 || ASCII(mtimeUtcNs) || 0x00 || ASCII(mode) || 0x0A,
/// then SHA-256, lowercase hex. Paths on the wire are NFC.
public enum ManifestDigest {
    public struct Entry: Equatable, Sendable {
        public let path: String
        public let type: String
        public let size: Int64
        public let mtimeUtcNs: String
        public let mode: Int64

        public init(path: String, type: String, size: Int64, mtimeUtcNs: String, mode: Int64) {
            self.path = path
            self.type = type
            self.size = size
            self.mtimeUtcNs = mtimeUtcNs
            self.mode = mode
        }
    }

    public static func canonicalBytes(_ entries: [Entry]) -> Data {
        var out = Data()
        func append0(_ s: String) {
            out.append(Data(s.utf8))
            out.append(0)
        }
        for e in entries {
            append0(e.path)
            append0(e.type)
            append0(String(e.size))
            append0(e.mtimeUtcNs)
            out.append(Data(String(e.mode).utf8))
            out.append(0x0A)
        }
        return out
    }

    public static func computeHex(_ entries: [Entry]) -> String {
        let digest = SHA256.hash(data: canonicalBytes(entries))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
