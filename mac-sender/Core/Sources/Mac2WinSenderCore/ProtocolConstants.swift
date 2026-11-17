/// Protocol-wide constants (protocol/PROTOCOL.md, protocol/VERSION).
/// Must stay in sync with win-receiver/Core/ProtocolConstants.cs — both are pinned
/// by the golden vectors and the version-handshake test.
public enum ProtocolConstants {
    public static let protocolVersion = 1
    public static let defaultPort = 48600
    public static let serviceType = "_mac2win._tcp"
    public static let pathPrefix = "/v1"

    public static let maxEntriesPerBatch = 1000
    public static let maxBatchJsonBytes = 1024 * 1024

    public static let minChunkSize = 1 * 1024 * 1024
    public static let maxChunkSize = 64 * 1024 * 1024
    public static let defaultChunkSize = 4 * 1024 * 1024

    public static let pinMinDigits = 6
    public static let pinMaxAgeSeconds = 300
    public static let pinMaxFailedAttempts = 5
}
