import CryptoKit
import Foundation
import Security

/// Wire-level error returned by the receiver (protocol/PROTOCOL.md §5).
public struct ProtocolWireError: Error, CustomStringConvertible, Equatable {
    public let code: String
    public let message: String
    public let retryable: Bool
    public let httpStatus: Int

    public var description: String {
        "E[\(code)] http=\(httpStatus) retryable=\(retryable): \(message)"
    }
}

/// Transport-level failure (TLS pin mismatch, no route, timeout).
public struct TransportError: Error, CustomStringConvertible {
    public let reason: String
    public let underlying: Error?

    public init(_ reason: String, _ underlying: Error? = nil) {
        self.reason = reason
        self.underlying = underlying
    }

    public var description: String { "transport: \(reason)" }
}

/// A decoded 2xx response.
public struct WireResponse<Value> {
    public let status: Int
    public let value: Value
}

/// The Mac sender's protocol client (SPEC §3: UI depends on core, never the reverse).
///
/// * TLS: the server certificate is **pinned** to a SHA-256 fingerprint supplied
///   out-of-band (QR / manual connection code). There is deliberately no
///   "accept any certificate" path anywhere, including debug builds (SPEC §7).
/// * Pairing: HKDF/HMAC PIN proof per protocol §2.3 (`PairingProof`).
/// * Chunks: raw `PUT` with `X-Chunk-Sha256`; bodies are chunk-sized `Data`
///   objects, so memory use depends on chunk size × concurrency, never on file size.
public final class ProtocolClient: NSObject, URLSessionDelegate {

    public let baseURL: URL
    public let pinnedFingerprint: String

    private let session: URLSession
    private var deviceKey: P256.Signing.PrivateKey?
    public private(set) var deviceId: String?
    public private(set) var deviceToken: String?

    // nonisolated(unsafe): JSONEncoder/Decoder are allocation-cheap and only used inside
    // synchronous encode/decode calls — no shared mutable state escapes (Swift 6 mode).
    nonisolated(unsafe) public static let json: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }()

    nonisolated(unsafe) public static let jsonDecoder = JSONDecoder()

    public init(baseURL: URL, pinnedFingerprint: String, timeout: TimeInterval = 60) {
        self.baseURL = baseURL
        self.pinnedFingerprint = pinnedFingerprint.lowercased()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 10
        // never fall back to a shared cookie/credential store (local-only operation)
        config.httpCookieStorage = nil
        config.urlCache = nil
        self.session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        super.init()
    }

    deinit {
        session.invalidateAndCancel()
    }

    // MARK: - TLS pinning (SPEC §7: no accept-all path)

    public func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // Extract the leaf WITHOUT requiring PKI validation: the receiver's certificate is
        // self-signed (ADR-007), so SecTrustEvaluateWithError would fail on the untrusted
        // root — trust here comes solely from the pinned fingerprint (SPEC §7).
        var leaf: SecCertificate?
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            leaf = chain.first
        }
        if leaf == nil, SecTrustGetCertificateCount(trust) > 0 {
            // SecTrustCopyCertificateChain may need an evaluated trust; fall back to the
            // (deprecated but supported) accessor for the input certificates.
            leaf = SecTrustGetCertificateAtIndex(trust, 0)
        }
        guard let leaf else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        // SHA-256 over the leaf certificate's DER (protocol §2.1)
        let actual = Self.sha256Hex(Data(referencing: SecCertificateCopyData(leaf) as NSData))
        if actual == pinnedFingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            // fingerprint mismatch ⇒ MITM or wrong receiver: never proceed
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - request plumbing

    private struct ErrorBody: Decodable {
        struct Inner: Decodable {
            let code: String
            let message: String
            let retryable: Bool
        }
        let error: Inner
    }

    /// Encodes as `{}` — for endpoints whose request body is ignored (protocol §2.2/§2.4).
    public struct EmptyValue: Codable {
        public init() {}
    }

    private static func wireError(status: Int, _ data: Data) -> ProtocolWireError {
        if let decoded = try? jsonDecoder.decode(ErrorBody.self, from: data) {
            return ProtocolWireError(
                code: decoded.error.code, message: decoded.error.message,
                retryable: decoded.error.retryable, httpStatus: status)
        }
        return ProtocolWireError(
            code: "E_BAD_REQUEST", message: "non-JSON error body (http \(status))",
            retryable: status >= 500, httpStatus: status)
    }

    /// `appendingPathComponent` percent-encodes `?`, so an optional query string is split
    /// off and reattached through URLComponents (used by `state?cursor=`).
    private static func makeURL(base: URL, path: String) -> URL {
        if let idx = path.firstIndex(of: "?") {
            let bare = String(path[..<idx])
            let query = String(path[path.index(after: idx)...])
            if var components = URLComponents(
                url: base.appendingPathComponent(bare), resolvingAgainstBaseURL: false) {
                components.query = query // set decoded; URLComponents percent-encodes
                if let url = components.url { return url }
            }
        }
        return base.appendingPathComponent(path)
    }

    private func send(
        _ method: String, _ path: String, body: Data?, bearer: String?
    ) async throws -> (Int, Data) {
        var request = URLRequest(url: Self.makeURL(base: baseURL, path: path))
        request.httpMethod = method
        if let body {
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        if let bearer {
            request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw TransportError("request \(method) \(path) failed", error)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw Self.wireError(status: status, data)
        }
        return (status, data)
    }

    /// Request with no JSON body (GET, and POSTs whose body the receiver ignores).
    private func request<Value: Decodable>(
        _ method: String, _ path: String, bearer: String? = nil, as: Value.Type = Value.self
    ) async throws -> WireResponse<Value> {
        let (status, data) = try await send(method, path, body: nil, bearer: bearer)
        return try Self.decode(status, data)
    }

    private func request<Value: Decodable, Body: Encodable>(
        _ method: String, _ path: String, body: Body, bearer: String? = nil,
        as: Value.Type = Value.self
    ) async throws -> WireResponse<Value> {
        let encoded = try Self.json.encode(body)
        let (status, data) = try await send(method, path, body: encoded, bearer: bearer)
        return try Self.decode(status, data)
    }

    private static func decode<Value: Decodable>(_ status: Int, _ data: Data) throws -> WireResponse<Value> {
        let value: Value
        if Value.self == EmptyValue.self, data.isEmpty {
            value = EmptyValue() as! Value
        } else {
            value = try jsonDecoder.decode(Value.self, from: data)
        }
        return WireResponse(status: status, value: value)
    }

    // MARK: - crypto helpers

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// CSPRNG nonce, base64 (protocol §2.2/§2.3). Never falls back to weak randomness.
    public static func randomNonceB64(byteCount: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed (\(status))")
        return Data(bytes).base64EncodedString()
    }

    // MARK: - anonymous endpoints

    public struct Health: Decodable {
        public let service: String
        public let protocolVersion: Int
        public let deviceName: String
        public let certFingerprintSha256: String
        public let serverNonce: String
    }

    public struct Challenge: Decodable {
        public let serverNonce: String
    }

    public func health() async throws -> Health {
        try await request("GET", "v1/health").value
    }

    /// Verifies the pinned fingerprint against the live channel before any credential is used.
    public func verifyChannel() async throws -> Health {
        let h = try await health()
        guard h.certFingerprintSha256.lowercased() == pinnedFingerprint else {
            throw TransportError("certificate fingerprint mismatch")
        }
        guard h.protocolVersion == ProtocolConstants.protocolVersion else {
            throw ProtocolWireError(
                code: "E_UNSUPPORTED_VERSION",
                message: "receiver speaks v\(h.protocolVersion), sender speaks v\(ProtocolConstants.protocolVersion)",
                retryable: false, httpStatus: 400)
        }
        return h
    }

    // MARK: - pairing (protocol §2.3 / §2.4)

    public struct PairResult: Decodable {
        public let deviceId: String
    }

    public struct HelloResult: Decodable {
        public let deviceToken: String
        public let expiresIn: Int
    }

    private struct PairRequest: Encodable {
        let protocolVersion: Int
        let deviceName: String
        let devicePublicKey: String
        let clientNonce: String
        let serverNonce: String
        let pinProof: String
    }

    private struct HelloRequest: Encodable {
        let deviceId: String
        let deviceName: String
        let clientNonce: String
        let serverNonce: String
        let signature: String
    }

    public func pair(pin: String, deviceName: String) async throws -> String {
        let challenge: Challenge = try await request("POST", "v1/auth/challenge", body: EmptyValue()).value
        let key = P256.Signing.PrivateKey()
        deviceKey = key
        // The receiver imports this with ECDsa.ImportSubjectPublicKeyInfo: SPKI DER, not X9.63
        let pubkeyB64 = key.publicKey.derRepresentation.base64EncodedString()
        let clientNonce = Self.randomNonceB64()
        let proof = PairingProof.computeProof(
            pin: pin, certFingerprintHex: pinnedFingerprint,
            clientNonceB64: clientNonce, serverNonceB64: challenge.serverNonce,
            devicePublicKeyB64: pubkeyB64)
        let body = PairRequest(
            protocolVersion: ProtocolConstants.protocolVersion,
            deviceName: deviceName,
            devicePublicKey: pubkeyB64,
            clientNonce: clientNonce,
            serverNonce: challenge.serverNonce,
            pinProof: proof.base64EncodedString())
        let result: PairResult = try await request("POST", "v1/pair", body: body).value
        deviceId = result.deviceId
        return result.deviceId
    }

    public func hello() async throws -> String {
        guard let key = deviceKey, let deviceId else {
            throw TransportError("hello() before pair()")
        }
        let challenge: Challenge = try await request("POST", "v1/auth/challenge", body: EmptyValue()).value
        let clientNonce = Self.randomNonceB64()
        let message = Data("\(clientNonce)|\(challenge.serverNonce)".utf8)
        let signature = try key.signature(for: message)
        let body = HelloRequest(
            deviceId: deviceId,
            deviceName: ProcessInfo.processInfo.hostName,
            clientNonce: clientNonce,
            serverNonce: challenge.serverNonce,
            signature: signature.rawRepresentation.base64EncodedString())
        let result: HelloResult = try await request("POST", "v1/auth/hello", body: body).value
        deviceToken = result.deviceToken
        return result.deviceToken
    }

    /// Full anonymous→paired→authenticated bootstrap used by the cross-impl test.
    public func authenticate(pin: String, deviceName: String = "mac-sender-test") async throws {
        _ = try await verifyChannel()
        _ = try await pair(pin: pin, deviceName: deviceName)
        _ = try await hello()
    }

    // MARK: - sessions

    public struct SessionSummaryBody: Encodable {
        public struct Summary: Encodable {
            public let fileCount: Int
            public let dirCount: Int
            public let symlinkCount: Int
            public let totalBytes: Int64
            public init(fileCount: Int, dirCount: Int, symlinkCount: Int, totalBytes: Int64) {
                self.fileCount = fileCount
                self.dirCount = dirCount
                self.symlinkCount = symlinkCount
                self.totalBytes = totalBytes
            }
        }
        public struct Source: Encodable {
            public let name: String
            public init(name: String) { self.name = name }
        }
        public let summary: Summary
        public let sourceDevice: Source

        public init(summary: Summary, sourceDevice: Source) {
            self.summary = summary
            self.sourceDevice = sourceDevice
        }
    }

    public struct CreateSessionResult: Decodable {
        public let sessionId: String
        public let status: String
    }

    public struct SessionStatusResult: Decodable {
        public let sessionId: String
        public let status: String
        public let sessionToken: String?
    }

    public func createSession(_ body: SessionSummaryBody) async throws -> String {
        let result: CreateSessionResult = try await request(
            "POST", "v1/sessions", body: body, bearer: deviceToken).value
        guard result.status == "AWAITING_APPROVAL" else {
            throw ProtocolWireError(
                code: "E_SESSION_STATE", message: "unexpected \(result.status)",
                retryable: false, httpStatus: 409)
        }
        return result.sessionId
    }

    public func sessionStatus(_ sessionId: String) async throws -> SessionStatusResult {
        try await request("GET", "v1/sessions/\(sessionId)", bearer: deviceToken).value
    }

    /// Polls until the receiver's approval dialog grants a session token (SPEC §4).
    public func awaitApproval(
        _ sessionId: String, timeout: TimeInterval = 30, pollInterval: TimeInterval = 0.25
    ) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let status = try await sessionStatus(sessionId)
            if status.status == "MANIFEST_RECEIVING", let token = status.sessionToken {
                return token
            }
            if status.status == "DENIED" || status.status == "EXPIRED" {
                throw ProtocolWireError(
                    code: "E_APPROVAL_DENIED", message: "session \(status.status)",
                    retryable: false, httpStatus: 403)
            }
            try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
        }
        throw TransportError("approval timed out")
    }

    // MARK: - manifest (protocol §2.7)

    public struct ManifestEntry: Encodable {
        public let path: String
        public let type: String
        public let size: Int64
        public let mtimeUtcNs: String
        public let mode: Int64
        public let ctimeUtcNs: String?
        public let symlinkTarget: String?
        public let senderState: String?

        public init(
            path: String, type: String, size: Int64, mtimeUtcNs: String, mode: Int64,
            ctimeUtcNs: String? = nil, symlinkTarget: String? = nil, senderState: String? = nil
        ) {
            self.path = path
            self.type = type
            self.size = size
            self.mtimeUtcNs = mtimeUtcNs
            self.mode = mode
            self.ctimeUtcNs = ctimeUtcNs
            self.symlinkTarget = symlinkTarget
            self.senderState = senderState
        }
    }

    public struct PlannedFile: Decodable {
        public let path: String
        public let fileId: String?
        public let action: String
        public let finalPath: String?
        public let reason: String?
    }

    public struct PreflightTotals: Decodable {
        public let files: Int64
        public let dirs: Int64
        public let symlinks: Int64
        public let bytes: Int64
    }

    public struct DestinationInfo: Decodable {
        public let path: String
        public let freeBytes: Int64
        public let fileSystem: String
        public let writable: Bool
        public let longPathsEnabled: Bool
    }

    public struct ConflictInfo: Decodable {
        public let path: String
        public let existingSize: Int64?
        public let existingMtimeUtcNs: String?
    }

    public struct RenameInfo: Decodable {
        public let path: String
        public let finalPath: String
        public let reason: String?
    }

    public struct ExclusionInfo: Decodable {
        public let path: String
        public let reason: String?
    }

    /// Per-batch response; the preflight block is present only on the final batch.
    public struct ManifestBatchResult: Decodable {
        public let status: String
        public let planned: [PlannedFile]
        public let batchAccepted: Bool
        public let manifestDigest: String?
        public let totals: PreflightTotals?
        public let conflicts: [ConflictInfo]?
        public let renames: [RenameInfo]?
        public let excluded: [ExclusionInfo]?
        public let rejected: [ExclusionInfo]?
        public let destination: DestinationInfo?
    }

    private struct ManifestRequest: Encodable {
        let batchIndex: Int
        let `final`: Bool
        let manifestDigest: String?
        let entries: [ManifestEntry]
    }

    /// Uploads one manifest batch. `manifestDigest` is required on the final batch (§2.7.1).
    /// NOTE: each response carries only its own `planned` list — merge fileId mappings
    /// across batches on the sender side.
    public func sendManifestBatch(
        sessionId: String, batchIndex: Int, entries: [ManifestEntry],
        final: Bool, manifestDigest: String? = nil, sessionToken: String
    ) async throws -> ManifestBatchResult {
        let body = ManifestRequest(
            batchIndex: batchIndex, final: final,
            manifestDigest: final ? manifestDigest : nil, entries: entries)
        return try await request(
            "POST", "v1/sessions/\(sessionId)/manifest",
            body: body, bearer: sessionToken).value
    }

    // MARK: - confirm (protocol §2.8)

    public struct ConfirmResult: Decodable {
        public let status: String
        public let chunkSize: Int
        /// Effective per-path resolutions the receiver applied (protocol §2.8), merged
        /// with the receiver's default conflict policy. Files resolved as SKIP MUST NOT
        /// be uploaded. Optional: receivers predating the echo omit it.
        public let conflictResolutions: [String: String]?
    }

    private struct ConfirmRequest: Encodable {
        let conflictResolutions: [String: String]?
        let applyToAllDefault: String?
    }

    public func confirm(
        sessionId: String, resolutions: [String: String] = [:],
        applyToAllDefault: String? = nil, sessionToken: String
    ) async throws -> ConfirmResult {
        let body = ConfirmRequest(
            conflictResolutions: resolutions.isEmpty ? nil : resolutions,
            applyToAllDefault: applyToAllDefault)
        return try await request(
            "POST", "v1/sessions/\(sessionId)/confirm",
            body: body, bearer: sessionToken).value
    }

    // MARK: - state / resume (protocol §2.9)

    public struct CompletedFile: Decodable {
        public let path: String
        public let fileSha256: String
    }

    public struct PartialFile: Decodable {
        public let path: String
        public let fileId: String
        public let verifiedChunks: [Int]
        public let nextChunk: Int
    }

    public struct SessionState: Decodable {
        public let status: String
        public let manifestDigest: String?
        public let chunkSize: Int
        public let completed: [CompletedFile]
        public let partial: [PartialFile]
        public let cursor: String?
    }

    public func state(
        sessionId: String, cursor: String? = nil, sessionToken: String
    ) async throws -> SessionState {
        var path = "v1/sessions/\(sessionId)/state"
        if let cursor, !cursor.isEmpty {
            path += "?cursor=\(cursor)" // makeURL attaches it via URLComponents
        }
        return try await request("GET", path, bearer: sessionToken).value
    }

    // MARK: - chunks (protocol §2.10)

    public struct ChunkResult: Decodable {
        public let status: String
        public let bytesStored: Int64
    }

    /// Raw-body chunk upload with `X-Chunk-Sha256` (§2.10). The receiver recomputes the
    /// hash and answers `E_CHUNK_HASH_MISMATCH` without persisting anything on mismatch.
    public func putChunk(
        sessionId: String, fileId: String, index: Int, data: Data,
        sha256Hex chunkShaHex: String, sessionToken: String
    ) async throws -> ChunkResult {
        var request = URLRequest(url: baseURL.appendingPathComponent(
            "v1/sessions/\(sessionId)/files/\(fileId)/chunks/\(index)"))
        request.httpMethod = "PUT"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue(chunkShaHex, forHTTPHeaderField: "X-Chunk-Sha256")
        request.setValue("Bearer \(sessionToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = data
        let (body, response): (Data, URLResponse)
        do {
            (body, response) = try await session.data(for: request)
        } catch {
            throw TransportError("chunk PUT \(fileId)#\(index) failed", error)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw Self.wireError(status: status, body)
        }
        return try Self.jsonDecoder.decode(ChunkResult.self, from: body)
    }

    // MARK: - commit (protocol §2.11)

    public struct CommitResult: Decodable {
        public let outcome: String
        public let finalPath: String
    }

    private struct CommitRequest: Encodable {
        let fileSha256: String
        let size: Int64
        let mtimeUtcNs: String?
        let ctimeUtcNs: String?
    }

    /// Whole-file verify-after-write: the receiver flushes the staged `.m2wpart`,
    /// re-hashes it and only then renames into the final path (§2.11).
    public func commit(
        sessionId: String, fileId: String, fileSha256: String, size: Int64,
        mtimeUtcNs: String? = nil, ctimeUtcNs: String? = nil, sessionToken: String
    ) async throws -> CommitResult {
        let body = CommitRequest(
            fileSha256: fileSha256, size: size,
            mtimeUtcNs: mtimeUtcNs, ctimeUtcNs: ctimeUtcNs)
        return try await request(
            "POST", "v1/sessions/\(sessionId)/files/\(fileId)/commit",
            body: body, bearer: sessionToken).value
    }

    // MARK: - controls and report (protocol §2.12/§2.13)

    public struct StatusResult: Decodable {
        public let status: String
    }

    public struct ReportTotals: Decodable {
        public let items: Int64
        public let verified: Int64
        public let renamed: Int64
        public let replaced: Int64
        public let skipped: Int64
        public let excluded: Int64
        public let unreadable: Int64
        public let cloudPlaceholder: Int64
        public let changed: Int64
        public let failed: Int64
        public let bytesVerified: Int64
    }

    public struct ReportItem: Decodable {
        public let path: String
        public let finalPath: String?
        public let outcome: String
        public let size: Int64
        public let fileSha256: String?
        public let reason: String?
        public let errorCode: String?
    }

    public struct SessionReport: Decodable {
        public let sessionId: String
        public let status: String
        public let startedAt: String
        public let finishedAt: String
        public let totals: ReportTotals
        public let items: [ReportItem]
    }

    public struct CancelResult: Decodable {
        public let status: String
        public let report: SessionReport
    }

    public func pause(sessionId: String, sessionToken: String) async throws -> String {
        let result: StatusResult = try await request(
            "POST", "v1/sessions/\(sessionId)/pause", bearer: sessionToken).value
        return result.status
    }

    public func resume(sessionId: String, sessionToken: String) async throws -> String {
        let result: StatusResult = try await request(
            "POST", "v1/sessions/\(sessionId)/resume", bearer: sessionToken).value
        return result.status
    }

    public func cancel(sessionId: String, sessionToken: String) async throws -> SessionReport {
        let result: CancelResult = try await request(
            "POST", "v1/sessions/\(sessionId)/cancel", bearer: sessionToken).value
        return result.report
    }

    public func report(sessionId: String, sessionToken: String) async throws -> SessionReport {
        try await request("GET", "v1/sessions/\(sessionId)/report", bearer: sessionToken).value
    }

    /// Marks the session completed; returns the final ledger (exactly one outcome per item).
    public func complete(sessionId: String, sessionToken: String) async throws -> SessionReport {
        try await request("POST", "v1/sessions/\(sessionId)/complete", bearer: sessionToken).value
    }
}
