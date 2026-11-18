import Foundation
import Mac2WinSenderCore

/// Drives the Mac sender UI (SPEC §8 Mac sender screens). All network work happens on
/// async tasks; the view model is a MainActor class so SwiftUI bindings stay on the main
/// thread. The core client is UI-free and never touches the UI.
@MainActor
final class SenderViewModel: ObservableObject {
    enum Phase: Equatable {
        case disconnected
        case connecting
        case paired          // paired + hello'd, no session yet
        case awaitingApproval(sessionId: String)
        case transferring(SessionProgress)
        case completed(SessionReport)
        case error(String)
    }

    @Published var phase: Phase = .disconnected
    @Published var statusMessage = ""
    @Published var receiverName = ""
    @Published var receiverAddress = ""
    @Published var pin = ""

    private var client: ProtocolClient?
    private var deviceToken: String?
    private var sessionId: String?
    private var sessionToken: String?

    var isConnected: Bool {
        if case .paired = phase { return true }
        if case .awaitingApproval = phase { return true }
        if case .transferring = phase { return true }
        return false
    }

    func disconnect() {
        client = nil
        deviceToken = nil
        sessionId = nil
        sessionToken = nil
        phase = .disconnected
        statusMessage = ""
    }

    // MARK: - Connect (manual connection code, protocol §1.1)

    /// Parses `m2w://host:port?fp=...&pin=...`, pairs, and says hello.
    func connect(code: String) async {
        phase = .connecting
        statusMessage = "Connecting…"
        do {
            let info = try ConnectionCode.parse(code)
            let baseURL = URL(string: "https://\(info.host):\(info.port)")!
            let client = ProtocolClient(baseURL: baseURL, pinnedFingerprint: info.fingerprint)
            try await client.authenticate(pin: info.pin, deviceName: Host.current().localizedName ?? "Mac")
            self.client = client
            self.deviceToken = client.deviceToken
            self.receiverAddress = info.host
            self.pin = info.pin
            self.phase = .paired
            self.statusMessage = "Paired with \(info.host)"
        } catch {
            self.phase = .error(error.localizedDescription)
        }
    }

    // MARK: - Selection & transfer

    /// Starts a session for the given files (already selected by the UI).
    func startTransfer(files: [URL]) async {
        guard let client, let deviceToken else {
            phase = .error("Not paired"); return
        }
        let entries = files.map { url -> Mac2WinSenderCore.ManifestEntry in
            let attrs = (try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])) ?? URLResourceValues()
            let size = attrs.fileSize ?? 0
            let mtimeNs = String(Int64(attrs.contentModificationDate?.timeIntervalSince1970 ?? 0) * 1_000_000_000)
            return Mac2WinSenderCore.ManifestEntry(
                path: url.lastPathComponent, type: "file", size: Int64(size),
                mtimeUtcNs: mtimeNs, mode: 0o644)
        }
        let totalBytes = entries.reduce(0) { $0 + $1.size }
        let body = Mac2WinSenderCore.ProtocolClient.SessionSummaryBody(
            summary: .init(fileCount: Int64(entries.count), dirCount: 0, symlinkCount: 0,
                           totalBytes: totalBytes),
            sourceDevice: .init(name: Host.current().localizedName ?? "Mac")
        )
        do {
            let sid = try await client.createSession(body)
            self.sessionId = sid
            self.statusMessage = "Waiting for receiver approval…"
            self.phase = .awaitingApproval(sessionId: sid)
            let token = try await client.awaitApproval(sid)
            self.sessionToken = token
            await sendFiles(files: files, entries: entries, sessionId: sid, token: token)
        } catch {
            self.phase = .error(error.localizedDescription)
        }
    }

    private func sendFiles(files: [URL], entries: [Mac2WinSenderCore.ManifestEntry],
                           sessionId: String, token: String) async {
        guard let client else { return }
        do {
            // compute manifest digest over all entries
            let digest = ManifestDigest.computeHex(
                entries.map { Mac2WinSenderCore.ManifestDigest.Entry(
                    path: $0.path, type: $0.type, size: $0.size,
                    mtimeUtcNs: $0.mtimeUtcNs, mode: $0.mode)})
            let batchSize = Mac2WinSenderCore.ProtocolConstants.maxEntriesPerBatch
            var fileIds: [String: String] = [:]  // path -> fileId
            for b in stride(from: 0, to: entries.count, by: batchSize) {
                let batch = Array(entries[b..<min(b + batchSize, entries.count)])
                let isLast = b + batchSize >= entries.count
                let result = try await client.sendManifestBatch(
                    sessionId: sessionId, batchIndex: b / batchSize, entries: batch,
                    final: isLast, manifestDigest: isLast ? digest : nil, sessionToken: token)
                for p in result.planned {
                    if let fid = p.fileId { fileIds[p.path] = fid }
                }
                self.statusMessage = "Prepared \(min(b + batch.count, entries.count)) of \(entries.count) items"
            }
            // confirm (receiver resolves conflicts; we honor its echo)
            let confirm = try await client.confirm(sessionId: sessionId,
                resolutions: [:], sessionToken: token)
            var skipSet = Set<String>()
            if let resolutions = confirm.conflictResolutions {
                for (path, policy) in resolutions where policy == "SKIP" {
                    skipSet.insert(path)
                }
            }
            // upload each non-skipped file
            for (index, entry) in entries.enumerated() where !skipSet.contains(entry.path) {
                guard let fileId = fileIds[entry.path] else { continue }
                guard let url = files.first(where: { $0.lastPathComponent == entry.path }) else { continue }
                let data = try Data(contentsOf: url)
                let chunkSize = Int(confirm.chunkSize)
                let chunkCount = max(1, (data.count + chunkSize - 1) / chunkSize)
                for ci in 0..<chunkCount {
                    let offset = ci * chunkSize
                    let len = min(chunkSize, data.count - offset)
                    let chunk = data.subdata(in: offset..<offset + len)
                    let chunkHash = sha256Hex(chunk)
                    _ = try await client.putChunk(
                        sessionId: sessionId, fileId: fileId, index: ci, data: chunk,
                        sha256Hex: chunkHash, sessionToken: token)
                    let pct = Double(ci + 1) / Double(chunkCount) * 100
                    self.phase = .transferring(SessionProgress(
                        path: entry.path, bytesTotal: Int64(data.count),
                        bytesDone: Int64(min(offset + len, data.count)), percent: pct))
                }
                let fileHash = sha256Hex(data)
                _ = try await client.commit(
                    sessionId: sessionId, fileId: fileId, fileSha256: fileHash,
                    size: Int64(data.count), sessionToken: token)
            }
            let report = try await client.complete(sessionId: sessionId, sessionToken: token)
            self.phase = .completed(report)
            self.statusMessage = "Transfer complete"
        } catch {
            self.phase = .error(error.localizedDescription)
        }
    }

    private func sha256Hex(_ data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// Cancels the in-flight session.
    func cancel() async {
        guard let client, let sessionId, let sessionToken else { return }
        do {
            _ = try await client.cancel(sessionId: sessionId, sessionToken: sessionToken)
        } catch {
            // best effort
        }
        phase = .disconnected
    }
}

struct SessionProgress: Equatable {
    let path: String
    let bytesTotal: Int64
    let bytesDone: Int64
    let percent: Double
}
