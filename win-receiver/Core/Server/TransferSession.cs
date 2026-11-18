using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mac2WinReceiver.Core.Server;

public enum SessionStatus
{
    AwaitingApproval,
    ManifestReceiving,
    PreflightReady,
    Transferring,
    Paused,
    Completed,
    Failed,
    Cancelled,
    Denied,
    Expired,
}

/// <summary>Summary shown in the receiver's approval dialog (SPEC §4).</summary>
public sealed record SessionSummary(
    string SessionId, string SourceDeviceName, long FileCount, long DirCount,
    long SymlinkCount, long TotalBytes, string RemoteIp);

/// <summary>One manifest entry and its ledger state (SPEC §5: exactly one terminal outcome).</summary>
public sealed class ManifestItem
{
    public required string Path { get; init; }          // NFC, relative, '/'-separated (wire form)
    public required string Type { get; init; }          // file | dir | symlink
    public long Size { get; init; }
    public required string MtimeUtcNs { get; init; }
    public string? CtimeUtcNs { get; init; }
    public long Mode { get; init; }
    public string? SymlinkTarget { get; init; }
    public string? SenderState { get; init; }           // UNREADABLE | CLOUD_PLACEHOLDER (sender-detected)

    public string? FileId { get; set; }                 // assigned for transferring files
    public string Action { get; set; } = "CREATE";      // CREATE|RENAME|CONFLICT|EXCLUDED_BY_POLICY|REJECTED
    public string? FinalRelativePath { get; set; }      // destination-relative, '/'-separated
    public string? PlanReason { get; set; }
    public bool OverwriteAllowed { get; set; }

    // transfer progress
    public SortedSet<int> VerifiedChunks { get; } = new();
    public Dictionary<int, string> ChunkHashes { get; } = new();
    public IncrementalHash? StreamingHash { get; set; } // whole-file hash while writing (verify-after-write OFF)
    public long BytesReceived { get; set; }
    public bool Committed { get; set; }
    public string? FileSha256 { get; set; }

    // ledger (terminal once set to a non-"PENDING" value)
    public string Outcome { get; set; } = "PENDING";
    public string? OutcomeReason { get; set; }
    public string? OutcomeErrorCode { get; set; }

    public bool IsTerminal => Outcome != "PENDING";
}

/// <summary>
/// One transfer session: manifest planning, chunk intake with per-chunk SHA-256,
/// atomic verified commit, per-item ledger, resume state (protocol §2, SPEC §5).
/// All public operations are thread-safe; IO (body reads) happens outside the lock.
/// </summary>
public sealed class TransferSession : IDisposable
{
    public const int StatePageSize = 500;

    private readonly ReceiverOptions _options;
    private readonly IDestinationInfo _destination;
    private readonly object _gate = new();
    private readonly Dictionary<string, ManifestItem> _byFileId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _reparseCheckCache = new(StringComparer.Ordinal);

    public string Id { get; }
    /// <summary>Device that created this session (only it may poll/drive it).</summary>
    public string OwnerDeviceId { get; set; } = "";
    public SessionSummary Summary { get; }
    public SessionStatus Status { get; private set; } = SessionStatus.AwaitingApproval;
    public string? SessionToken { get; set; }
    public DateTimeOffset CreatedAt { get; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ApprovedAt { get; private set; }
    public int ChunkSize { get; }
    public string StagingDir { get; }
    public Journal Journal { get; }
    public List<ManifestItem> Items { get; } = new();
    public int BatchesReceived { get; private set; }
    public string? ManifestDigestHex { get; private set; }
    public Dictionary<string, string> ConflictResolutions { get; } = new(StringComparer.Ordinal);
    /// <summary>Index into <see cref="Items"/> where the last accepted manifest batch started.</summary>
    public int LastBatchItemStart { get; private set; } = -1;
    /// <summary>Whether the last accepted manifest batch was the final one.</summary>
    public bool LastBatchFinal { get; private set; }

    private long _plannedFileBytes; // bytes of files that will actually transfer
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow; // idle clock (post-approval)

    public TransferSession(ReceiverOptions options, IDestinationInfo destination, SessionSummary summary)
    {
        _options = options;
        _destination = destination;
        Summary = summary;
        Id = Guid.NewGuid().ToString();
        ChunkSize = options.ChunkSize;
        StagingDir = Path.Combine(
            options.StagingRoot ?? Path.Combine(options.DestinationRoot, ".mac2win-staging"),
            Id);
        Directory.CreateDirectory(StagingDir);
        Journal = new Journal(Path.Combine(StagingDir, "journal.log"));
    }

    /// <summary>Recovery constructor: rebuilds in-memory state from a persisted snapshot.</summary>
    private TransferSession(ReceiverOptions options, IDestinationInfo destination, SessionSnapshot snap)
    {
        _options = options;
        _destination = destination;
        Id = snap.SessionId;
        Summary = new SessionSummary(snap.SessionId, snap.SourceDeviceName, snap.FileCount,
            snap.DirCount, snap.SymlinkCount, snap.TotalBytes, snap.RemoteIp);
        ChunkSize = snap.ChunkSize > 0 ? snap.ChunkSize : options.ChunkSize;
        StagingDir = Path.Combine(
            options.StagingRoot ?? Path.Combine(options.DestinationRoot, ".mac2win-staging"),
            Id);
        Status = Enum.TryParse<SessionStatus>(snap.Status, out var status)
            ? status : SessionStatus.Failed;
        SessionToken = snap.SessionToken;
        CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(snap.CreatedAtMs);
        ApprovedAt = snap.ApprovedAtMs is { } approved
            ? DateTimeOffset.FromUnixTimeMilliseconds(approved) : null;
        _lastActivity = snap.LastActivityMs > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(snap.LastActivityMs)
            : DateTimeOffset.UtcNow;
        OwnerDeviceId = snap.OwnerDeviceId;
        BatchesReceived = snap.BatchesReceived;
        ManifestDigestHex = snap.ManifestDigest;
        _plannedFileBytes = snap.PlannedFileBytes;
        LastBatchItemStart = snap.LastBatchItemStart;
        LastBatchFinal = snap.LastBatchFinal;
        foreach (var kv in snap.ConflictResolutions)
            ConflictResolutions[kv.Key] = kv.Value;

        foreach (var i in snap.Items)
        {
            var item = new ManifestItem
            {
                Path = i.Path, Type = i.Type, Size = i.Size, MtimeUtcNs = i.MtimeUtcNs,
                CtimeUtcNs = i.CtimeUtcNs, Mode = i.Mode, SymlinkTarget = i.SymlinkTarget,
                SenderState = i.SenderState, FileId = i.FileId, Action = i.Action,
                FinalRelativePath = i.FinalRelativePath, PlanReason = i.PlanReason,
                OverwriteAllowed = i.OverwriteAllowed, Committed = i.Committed,
                FileSha256 = i.FileSha256, Outcome = i.Outcome, OutcomeReason = i.OutcomeReason,
                OutcomeErrorCode = i.OutcomeErrorCode,
            };
            Items.Add(item);
            if (item.FileId is not null) _byFileId[item.FileId] = item;
        }

        // terminal sessions whose staging was purged record nothing further; anything else
        // (or a staging directory that still exists) keeps its write-ahead journal
        var terminal = Status is SessionStatus.Completed or SessionStatus.Failed
            or SessionStatus.Cancelled or SessionStatus.Denied or SessionStatus.Expired;
        Journal = !terminal || Directory.Exists(StagingDir)
            ? new Journal(Path.Combine(StagingDir, "journal.log"))
            : Journal.Detached();
    }

    /// <summary>
    /// Rebuilds a session after a receiver restart (M3 crash consistency, SPEC §5): merges
    /// the persisted snapshot with the write-ahead journal and reconciles crash windows —
    /// commit intents whose rename did not finish are completed (or failed) and chunk
    /// records are re-validated so unjournaled bytes are never trusted.
    /// </summary>
    public static TransferSession Recover(ReceiverOptions options, IDestinationInfo destination,
        SessionSnapshot snap)
    {
        var session = new TransferSession(options, destination, snap);
        session.ReplayJournal();
        return session;
    }

    private void ReplayJournal()
    {
        JournalSnapshot snap;
        try
        {
            snap = Journal.Replay(Path.Combine(StagingDir, "journal.log"));
        }
        catch (IOException)
        {
            return; // unreadable journal: keep the snapshot state; sender resumes from there
        }

        lock (_gate)
        {
            // 1. FILE records are write-ahead intents for the atomic rename: finish or fail them
            foreach (var (fileId, sha, relPath) in snap.Files)
                ReconcileCommitIntentLocked(fileId, sha, relPath);

            // 2. CHUNK records: trust only bytes that are actually on disk, re-hashing the boundary
            foreach (var group in snap.Chunks.GroupBy(c => c.FileId, StringComparer.Ordinal))
                RecoverChunksLocked(group.Key, group.ToList());
        }
    }

    /// <summary>Completes (or fails) a journaled commit whose rename may not have run yet.</summary>
    private void ReconcileCommitIntentLocked(string fileId, string sha, string finalRel)
    {
        if (!_byFileId.TryGetValue(fileId, out var item)) return; // orphan intent: ignore
        if (item.Committed) return;

        string finalAbs;
        try
        {
            finalAbs = DestinationFullPath(finalRel);
        }
        catch (ProtocolException)
        {
            MarkRecoveryFailed(item, "committed path resolves outside the destination");
            return;
        }

        var staged = StagedPath(fileId);
        try
        {
            if (File.Exists(finalAbs) &&
                string.Equals(HashFile(finalAbs), sha, StringComparison.OrdinalIgnoreCase))
            {
                // the rename finished before the crash
                if (File.Exists(staged)) File.Delete(staged);
            }
            else if (File.Exists(staged) &&
                     string.Equals(HashFile(staged), sha, StringComparison.OrdinalIgnoreCase))
            {
                // the rename had not run yet: complete it from the write-ahead intent
                Directory.CreateDirectory(Path.GetDirectoryName(finalAbs)!);
                if (File.Exists(finalAbs) && !item.OverwriteAllowed)
                {
                    // conflict appeared after planning: deterministic free name, never overwrite
                    finalRel = NextFreeName(finalRel);
                    finalAbs = DestinationFullPath(finalRel);
                }
                File.Move(staged, finalAbs, overwrite: item.OverwriteAllowed);
            }
            else
            {
                MarkRecoveryFailed(item, "committed file data unavailable after restart");
                return;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
            or ArgumentException or NotSupportedException)
        {
            MarkRecoveryFailed(item, "could not complete atomic rename: " + ex.Message);
            return;
        }

        item.Committed = true;
        item.FileSha256 = sha;
        item.FinalRelativePath = finalRel;
        // same rule as the live commit path (existed-before is unknowable after a crash,
        // so REPLACE-resolution files are reported REPLACED — cosmetic, both verify)
        item.Outcome = !string.Equals(finalRel, item.Path, StringComparison.Ordinal) ? "RENAMED"
            : item.OverwriteAllowed ? "REPLACED" : "VERIFIED";
        item.OutcomeReason ??= item.Action == "RENAME" ? item.PlanReason : null;
    }

    private static void MarkRecoveryFailed(ManifestItem item, string reason)
    {
        item.Committed = false;
        item.Outcome = "FAILED";
        item.OutcomeErrorCode = ErrorCode.E_DESTINATION_ERROR.ToString();
        item.OutcomeReason = reason;
    }

    /// <summary>
    /// Rebuilds chunk trust for one file from its journal records: coverage check (bytes
    /// present on disk), then the SPEC §5 boundary re-hash. Unjournaled bytes — a crash
    /// between the data flush and the journal append — are never trusted.
    /// </summary>
    private void RecoverChunksLocked(string fileId,
        List<(string FileId, int ChunkIndex, string Sha256Hex)> records)
    {
        if (!_byFileId.TryGetValue(fileId, out var item)) return;
        item.VerifiedChunks.Clear();
        item.ChunkHashes.Clear();
        item.BytesReceived = 0;
        if (item.Committed) return; // committed state comes from the FILE record, not chunks

        long length;
        try
        {
            var staged = StagedPath(fileId);
            length = File.Exists(staged) ? new FileInfo(staged).Length : -1;
        }
        catch (IOException)
        {
            length = -1;
        }
        if (length < 0) return; // staged data gone: sender restarts this file from chunk 0

        // last record per index wins (records after a RESET supersede stale pre-restart ones;
        // Replay already dropped pre-RESET records entirely)
        var byIndex = new SortedDictionary<int, string>();
        foreach (var r in records)
        {
            var remaining = item.Size - (long)r.ChunkIndex * ChunkSize;
            if (r.ChunkIndex < 0 || remaining <= 0) continue; // out of range for this size
            byIndex[r.ChunkIndex] = r.Sha256Hex;
        }

        var trusted = new SortedSet<int>();
        foreach (var (idx, _) in byIndex)
        {
            var end = (long)idx * ChunkSize + Math.Min(ChunkSize, item.Size - (long)idx * ChunkSize);
            if (end <= length) trusted.Add(idx); // journaled but truncated away ⇒ distrusted
        }

        // boundary re-validation (SPEC §5): re-hash the chunk below the resume point; on
        // mismatch distrust it and everything above (source may have changed under it)
        var boundary = -1;
        while (trusted.Contains(boundary + 1)) boundary++;
        if (boundary >= 0 && !ValidateChunkOnDisk(item, fileId, boundary, byIndex[boundary]))
            trusted.RemoveWhere(i => i >= boundary);

        foreach (var idx in trusted)
        {
            item.VerifiedChunks.Add(idx);
            item.ChunkHashes[idx] = byIndex[idx];
            item.BytesReceived += Math.Min(ChunkSize, item.Size - (long)idx * ChunkSize);
        }
    }

    private bool ValidateChunkOnDisk(ManifestItem item, string fileId, int idx, string expectedSha)
    {
        try
        {
            var offset = (long)idx * ChunkSize;
            var len = Math.Min(ChunkSize, item.Size - offset);
            using var fs = new FileStream(StagedPath(fileId), FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.SequentialScan);
            fs.Seek(offset, SeekOrigin.Begin);
            var buf = ArrayPool<byte>.Shared.Rent((int)len);
            try
            {
                var read = 0;
                while (read < len)
                {
                    var n = fs.Read(buf, read, (int)len - read);
                    if (n == 0) break;
                    read += n;
                }
                if (read != len) return false;
                var actual = Convert.ToHexString(
                    SHA256.HashData(buf.AsSpan(0, read))).ToLowerInvariant();
                return string.Equals(actual, expectedSha, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    // -------------------------------------------------------------- persistence

    /// <summary>Writes the durable session snapshot. Throws E_DESTINATION_ERROR when the
    /// state volume cannot be written (the sender may retry the operation).</summary>
    private void PersistLocked()
    {
        try
        {
            ToSnapshot().Save(SessionSnapshot.MetadataPath(
                Path.GetDirectoryName(StagingDir)!, Id));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ProtocolException(ErrorCode.E_DESTINATION_ERROR,
                "could not persist session state: " + ex.Message);
        }
    }

    /// <summary>Same as <see cref="PersistLocked"/> but never fails the operation (expiry/denial).</summary>
    private void PersistBestEffortLocked()
    {
        try { PersistLocked(); }
        catch (ProtocolException) { /* state already decided; restart falls back to the journal */ }
    }

    /// <summary>Server hook: persist the initial snapshot when the session is created.</summary>
    public void Persist()
    {
        lock (_gate) PersistLocked();
    }

    private SessionSnapshot ToSnapshot()
    {
        // called under _gate by every persist site
        return new SessionSnapshot
        {
            SessionId = Id,
            OwnerDeviceId = OwnerDeviceId,
            Status = Status.ToString(),
            SessionToken = SessionToken,
            CreatedAtMs = CreatedAt.ToUnixTimeMilliseconds(),
            ApprovedAtMs = ApprovedAt?.ToUnixTimeMilliseconds(),
            LastActivityMs = _lastActivity.ToUnixTimeMilliseconds(),
            ChunkSize = ChunkSize,
            SourceDeviceName = Summary.SourceDeviceName,
            FileCount = Summary.FileCount,
            DirCount = Summary.DirCount,
            SymlinkCount = Summary.SymlinkCount,
            TotalBytes = Summary.TotalBytes,
            RemoteIp = Summary.RemoteIp,
            BatchesReceived = BatchesReceived,
            ManifestDigest = ManifestDigestHex,
            PlannedFileBytes = _plannedFileBytes,
            LastBatchItemStart = LastBatchItemStart,
            LastBatchFinal = LastBatchFinal,
            ConflictResolutions = new Dictionary<string, string>(ConflictResolutions, StringComparer.Ordinal),
            Items = Items.Select(i => new ItemSnapshot
            {
                Path = i.Path, Type = i.Type, Size = i.Size, MtimeUtcNs = i.MtimeUtcNs,
                CtimeUtcNs = i.CtimeUtcNs, Mode = i.Mode, SymlinkTarget = i.SymlinkTarget,
                SenderState = i.SenderState, FileId = i.FileId, Action = i.Action,
                FinalRelativePath = i.FinalRelativePath, PlanReason = i.PlanReason,
                OverwriteAllowed = i.OverwriteAllowed, Committed = i.Committed,
                FileSha256 = i.FileSha256, Outcome = i.Outcome, OutcomeReason = i.OutcomeReason,
                OutcomeErrorCode = i.OutcomeErrorCode,
            }).ToList(),
        };
    }

    public void MarkApproved(string sessionToken)
    {
        lock (_gate)
        {
            if (Status != SessionStatus.AwaitingApproval)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, "session already handled");
            Status = SessionStatus.ManifestReceiving;
            SessionToken = sessionToken;
            ApprovedAt = DateTimeOffset.UtcNow;
            _lastActivity = ApprovedAt.Value;
            PersistLocked();
        }
    }

    public void MarkDenied()
    {
        lock (_gate)
        {
            Status = SessionStatus.Denied;
            PersistBestEffortLocked();
        }
    }

    /// <summary>Records protocol activity so the idle clock restarts (SPEC §7 idle timeouts).</summary>
    public void Touch()
    {
        lock (_gate) _lastActivity = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Expires the session when it is past <see cref="ReceiverOptions.SessionTtl"/> (from
    /// creation) or, for approved sessions, past <see cref="ReceiverOptions.IdleTimeout"/>
    /// of inactivity; expiry is terminal and purges staging (SPEC §5: "expiry is
    /// configurable, with staging cleanup"; verified files at final paths stay in place).
    /// </summary>
    public void ExpireIfDue()
    {
        lock (_gate)
        {
            var terminal = Status is SessionStatus.Completed or SessionStatus.Failed
                or SessionStatus.Cancelled or SessionStatus.Denied or SessionStatus.Expired;
            if (terminal) return;

            var now = DateTimeOffset.UtcNow;
            var ttlExceeded = now - CreatedAt > _options.SessionTtl;
            var idleExceeded = ApprovedAt is not null
                && _options.IdleTimeout > TimeSpan.Zero
                && now - _lastActivity > _options.IdleTimeout;
            if (!ttlExceeded && !idleExceeded) return;

            Status = SessionStatus.Expired;
            PersistBestEffortLocked(); // metadata first: purge must not lose the expiry itself
            PurgeStaging();
        }
    }

    private void RequireStatus(params SessionStatus[] allowed)
    {
        lock (_gate)
        {
            if (!allowed.Contains(Status))
                throw new ProtocolException(ErrorCode.E_SESSION_STATE,
                    $"session is {Status}, expected one of [{string.Join(", ", allowed)}]");
        }
    }

    // ------------------------------------------------------------------ manifest

    public ManifestBatchResponse ReceiveBatch(IReadOnlyList<JsonElement> entries, int batchIndex,
        bool final, string? manifestDigestHex, CancellationToken ct)
    {
        lock (_gate)
        {
            // idempotent retry (M3 fault injection, SPEC §8): the response to the last
            // accepted batch was lost — rebuild it from state instead of failing the replay
            if (BatchesReceived > 0 && batchIndex == BatchesReceived - 1 &&
                LastBatchItemStart >= 0 && final == LastBatchFinal)
                return RebuildBatchResponseLocked();

            if (Status != SessionStatus.ManifestReceiving)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");
            if (batchIndex != BatchesReceived)
                throw new ProtocolException(ErrorCode.E_BAD_REQUEST,
                    $"out-of-order batch: got {batchIndex}, expected {BatchesReceived}");
            if (entries.Count > ProtocolConstants.MaxEntriesPerBatch)
                throw new ProtocolException(ErrorCode.E_MANIFEST_TOO_LARGE,
                    $"{entries.Count} entries exceeds {ProtocolConstants.MaxEntriesPerBatch}");
            if (final && string.IsNullOrEmpty(manifestDigestHex))
                throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "final batch requires manifestDigest");

            // two-phase: parse everything before mutating state, so a rejected entry or a
            // digest mismatch leaves the session exactly as it was (the sender may retry)
            var parsed = new List<ManifestItem>(entries.Count);
            foreach (var el in entries)
            {
                ct.ThrowIfCancellationRequested();
                parsed.Add(ParseAndPlanEntry(el));
            }

            if (final)
            {
                var computed = ManifestDigest.ComputeHex(Items.Concat(parsed).Select(
                    i => new ManifestDigest.Entry(i.Path, i.Type, i.Size, i.MtimeUtcNs, i.Mode)));
                if (!string.Equals(computed, manifestDigestHex, StringComparison.Ordinal))
                    throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "manifestDigest mismatch");
                ManifestDigestHex = computed;
            }

            var start = Items.Count;
            var planned = new List<PlannedItem>(parsed.Count);
            foreach (var item in parsed)
            {
                Items.Add(item);
                if (item.Type == "file" && item.Action is "CREATE" or "RENAME" or "CONFLICT")
                {
                    item.FileId = $"f-{_byFileId.Count:D4}";
                    _byFileId[item.FileId] = item;
                    _plannedFileBytes += item.Size;
                }
                planned.Add(new PlannedItem(
                    item.Path, item.FileId, item.Action, item.FinalRelativePath, item.PlanReason));
            }
            LastBatchItemStart = start;
            LastBatchFinal = final;
            BatchesReceived++;

            if (final)
            {
                ApplyCaseCollisionRenames();
                Status = SessionStatus.PreflightReady;
            }
            PersistLocked();

            if (!final)
                return new ManifestBatchResponse("MANIFEST_RECEIVING", planned, null, true);
            return new ManifestBatchResponse("PREFLIGHT_READY", planned, BuildPreflight(), true);
        }
    }

    /// <summary>Rebuilds the response for a re-sent batch that was already accepted.</summary>
    private ManifestBatchResponse RebuildBatchResponseLocked()
    {
        var planned = Items.Skip(LastBatchItemStart)
            .Select(i => new PlannedItem(i.Path, i.FileId, i.Action, i.FinalRelativePath, i.PlanReason))
            .ToList();
        if (Status == SessionStatus.PreflightReady && LastBatchFinal)
            return new ManifestBatchResponse("PREFLIGHT_READY", planned, BuildPreflight(), true);
        if (Status == SessionStatus.ManifestReceiving)
            return new ManifestBatchResponse("MANIFEST_RECEIVING", planned, null, true);
        // sender already moved past this batch; ack the current state
        return new ManifestBatchResponse(WireStatus(Status), planned, null, true);
    }

    /// <summary>Session status in wire form: AwaitingApproval → AWAITING_APPROVAL.</summary>
    public static string WireStatus(SessionStatus status) =>
        System.Text.RegularExpressions.Regex.Replace(
            status.ToString(), "([a-z0-9])([A-Z])", "$1_$2").ToUpperInvariant();

    private ManifestItem ParseAndPlanEntry(JsonElement el)
    {
        var path = el.GetProperty("path").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "entry.path missing");
        var type = el.GetProperty("type").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "entry.type missing");
        if (type is not ("file" or "dir" or "symlink"))
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, $"invalid type '{type}'");
        var size = el.GetProperty("size").GetInt64();
        var mtime = el.GetProperty("mtimeUtcNs").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "entry.mtimeUtcNs missing");
        var mode = el.GetProperty("mode").GetInt64();
        var ctime = el.TryGetProperty("ctimeUtcNs", out var ctEl) ? ctEl.GetString() : null;
        var target = el.TryGetProperty("symlinkTarget", out var stEl) ? stEl.GetString() : null;
        var senderState = el.TryGetProperty("senderState", out var ssEl) ? ssEl.GetString() : null;

        // wire paths are NFC; normalize again defensively (defense in depth)
        path = path.Normalize(NormalizationForm.FormC);

        var item = new ManifestItem
        {
            Path = path, Type = type, Size = size, MtimeUtcNs = mtime, CtimeUtcNs = ctime,
            Mode = mode, SymlinkTarget = target, SenderState = senderState,
        };

        // 1. sender-declared states (unreadable / cloud placeholder) — ledger, never transferred
        if (senderState is "UNREADABLE" or "CLOUD_PLACEHOLDER")
        {
            item.Action = "EXCLUDED_BY_POLICY";
            item.PlanReason = senderState;
            item.Outcome = senderState;
            return item;
        }

        // 2. hostile-path defense (SPEC §6.2, PathSanitizer)
        var verdict = PathSanitizer.Sanitize(path);
        if (verdict.Verdict == PathSanitizer.Verdict.Reject)
        {
            item.Action = "REJECTED";
            item.PlanReason = verdict.Reason;
            item.Outcome = "FAILED";
            item.OutcomeErrorCode = ErrorCode.E_PATH_REJECTED.ToString();
            item.OutcomeReason = verdict.Reason;
            return item;
        }

        // 3. Apple metadata policy
        var excluded = PathSanitizer.ExcludedPolicyReason(path);
        if (excluded is not null)
        {
            item.Action = "EXCLUDED_BY_POLICY";
            item.PlanReason = excluded;
            item.Outcome = "EXCLUDED_BY_POLICY";
            item.OutcomeReason = excluded;
            return item;
        }

        // 4. symlinks: recorded, not recreated by default (ADR-013)
        if (type == "symlink")
        {
            item.Action = "EXCLUDED_BY_POLICY";
            item.PlanReason = "POLICY_SYMLINK_NOT_PRESERVED";
            item.Outcome = "EXCLUDED_BY_POLICY";
            item.OutcomeReason = "POLICY_SYMLINK_NOT_PRESERVED";
            return item;
        }

        // sanitized form becomes the working path (recorded as RENAMED if it differs)
        var sanitizedPath = verdict.FinalPath;
        item.FinalRelativePath = sanitizedPath;
        if (!string.Equals(sanitizedPath, path, StringComparison.Ordinal))
        {
            item.Action = "RENAME";
            item.PlanReason = "SANITIZED";
        }

        // 5. canonicalization containment (defense in depth) + destination conflicts
        string abs;
        try
        {
            abs = DestinationFullPath(sanitizedPath);
        }
        catch (Exception ex) when (ex is ProtocolException { Code: ErrorCode.E_PATH_REJECTED }
            or ArgumentException or PathTooLongException or NotSupportedException)
        {
            // canonicalized outside the destination ⇒ ledger as FAILED, never write
            item.Action = "REJECTED";
            item.PlanReason = "OUTSIDE_DESTINATION";
            item.Outcome = "FAILED";
            item.OutcomeErrorCode = ErrorCode.E_PATH_REJECTED.ToString();
            item.OutcomeReason = "OUTSIDE_DESTINATION";
            return item;
        }

        if (type == "file" && (File.Exists(abs) || Directory.Exists(abs)))
        {
            item.Action = "CONFLICT";
            item.PlanReason = "EXISTS";
        }

        return item;
    }

    private void ApplyCaseCollisionRenames()
    {
        // deterministic: manifest order; second+ colliding (NFC + case-insensitive) gets " (n)"
        var candidates = Items.Where(i => i.Type == "file" && i.FinalRelativePath is not null).ToList();
        var resolved = PathSanitizer.ResolveCaseCollisions(
            candidates.Select(i => i.FinalRelativePath!).ToList());
        for (var idx = 0; idx < candidates.Count; idx++)
        {
            var item = candidates[idx];
            var renamed = resolved[idx];
            if (string.Equals(renamed, item.FinalRelativePath, StringComparison.Ordinal))
                continue;
            item.FinalRelativePath = renamed;
            if (item.Action != "CONFLICT")
            {
                item.Action = "RENAME";
                item.PlanReason ??= "CASE_COLLISION";
            }
            // conflicted items keep Action=CONFLICT; resolution applies to the renamed path
        }
    }

    private PreflightInfo BuildPreflight()
    {
        var conflicts = new List<object>();
        var renames = new List<object>();
        var excluded = new List<object>();
        var rejected = new List<object>();
        var problems = new List<object>();
        var info = _destination.GetInfo();

        foreach (var item in Items)
        {
            switch (item.Action)
            {
                case "CONFLICT" when item.Type == "file":
                {
                    var abs = DestinationFullPath(item.FinalRelativePath ?? item.Path);
                    long size = 0;
                    string? mtimeNs = null;
                    if (File.Exists(abs))
                    {
                        var fi = new FileInfo(abs);
                        size = fi.Length;
                        mtimeNs = ((fi.LastWriteTimeUtc - DateTime.UnixEpoch).Ticks * 100L)
                            .ToString();
                    }
                    conflicts.Add(new { path = item.Path, existingSize = size, existingMtimeUtcNs = mtimeNs });
                    break;
                }
                case "RENAME":
                    renames.Add(new { path = item.Path, finalPath = item.FinalRelativePath, reason = item.PlanReason });
                    break;
                case "EXCLUDED_BY_POLICY":
                    excluded.Add(new { path = item.Path, reason = item.PlanReason });
                    break;
                case "REJECTED":
                    rejected.Add(new { path = item.Path, reason = item.PlanReason });
                    break;
            }

            if (item.Type == "file" && item.Size > info.MaxFileSize)
                problems.Add(new
                {
                    code = "P_FAT32_4GB", path = item.Path,
                    message = $"file is {item.Size} bytes; destination filesystem {info.FileSystem} " +
                              $"supports at most {info.MaxFileSize} bytes per file",
                });
        }

        return new PreflightInfo(
            Status: "PREFLIGHT_READY",
            ManifestDigest: ManifestDigestHex,
            Totals: new ManifestTotals(
                Files: Items.Count(i => i.Type == "file"),
                Dirs: Items.Count(i => i.Type == "dir"),
                Symlinks: Items.Count(i => i.Type == "symlink"),
                Bytes: Items.Where(i => i.Type == "file").Sum(i => i.Size)),
            Conflicts: conflicts, Renames: renames, Excluded: excluded, Rejected: rejected,
            Destination: new DestinationInfoDto(
                info.Path, info.FreeBytes, info.FileSystem, info.Writable, info.LongPathsEnabled),
            PredictedProblems: problems);
    }

    // ------------------------------------------------------------------- confirm

    public void Confirm(IReadOnlyDictionary<string, string> resolutions, string? applyToAllDefault)
    {
        lock (_gate)
        {
            // idempotent retry (M3): the confirm response was lost — names are already
            // fixed and the session is already in flight, so re-confirming is a no-op
            if (Status is SessionStatus.Transferring or SessionStatus.Paused)
            {
                PersistBestEffortLocked();
                return;
            }
            if (Status != SessionStatus.PreflightReady)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");

            foreach (var kv in resolutions)
                ConflictResolutions[kv.Key] = kv.Value;
            if (applyToAllDefault is not null && applyToAllDefault != "ASK")
            {
                foreach (var item in Items.Where(i => i.Action == "CONFLICT"))
                    ConflictResolutions.TryAdd(item.Path, applyToAllDefault);
            }

            var unresolved = Items.Where(i => i.Action == "CONFLICT" &&
                !ConflictResolutions.ContainsKey(i.Path)).Select(i => i.Path).ToList();
            if (unresolved.Count > 0)
                throw new ProtocolException(ErrorCode.E_CONFLICT_UNRESOLVED,
                    $"{unresolved.Count} conflicts unresolved");

            // blocking preflight problems (e.g. FAT32 4 GiB) fail preflight (SPEC §6.2)
            var info = _destination.GetInfo();
            if (Items.Any(i => i.Type == "file" && i.Size > info.MaxFileSize))
                throw new ProtocolException(ErrorCode.E_LIMIT_EXCEEDED,
                    $"file exceeds destination filesystem {info.FileSystem} per-file limit");

            if (info.FreeBytes < _plannedFileBytes + _options.FreeSpaceMarginBytes)
                throw new ProtocolException(ErrorCode.E_INSUFFICIENT_STORAGE,
                    $"need {_plannedFileBytes + _options.FreeSpaceMarginBytes} bytes, have {info.FreeBytes}");

            // apply conflict resolutions now (names fixed before any bytes flow)
            foreach (var item in Items.Where(i => i.Action == "CONFLICT"))
            {
                var resolution = ConflictResolutions[item.Path];
                switch (resolution)
                {
                    case "SKIP":
                        item.Outcome = "SKIPPED_BY_USER";
                        item.OutcomeReason = "CONFLICT_SKIP";
                        item.FinalRelativePath = null;
                        break;
                    case "REPLACE":
                        item.OverwriteAllowed = true;
                        break;
                    case "RENAME":
                        item.FinalRelativePath = NextFreeName(item.FinalRelativePath!);
                        item.Action = "RENAME";
                        item.PlanReason = "CONFLICT_RENAME";
                        break;
                    case "KEEP_BOTH":
                        item.FinalRelativePath = NextFreeName(item.FinalRelativePath!);
                        item.Action = "RENAME";
                        item.PlanReason = "CONFLICT_KEEP_BOTH";
                        break;
                    default:
                        throw new ProtocolException(ErrorCode.E_BAD_REQUEST,
                            $"unknown conflict resolution '{resolution}'");
                }
            }

            // create every manifest directory up front (deterministic, before any file bytes)
            foreach (var dir in Items.Where(i => i.Type == "dir"))
            {
                var rel = dir.FinalRelativePath ?? dir.Path;
                var abs = DestinationFullPath(rel);
                AssertNoReparseAncestor(abs);
                Directory.CreateDirectory(abs);
                StampTimestamps(abs, dir.MtimeUtcNs, dir.CtimeUtcNs);
            }

            Status = SessionStatus.Transferring;
            PersistLocked();
        }
    }

    private string NextFreeName(string relativePath)
    {
        var n = 2;
        var candidate = InsertSuffix(relativePath, n);
        while (File.Exists(DestinationFullPath(candidate)) ||
               Directory.Exists(DestinationFullPath(candidate)) ||
               Items.Any(i => i.FinalRelativePath == candidate))
        {
            n++;
            candidate = InsertSuffix(relativePath, n);
        }
        return candidate;
    }

    private static string InsertSuffix(string relativePath, int n)
    {
        var slash = relativePath.LastIndexOf('/');
        var dir = slash >= 0 ? relativePath[..(slash + 1)] : string.Empty;
        var name = slash >= 0 ? relativePath[(slash + 1)..] : relativePath;
        var dot = name.LastIndexOf('.');
        return dot > 0
            ? dir + name[..dot] + $" ({n})" + name[dot..]
            : dir + name + $" ({n})";
    }

    // ------------------------------------------------------------------- chunks

    public async Task<ChunkPutResponse> PutChunkAsync(string fileId, int chunkIndex, Stream body,
        string? declaredSha256, CancellationToken ct, long? declaredContentLength = null)
    {
        ManifestItem item;
        long expectedLen;
        lock (_gate)
        {
            if (Status != SessionStatus.Transferring)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");
            if (!_byFileId.TryGetValue(fileId, out item!))
                throw new ProtocolException(ErrorCode.E_SESSION_NOT_FOUND, $"unknown fileId {fileId}");

            expectedLen = Math.Min(ChunkSize, item.Size - (long)chunkIndex * ChunkSize);
            if (chunkIndex < 0 || item.Size == 0 || expectedLen <= 0 || expectedLen > ChunkSize)
                throw new ProtocolException(ErrorCode.E_BAD_REQUEST,
                    $"chunk {chunkIndex} out of range for size {item.Size}");

            // declared body size must match the chunk exactly — a longer/shorter stream is
            // hostile or broken input (SPEC §7 endless streams), reject before reading
            if (declaredContentLength is { } contentLength && contentLength != expectedLen)
                throw new ProtocolException(ErrorCode.E_BAD_REQUEST,
                    $"Content-Length {contentLength} != expected chunk length {expectedLen}");

            if (item.VerifiedChunks.Contains(chunkIndex))
            {
                // idempotent retry: same bytes ⇒ ALREADY_VERIFIED; different ⇒ source changed
                if (item.ChunkHashes.TryGetValue(chunkIndex, out var stored) &&
                    string.Equals(stored, declaredSha256, StringComparison.OrdinalIgnoreCase))
                    return new ChunkPutResponse("ALREADY_VERIFIED", expectedLen);
                throw new ProtocolException(ErrorCode.E_SOURCE_CHANGED,
                    $"chunk {chunkIndex} of {fileId} already verified with different content");
            }
        }

        // read + hash outside the lock (backpressure = we only read as fast as we persist)
        var buffer = ArrayPool<byte>.Shared.Rent((int)expectedLen);
        try
        {
            var read = 0;
            while (read < expectedLen)
            {
                var n = await body.ReadAsync(buffer.AsMemory(read, (int)expectedLen - read), ct);
                if (n == 0) break;
                read += n;
            }
            if (read != expectedLen)
                throw new ProtocolException(ErrorCode.E_BAD_REQUEST,
                    $"chunk body length {read}, expected {expectedLen}");

            var actualSha = Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, read))).ToLowerInvariant();
            if (!string.Equals(actualSha, declaredSha256, StringComparison.OrdinalIgnoreCase))
                throw new ProtocolException(ErrorCode.E_CHUNK_HASH_MISMATCH,
                    $"chunk {chunkIndex} hash mismatch");

            lock (_gate)
            {
                if (Status != SessionStatus.Transferring)
                    throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");

                // persist: write at offset, flush to disk, THEN journal (write-ahead order)
                var stagedPath = StagedPath(fileId);
                Directory.CreateDirectory(StagingDir); // recovered session whose staging vanished
                using (var fs = new FileStream(stagedPath, FileMode.OpenOrCreate, FileAccess.Write,
                           FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    fs.Seek((long)chunkIndex * ChunkSize, SeekOrigin.Begin);
                    fs.Write(buffer, 0, read);
                    fs.Flush(flushToDisk: true);
                }

                item.StreamingHash ??= IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                item.StreamingHash.AppendData(buffer.AsSpan(0, read));
                item.VerifiedChunks.Add(chunkIndex);
                item.ChunkHashes[chunkIndex] = actualSha;
                item.BytesReceived += read;
                Journal.RecordChunk(fileId, chunkIndex, actualSha);

                return new ChunkPutResponse("VERIFIED", read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ------------------------------------------------------------------- commit

    public CommitResponse CommitFile(string fileId, string fileSha256Hex, long size,
        string? mtimeUtcNs, string? ctimeUtcNs, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_byFileId.TryGetValue(fileId, out var item))
                throw new ProtocolException(ErrorCode.E_SESSION_NOT_FOUND, $"unknown fileId {fileId}");

            // idempotent retry (M3 fault injection, SPEC §8): the commit response was lost
            // after the atomic rename — replaying the same commit must not rename twice
            if (item.Committed)
            {
                if (string.Equals(item.FileSha256, fileSha256Hex, StringComparison.OrdinalIgnoreCase))
                    return new CommitResponse(item.Outcome,
                        DestinationFullPath(item.FinalRelativePath!));
                throw new ProtocolException(ErrorCode.E_SOURCE_CHANGED,
                    "file already committed with different content");
            }

            if (Status != SessionStatus.Transferring)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");

            var expectedChunks = item.Size == 0 ? 0 : (int)((item.Size + ChunkSize - 1) / ChunkSize);
            if (item.VerifiedChunks.Count < expectedChunks)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE,
                    $"file {fileId} has {item.VerifiedChunks.Count}/{expectedChunks} chunks");

            // source changed since manifest (SPEC §5/§6.1): flag and require a restart
            if (size != item.Size)
            {
                ResetFileForRestart(item, fileId);
                item.Outcome = "CHANGED_DURING_TRANSFER";
                item.OutcomeReason = $"size {size} != manifest {item.Size}";
                throw new ProtocolException(ErrorCode.E_SOURCE_CHANGED,
                    "source size changed since manifest");
            }

            var staged = StagedPath(fileId);
            if (!File.Exists(staged))
            {
                if (size == 0)
                    File.WriteAllBytes(staged, Array.Empty<byte>());
                else
                    throw new ProtocolException(ErrorCode.E_SESSION_STATE, "staged file missing");
            }
            var stagedInfo = new FileInfo(staged);
            if (stagedInfo.Length != size)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE,
                    $"staged length {stagedInfo.Length}, expected {size}");

            // verify after write: hash the on-disk bytes (default ON, SPEC §5)
            string computedHash;
            if (_options.VerifyAfterWrite)
            {
                computedHash = HashFile(staged);
            }
            else
            {
                computedHash = item.StreamingHash is null
                    ? HashFile(staged)
                    : Convert.ToHexString(item.StreamingHash.GetHashAndReset()).ToLowerInvariant();
            }
            if (!string.Equals(computedHash, fileSha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                ResetFileForRestart(item, fileId);
                item.Outcome = "PENDING"; // sender restarts this file (once, per SPEC §5)
                throw new ProtocolException(ErrorCode.E_FILE_HASH_MISMATCH,
                    $"on-disk sha256 {computedHash} != declared {fileSha256Hex}");
            }

            var finalRel = item.FinalRelativePath
                ?? throw new ProtocolException(ErrorCode.E_SESSION_STATE, "item has no final path");
            var finalAbs = DestinationFullPath(finalRel);
            AssertNoReparseAncestor(finalAbs);

            // timestamps before the rename (SPEC §5: flush → verify → timestamps → rename)
            StampTimestamps(staged, mtimeUtcNs ?? item.MtimeUtcNs, ctimeUtcNs ?? item.CtimeUtcNs);

            var existed = File.Exists(finalAbs);
            if (existed && !item.OverwriteAllowed)
            {
                // conflict appeared after planning: deterministic free name, never overwrite silently
                var renamedRel = NextFreeName(finalRel);
                item.FinalRelativePath = renamedRel;
                item.Action = "RENAME";
                item.PlanReason = "RACE_RENAME";
                finalRel = renamedRel;
                finalAbs = DestinationFullPath(finalRel);
                existed = File.Exists(finalAbs);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(finalAbs)!);
            try
            {
                File.Move(staged, finalAbs, overwrite: item.OverwriteAllowed);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new ProtocolException(ErrorCode.E_DESTINATION_ERROR,
                    $"atomic rename failed: {ex.Message}");
            }

            item.Committed = true;
            item.FileSha256 = fileSha256Hex.ToLowerInvariant();
            item.Outcome = item.OverwriteAllowed && existed ? "REPLACED"
                : !string.Equals(finalRel, item.Path, StringComparison.Ordinal) ? "RENAMED"
                : "VERIFIED";
            item.OutcomeReason ??= item.Action == "RENAME" ? item.PlanReason : null;
            Journal.RecordFileCommitted(fileId, item.FileSha256, finalRel);

            return new CommitResponse(item.Outcome, finalAbs);
        }
    }

    private void ResetFileForRestart(ManifestItem item, string fileId)
    {
        // journal first: from here on, earlier CHUNK records for this file are stale
        // (M3 crash-recovery replay drops everything before the latest RESET)
        Journal.RecordReset(fileId);
        item.VerifiedChunks.Clear();
        item.ChunkHashes.Clear();
        item.BytesReceived = 0;
        item.StreamingHash?.GetHashAndReset(); // discard; resets for a full restart
        var staged = StagedPath(fileId);
        if (File.Exists(staged)) File.Delete(staged);
    }

    private static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096,
            FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    // ------------------------------------------------------------- resume state

    public SessionStateResponse GetState(string? cursor)
    {
        lock (_gate)
        {
            var completed = Items.Where(i => i.Committed)
                .Select(i => new CompletedFile(i.Path, i.FileSha256!)).ToList();
            var partial = Items.Where(i => i.Type == "file" && !i.Committed && i.VerifiedChunks.Count > 0)
                .Select(i => new PartialFile(i.Path, i.FileId!,
                    i.VerifiedChunks.ToList(), NextMissingChunk(i))).ToList();

            var offset = 0;
            if (!string.IsNullOrEmpty(cursor) && int.TryParse(cursor, out var o) && o >= 0)
                offset = o;
            var completedPage = completed.Skip(offset).Take(StatePageSize).ToList();
            var partialPage = offset < completed.Count
                ? partial.Skip(Math.Max(0, offset - completed.Count)).Take(StatePageSize).ToList()
                : offset == completed.Count ? partial.Take(StatePageSize).ToList() : new List<PartialFile>();
            var consumed = completedPage.Count + partialPage.Count;
            var total = completed.Count + partial.Count;
            var nextCursor = offset + consumed < total ? (offset + consumed).ToString() : null;

            return new SessionStateResponse(
                Status.ToString().ToUpperInvariant(),
                ManifestDigestHex,
                ChunkSize,
                completedPage,
                partialPage,
                nextCursor);
        }
    }

    private static int NextMissingChunk(ManifestItem item)
    {
        if (item.Size == 0) return 0;
        var i = 0;
        while (item.VerifiedChunks.Contains(i)) i++;
        return i;
    }

    // ----------------------------------------------------------------- controls

    public void Pause() => Transition(SessionStatus.Transferring, SessionStatus.Paused);
    public void Resume() => Transition(SessionStatus.Paused, SessionStatus.Transferring);

    private void Transition(SessionStatus from, SessionStatus to)
    {
        lock (_gate)
        {
            if (Status == to) { PersistBestEffortLocked(); return; } // idempotent replay
            if (Status != from)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE,
                    $"session is {Status}, expected {from}");
            Status = to;
            PersistLocked();
        }
    }

    public SessionReport Cancel()
    {
        lock (_gate)
        {
            if (Status != SessionStatus.Cancelled)
            {
                Status = SessionStatus.Cancelled;
                var report = BuildReportLocked(); // terminal outcomes land in the snapshot
                PersistLocked();
                // verified files stay in place; incomplete staging is deleted (SPEC §5)
                PurgeStaging();
                return report;
            }
            PurgeStaging(); // replayed cancel: make sure the purge happened
            return BuildReportLocked();
        }
    }

    public SessionReport Complete()
    {
        lock (_gate)
        {
            if (Status == SessionStatus.Completed)
            {
                PurgeStaging(); // replayed complete: make sure the purge happened
                return BuildReportLocked();
            }
            if (Status != SessionStatus.Transferring && Status != SessionStatus.Paused)
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, $"session is {Status}");
            Status = SessionStatus.Completed;
            var report = BuildReportLocked(); // terminal outcomes land in the snapshot
            PersistLocked();
            PurgeStaging();
            return report;
        }
    }

    public SessionReport BuildReport()
    {
        lock (_gate) return BuildReportLocked();
    }

    private void MarkTerminalFailures()
    {
        // any item still PENDING at report time gets a terminal state — nothing dropped silently
        foreach (var item in Items.Where(i => i.Outcome == "PENDING"))
        {
            if (item.Type == "dir")
            {
                var exists = Directory.Exists(DestinationFullPath(item.FinalRelativePath ?? item.Path));
                item.Outcome = exists ? "VERIFIED" : "FAILED";
                item.OutcomeReason = exists ? null : "directory missing";
            }
            else
            {
                item.Outcome = "FAILED";
                item.OutcomeErrorCode ??= ErrorCode.E_INTERNAL.ToString();
                item.OutcomeReason ??= "not committed";
            }
        }
    }

    private SessionReport BuildReportLocked()
    {
        MarkTerminalFailures();
        var files = Items.Where(i => i.Type == "file").ToList();
        var report = new SessionReport(
            Id,
            Status.ToString().ToUpperInvariant(),
            CreatedAt.ToUnixTimeMilliseconds().ToString(),
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(),
            new ReportTotals(
                Items: Items.Count,
                Verified: Items.Count(i => i.Outcome == "VERIFIED"),
                Renamed: Items.Count(i => i.Outcome == "RENAMED"),
                Replaced: Items.Count(i => i.Outcome == "REPLACED"),
                Skipped: Items.Count(i => i.Outcome == "SKIPPED_BY_USER"),
                Excluded: Items.Count(i => i.Outcome == "EXCLUDED_BY_POLICY"),
                Unreadable: Items.Count(i => i.Outcome == "UNREADABLE"),
                CloudPlaceholder: Items.Count(i => i.Outcome == "CLOUD_PLACEHOLDER"),
                Changed: Items.Count(i => i.Outcome == "CHANGED_DURING_TRANSFER"),
                Failed: Items.Count(i => i.Outcome == "FAILED"),
                BytesVerified: files.Where(i => i.Outcome is "VERIFIED" or "RENAMED" or "REPLACED")
                    .Sum(i => i.Size)),
            Items.Select(i => new ReportItem(
                i.Path,
                i.Type is "file" or "dir" && i.FinalRelativePath is not null
                    ? DestinationFullPath(i.FinalRelativePath)
                    : null,
                i.Outcome,
                i.Size,
                i.FileSha256,
                i.OutcomeReason ?? i.PlanReason,
                i.OutcomeErrorCode)).ToList());

        // invariant: totals reconcile with the ledger (SPEC §5)
        var t = report.Totals;
        var sum = t.Verified + t.Renamed + t.Replaced + t.Skipped + t.Excluded +
                  t.Unreadable + t.CloudPlaceholder + t.Changed + t.Failed;
        if (sum != t.Items)
            throw new InvalidOperationException(
                $"ledger reconcile failed: outcomes={sum} items={t.Items}");
        if (report.Items.Count != t.Items)
            throw new InvalidOperationException("report items != totals.items");
        return report;
    }

    private void PurgeStaging()
    {
        try
        {
            Journal.Dispose();
            if (Directory.Exists(StagingDir))
                Directory.Delete(StagingDir, recursive: true);
        }
        catch (IOException) { /* best effort; TTL sweep retries */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }

    // ------------------------------------------------------------- path helpers

    public string DestinationFullPath(string relativePath)
    {
        var combined = Path.GetFullPath(Path.Combine(
            _options.DestinationRoot,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
        AssertInsideDestination(combined);
        return combined;
    }

    private void AssertInsideDestination(string fullPath)
    {
        var root = Path.GetFullPath(_options.DestinationRoot);
        if (!root.EndsWith(Path.DirectorySeparatorChar)) root += Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new ProtocolException(ErrorCode.E_PATH_REJECTED,
                "resolved path escapes the destination");
    }

    /// <summary>Refuse to write through existing junctions/symlinks/reparse points (SPEC §7).</summary>
    private void AssertNoReparseAncestor(string fullPath)
    {
        var root = Path.GetFullPath(_options.DestinationRoot);
        var dir = Path.GetDirectoryName(fullPath);
        while (!string.IsNullOrEmpty(dir))
        {
            var dirFull = Path.GetFullPath(dir);
            if (!_reparseCheckCache.TryGetValue(dirFull, out var verdict))
            {
                verdict = "ok";
                if (Directory.Exists(dirFull) &&
                    (File.GetAttributes(dirFull) & FileAttributes.ReparsePoint) != 0)
                    verdict = "REPARSE_POINT";
                _reparseCheckCache[dirFull] = verdict;
            }
            if (verdict != "ok")
                throw new ProtocolException(ErrorCode.E_PATH_REJECTED,
                    $"path traverses an existing reparse point at {dirFull}");
            if (string.Equals(dirFull, Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase))
                break;
            dir = Path.GetDirectoryName(dirFull);
        }
    }

    private static void StampTimestamps(string path, string mtimeUtcNs, string? ctimeUtcNs)
    {
        try
        {
            // File.* opens without FILE_FLAG_BACKUP_SEMANTICS and fails with access-denied
            // on directories, so pick the API that matches the path kind.
            var isDirectory = Directory.Exists(path);
            if (long.TryParse(mtimeUtcNs, out var ns) && ns > 0)
            {
                var mtime = DateTimeOffset.FromUnixTimeMilliseconds(ns / 1_000_000)
                    .AddTicks((ns % 1_000_000) / 100).UtcDateTime;
                if (isDirectory) Directory.SetLastWriteTimeUtc(path, mtime);
                else File.SetLastWriteTimeUtc(path, mtime);
            }
            if (long.TryParse(ctimeUtcNs, out var cns) && cns > 0)
            {
                var ctime = DateTimeOffset.FromUnixTimeMilliseconds(cns / 1_000_000)
                    .AddTicks((cns % 1_000_000) / 100).UtcDateTime;
                if (isDirectory) Directory.SetCreationTimeUtc(path, ctime);
                else File.SetCreationTimeUtc(path, ctime);
            }
        }
        catch (IOException) { /* filesystem granularity (FAT32/exFAT documented in docs) */ }
        catch (UnauthorizedAccessException) { /* read-only media: timestamps are best-effort */ }
        catch (ArgumentOutOfRangeException) { /* out-of-range timestamp from hostile input */ }
        catch (PlatformNotSupportedException) { /* creation time unsupported on this volume */ }
    }

    private string StagedPath(string fileId) => Path.Combine(StagingDir, fileId + ".m2wpart");

    public void Dispose()
    {
        try { Journal.Dispose(); } catch { /* already purged */ }
    }
}

// ------------------------------------------------------------------ DTOs

public sealed record PlannedItem(string Path, string? FileId, string Action, string? FinalPath, string? Reason);

public sealed record ManifestBatchResponse(
    string Status, IReadOnlyList<PlannedItem> Planned, PreflightInfo? Preflight, bool BatchAccepted);

public sealed record ManifestTotals(long Files, long Dirs, long Symlinks, long Bytes);

public sealed record DestinationInfoDto(
    string Path, long FreeBytes, string FileSystem, bool Writable, bool LongPathsEnabled);

public sealed record PreflightInfo(
    string Status, string? ManifestDigest, ManifestTotals Totals,
    IReadOnlyList<object> Conflicts, IReadOnlyList<object> Renames,
    IReadOnlyList<object> Excluded, IReadOnlyList<object> Rejected,
    DestinationInfoDto Destination, IReadOnlyList<object> PredictedProblems);

public sealed record ChunkPutResponse(string Status, long BytesStored);

public sealed record CommitResponse(string Outcome, string FinalPath);

public sealed record SessionStateResponse(
    string Status, string? ManifestDigest, int ChunkSize,
    IReadOnlyList<CompletedFile> Completed, IReadOnlyList<PartialFile> Partial,
    string? Cursor);

public sealed record CompletedFile(string Path, string FileSha256);

public sealed record PartialFile(string Path, string FileId, IReadOnlyList<int> VerifiedChunks, int NextChunk);

public sealed record ReportTotals(
    long Items, long Verified, long Renamed, long Replaced, long Skipped, long Excluded,
    long Unreadable, long CloudPlaceholder, long Changed, long Failed, long BytesVerified);

public sealed record ReportItem(
    string Path, string? FinalPath, string Outcome, long Size, string? FileSha256,
    string? Reason, string? ErrorCode);

public sealed record SessionReport(
    string SessionId, string Status, string StartedAt, string FinishedAt,
    ReportTotals Totals, IReadOnlyList<ReportItem> Items);

/// <summary>Protocol-level error that maps directly to a non-2xx response (protocol §5).</summary>
public sealed class ProtocolException : Exception
{
    public ErrorCode Code { get; }
    public ProtocolException(ErrorCode code, string message) : base(message)
    {
        Code = code;
    }
}
