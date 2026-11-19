using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// M1 walking-skeleton integration tests: real TLS, real sockets, real files (AUTOMATED).
/// Invariants from SPEC Â§10 are asserted by <see cref="AssertTransferInvariants"/> after
/// every completed transfer: on-disk SHA-256 == source, no partial file at a final path,
/// source byte-identical, ledger totals reconcile.
/// Non-ASCII path literals use \u escapes so source encoding can never change meaning.
/// </summary>
public sealed class TransferTests
{
    private const int Chunk = 1024 * 1024; // TestEnv receiver chunk size (1 MiB)

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly DateTime SourceMtime = new(2024, 5, 1, 12, 0, 0, DateTimeKind.Utc);

    // ------------------------------------------------------------------ helpers

    private static byte[] Data(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string Nfc(string p) => p.Normalize(System.Text.NormalizationForm.FormC);

    private static string MtimeNs(DateTime utc) =>
        ((utc - DateTime.UnixEpoch).Ticks * 100L).ToString();

    private static Entry FileEntry(string path, byte[] data, string? senderState = null) =>
        new(Nfc(path), "file", data.Length, MtimeNs(SourceMtime), 420, SenderState: senderState);

    private static Entry DirEntry(string path) =>
        new(Nfc(path), "dir", 0, MtimeNs(SourceMtime), 493);

    private static string DigestOf(IEnumerable<Entry> entries) =>
        ManifestDigest.ComputeHex(entries.Select(e =>
            new ManifestDigest.Entry(Nfc(e.Path), e.Type, e.Size, e.MtimeUtcNs, e.Mode)));

    /// <summary>Writes a source file and records it keyed by its NFC manifest path.</summary>
    private static void AddSource(TestEnv env,
        Dictionary<string, (string Disk, byte[] Bytes)> sources, string path, byte[] bytes)
    {
        var rel = path.Replace('/', Path.DirectorySeparatorChar);
        var disk = Path.Combine(env.SourceDir, rel);
        Directory.CreateDirectory(Path.GetDirectoryName(disk)!);
        // The manifest may contain names differing only by case (a case-sensitive Mac
        // volume), but the Windows source filesystem is case-insensitive: give such
        // sources unique disk names so each declared source keeps its own bytes.
        var name = Path.GetFileName(disk);
        var dir = Path.GetDirectoryName(disk)!;
        var candidate = disk;
        for (var n = 2; sources.Values.Any(v =>
                 string.Equals(v.Disk, candidate, StringComparison.OrdinalIgnoreCase)); n++)
        {
            candidate = Path.Combine(dir,
                $"{Path.GetFileNameWithoutExtension(name)}__src{n}{Path.GetExtension(name)}");
        }
        File.WriteAllBytes(candidate, bytes);
        sources[Nfc(path)] = (candidate, bytes);
    }

    private static async Task<(string Sid, string Token)> CreateAndApproveAsync(
        ProtocolTestClient client, IReadOnlyList<Entry> entries)
    {
        var files = entries.Count(e => e.Type == "file");
        var dirs = entries.Count(e => e.Type == "dir");
        var bytes = entries.Where(e => e.Type == "file").Sum(e => e.Size);
        var sid = await client.CreateSessionAsync(files, dirs, bytes);
        var token = await client.AwaitApprovalAsync(sid);
        return (sid, token);
    }

    private static async Task<JsonElement> SendFinalManifestAsync(ProtocolTestClient client,
        string sid, string token, IReadOnlyList<Entry> entries, int batchIndex = 0)
    {
        var resp = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries), batchIndex: batchIndex);
        Assert.True(resp.IsSuccess, $"manifest: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        return resp.Body;
    }

    private static Dictionary<string, string> PlannedFileIds(JsonElement manifestResp)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in manifestResp.GetProperty("planned").EnumerateArray())
        {
            var path = p.GetProperty("path").GetString()!;
            if (p.TryGetProperty("fileId", out var fid) && fid.ValueKind == JsonValueKind.String)
                dict[path] = fid.GetString()!;
        }
        return dict;
    }

    private static async Task<int> ConfirmOkAsync(ProtocolTestClient client, string sid, string token,
        IReadOnlyDictionary<string, string>? resolutions = null, string? applyToAll = null)
    {
        var resp = await client.ConfirmAsync(sid, token, resolutions, applyToAll);
        Assert.True(resp.IsSuccess, $"confirm: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        return resp.Body.GetProperty("chunkSize").GetInt32();
    }

    private static async Task<ApiResponse> UploadAndCommitAsync(ProtocolTestClient client,
        string sid, string token, string fileId, byte[] data, int chunkSize,
        long? declaredSize = null)
    {
        var chunkCount = data.Length == 0 ? 0 : (data.Length + chunkSize - 1) / chunkSize;
        for (var i = 0; i < chunkCount; i++)
        {
            var offset = i * chunkSize;
            var len = Math.Min(chunkSize, data.Length - offset);
            var chunk = data.AsMemory(offset, len);
            var resp = await client.UploadChunkAsync(sid, token, fileId, i, chunk,
                TestEnv.HashBytes(chunk.Span));
            Assert.True(resp.IsSuccess, $"chunk {i}: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
            Assert.Equal("VERIFIED", resp.Body.GetProperty("status").GetString());
        }
        return await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(data),
            declaredSize ?? data.Length, MtimeNs(SourceMtime));
    }

    private static SessionReport ReportOf(ApiResponse resp)
    {
        Assert.True(resp.IsSuccess, $"report: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        var el = resp.Body.TryGetProperty("report", out var r) ? r : resp.Body;
        return el.Deserialize<SessionReport>(Json)!;
    }

    private static void AssertTransferInvariants(TestEnv env,
        IReadOnlyDictionary<string, (string Disk, byte[] Bytes)> sources, SessionReport report)
    {
        // ledger reconciliation: every manifest item has exactly one terminal outcome
        var t = report.Totals;
        var sum = t.Verified + t.Renamed + t.Replaced + t.Skipped + t.Excluded +
                  t.Unreadable + t.CloudPlaceholder + t.Changed + t.Failed;
        Assert.Equal(t.Items, sum);
        Assert.Equal(report.Items.Count, t.Items);

        // no partial file exists anywhere under the destination (SPEC Â§5 atomic writes)
        var partials = Directory.Exists(env.DestinationDir)
            ? Directory.GetFiles(env.DestinationDir, "*.m2wpart", SearchOption.AllDirectories)
            : Array.Empty<string>();
        Assert.Empty(partials);

        // every file the report calls verified matches the source bytes on disk
        foreach (var item in report.Items)
        {
            if (item.Outcome is not ("VERIFIED" or "RENAMED" or "REPLACED")) continue;
            if (!sources.TryGetValue(Nfc(item.Path), out var src)) continue; // dir entries
            Assert.NotNull(item.FinalPath);
            Assert.True(File.Exists(item.FinalPath!), $"missing final file {item.FinalPath}");
            Assert.Equal(TestEnv.HashBytes(src.Bytes), TestEnv.HashFile(item.FinalPath!));
        }

        // source is byte-identical before and after the transfer (read-only source)
        foreach (var (rel, src) in sources)
        {
            Assert.True(File.Exists(src.Disk), $"source disappeared: {rel}");
            Assert.Equal(TestEnv.HashBytes(src.Bytes), TestEnv.HashFile(src.Disk));
        }
    }

    // ------------------------------------------------------------------- tests

    [Fact]
    public async Task SingleFile_TransfersAndVerifiesSha256()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(1, 5 * 1024 * 1024 + 123); // multi-chunk
        AddSource(env, sources, "photo.jpg", bytes);
        var entries = new List<Entry> { FileEntry("photo.jpg", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        Assert.Equal("PREFLIGHT_READY", manifest.GetProperty("status").GetString());
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["photo.jpg"], bytes, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal("COMPLETED", report.Status);
        Assert.Equal(1, report.Totals.Verified);
        Assert.Equal(bytes.Length, report.Totals.BytesVerified);
        AssertTransferInvariants(env, sources, report);
    }

    /// <summary>
    /// Wire status is SNAKE_CASE (protocol §2.9/§2.13), including multi-word values.
    /// The state and report endpoints used <c>Status.ToString().ToUpperInvariant()</c>,
    /// which emits <c>PREFLIGHTREADY</c>; only the one-word <c>TRANSFERRING</c> was
    /// covered by tests, so the defect reached the Swift sender in CI before any C# test
    /// caught it. Every wire status must equal <c>WireStatus</c>.
    /// </summary>
    [Fact]
    public async Task StateAndReport_StatusesAreSnakeCase_OnEveryEndpoint()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(31, 64);
        AddSource(env, sources, "s.txt", bytes);
        var entries = new List<Entry> { FileEntry("s.txt", bytes) };

        // TestEnv auto-approves, so AWAITING_APPROVAL is not observable here; the
        // approval path already returned MANIFEST_RECEIVING (covered below).
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var receiving = await client.GetAsync($"/v1/sessions/{sid}", client.DeviceToken);
        Assert.True(receiving.IsSuccess, receiving.ErrorMessage);
        Assert.Equal("MANIFEST_RECEIVING", receiving.Body.GetProperty("status").GetString());

        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        Assert.Equal("PREFLIGHT_READY", manifest.GetProperty("status").GetString());

        // the state endpoint must agree with the manifest endpoint (§2.9)
        var preflight = await client.GetStateAsync(sid, token);
        Assert.True(preflight.IsSuccess, preflight.ErrorMessage);
        Assert.Equal("PREFLIGHT_READY", preflight.Body.GetProperty("status").GetString());

        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await UploadAndCommitAsync(client, sid, token, fileIds["s.txt"], bytes, chunkSize);

        var transferring = await client.GetStateAsync(sid, token);
        Assert.Equal("TRANSFERRING", transferring.Body.GetProperty("status").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal("COMPLETED", report.Status);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task BoundarySizes_ZeroOneChunkMinusOneChunkChunkPlus1_AllVerify()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();

        long[] sizes = { 0, 1, Chunk - 1, Chunk, Chunk + 1, 3 * Chunk + 7 };
        foreach (var size in sizes)
        {
            var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);
            var name = $"f-{size}.bin";
            var bytes = Data((int)size + 7, (int)size);
            AddSource(env, sources, name, bytes);
            var entries = new List<Entry> { FileEntry(name, bytes) };

            var (sid, token) = await CreateAndApproveAsync(client, entries);
            var manifest = await SendFinalManifestAsync(client, sid, token, entries);
            var fileIds = PlannedFileIds(manifest);
            var chunkSize = await ConfirmOkAsync(client, sid, token);

            var commit = await UploadAndCommitAsync(client, sid, token, fileIds[Nfc(name)], bytes, chunkSize);
            Assert.True(commit.IsSuccess, $"size {size}: {commit.ErrorCode} {commit.ErrorMessage}");
            Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

            var report = ReportOf(await client.CompleteAsync(sid, token));
            Assert.Equal(1, report.Totals.Verified);
            AssertTransferInvariants(env, sources, report);
        }
    }

    [Fact]
    public async Task FolderTransfer_UnicodeAndSpecialNames_PreservesBytes()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        // NFC, NFD-on-the-wire, emoji, RTL, CJK, reserved device name, trailing dot,
        // case collision, nested tree, zero-byte file
        var nfdPath = "cafe\u0301/nfd-name.txt";           // NFD on the wire â†’ NFC on disk
        var files = new (string Path, int Seed, int Len)[]
        {
            ("Vacation/IMG_0001.HEIC", 11, 2_500_000),
            ("cafÃ©/naÃ¯ve.txt", 12, 44),
            (nfdPath, 13, 99),
            ("\U0001F389/party.txt", 14, 31),
            ("×ž×›×ª×‘/×©×œ×•×.txt", 15, 64),
            ("ã“ã‚“ã«ã¡ã¯/ä¸–ç•Œ.txt", 16, 128),
            ("CON.txt", 17, 10),                       // reserved â†’ CON_.txt
            ("trailing.", 18, 11),                     // trailing dot â†’ "trailing"
            ("readme.txt", 19, 5),
            ("README.txt", 20, 6),                     // case collision â†’ README (2).txt
            ("deep/nested/tree/leaf.bin", 21, 4096),
            ("empty.bin", 22, 0),
        };

        var entries = new List<Entry>
        {
            DirEntry("Vacation"), DirEntry("cafÃ©"), DirEntry("\U0001F389"),
            DirEntry("×ž×›×ª×‘"), DirEntry("ã“ã‚“ã«ã¡ã¯"), DirEntry("deep"),
            DirEntry("deep/nested"), DirEntry("deep/nested/tree"),
        };
        foreach (var (path, seed, len) in files)
        {
            var bytes = Data(seed, len);
            AddSource(env, sources, path, bytes);
            entries.Add(FileEntry(path, bytes));
        }

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        Assert.Equal("PREFLIGHT_READY", manifest.GetProperty("status").GetString());
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        foreach (var (path, _, _) in files)
        {
            var bytes = sources[Nfc(path)].Bytes;
            var commit = await UploadAndCommitAsync(client, sid, token, fileIds[Nfc(path)], bytes, chunkSize);
            Assert.True(commit.IsSuccess, $"{path}: {commit.ErrorCode} {commit.ErrorMessage}");
            var outcome = commit.Body.GetProperty("outcome").GetString();
            Assert.True(outcome is "VERIFIED" or "RENAMED", $"{path} â†’ {outcome}");
        }

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal("COMPLETED", report.Status);
        AssertTransferInvariants(env, sources, report);

        // explicit final-path checks for the sanitization / normalization rules
        var dest = env.DestinationDir;
        Assert.True(File.Exists(Path.Combine(dest, "cafÃ©", "naÃ¯ve.txt")));
        Assert.True(File.Exists(Path.Combine(dest, "CON_.txt")));
        Assert.True(File.Exists(Path.Combine(dest, "trailing")));
        Assert.True(File.Exists(Path.Combine(dest, "README (2).txt")));
        Assert.True(File.Exists(Path.Combine(dest, "readme.txt")));
        Assert.False(File.Exists(Path.Combine(dest, "CON.txt")));
        // NFD must not survive: compare the *stored* entry names instead of probing
        // with an NFD path. APFS (macOS CI) is normalization-insensitive, so an NFD
        // Directory.Exists probe resolves the NFC directory and masks the check;
        // an ordinal comparison against the real directory entries cannot.
        // Non-ASCII literals use \u escapes (see file header).
        var storedNames = Directory.GetFileSystemEntries(dest)
            .Select(Path.GetFileName)
            .Where(n => n is not null)
            .ToList();
        Assert.DoesNotContain(storedNames,
            n => string.Equals(n, "cafe\u0301", StringComparison.Ordinal));   // NFD spelling absent
        Assert.Contains(storedNames,
            n => string.Equals(n, "caf\u00E9", StringComparison.Ordinal));             // NFC present
        Assert.Equal(Data(19, 5), File.ReadAllBytes(Path.Combine(dest, "readme.txt")));
        Assert.Equal(Data(20, 6), File.ReadAllBytes(Path.Combine(dest, "README (2).txt")));
    }

    [Fact]
    public async Task MultiBatchManifest_BeyondEntryCap_TransfersAll()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var entries = new List<Entry>();
        const int count = 1010; // crosses the 1000-entry batch cap
        for (var i = 0; i < count; i++)
        {
            var path = $"many/file-{i:D4}.dat";
            var bytes = Data(1000 + i, 8);
            AddSource(env, sources, path, bytes);
            entries.Add(FileEntry(path, bytes));
        }

        var (sid, token) = await CreateAndApproveAsync(client, entries);

        var batch0 = await client.SendManifestAsync(sid, token, entries.Take(1000).ToList(),
            final: false, digest: null, batchIndex: 0);
        Assert.True(batch0.IsSuccess, batch0.ErrorMessage);
        Assert.Equal("MANIFEST_RECEIVING", batch0.Body.GetProperty("status").GetString());
        Assert.True(batch0.Body.GetProperty("batchAccepted").GetBoolean());

        var batch1 = await client.SendManifestAsync(sid, token, entries.Skip(1000).ToList(),
            final: true, digest: DigestOf(entries), batchIndex: 1);
        Assert.True(batch1.IsSuccess, batch1.ErrorMessage);
        Assert.Equal("PREFLIGHT_READY", batch1.Body.GetProperty("status").GetString());
        Assert.Equal(DigestOf(entries), batch1.Body.GetProperty("manifestDigest").GetString());

        var fileIds = PlannedFileIds(batch0.Body);
        foreach (var kv in PlannedFileIds(batch1.Body))
            fileIds[kv.Key] = kv.Value;
        Assert.Equal(count, fileIds.Count);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        foreach (var e in entries)
        {
            var commit = await UploadAndCommitAsync(client, sid, token, fileIds[e.Path],
                sources[e.Path].Bytes, chunkSize);
            Assert.True(commit.IsSuccess, $"{e.Path}: {commit.ErrorCode}");
        }

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(count, report.Totals.Verified);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task Resume_StateReportsVerifiedChunks_AndReuploadIsIdempotent()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(31, 3 * Chunk + 100); // 4 chunks
        AddSource(env, sources, "big.iso", bytes);
        var entries = new List<Entry> { FileEntry("big.iso", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var fileId = fileIds["big.iso"];

        // send the first two chunks, then "lose the connection"
        for (var i = 0; i < 2; i++)
        {
            var chunk = bytes.AsMemory(i * chunkSize, chunkSize);
            var resp = await client.UploadChunkAsync(sid, token, fileId, i, chunk,
                TestEnv.HashBytes(chunk.Span));
            Assert.Equal("VERIFIED", resp.Body.GetProperty("status").GetString());
        }

        // reconnect: the receiver tells us exactly what is verified (SPEC Â§5 resume)
        var state = await client.GetStateAsync(sid, token);
        Assert.True(state.IsSuccess, state.ErrorMessage);
        Assert.Equal("TRANSFERRING", state.Body.GetProperty("status").GetString());
        var partial = state.Body.GetProperty("partial").EnumerateArray()
            .Single(p => p.GetProperty("path").GetString() == "big.iso");
        Assert.Equal(new[] { 0, 1 }, partial.GetProperty("verifiedChunks").EnumerateArray()
            .Select(x => x.GetInt32()).ToArray());
        Assert.Equal(2, partial.GetProperty("nextChunk").GetInt32());
        Assert.Equal(0, state.Body.GetProperty("completed").GetArrayLength());

        // re-validating the boundary chunk is idempotent (no byte re-sent: ALREADY_VERIFIED)
        var boundary = bytes.AsMemory(chunkSize, chunkSize);
        var redo = await client.UploadChunkAsync(sid, token, fileId, 1, boundary,
            TestEnv.HashBytes(boundary.Span));
        Assert.Equal("ALREADY_VERIFIED", redo.Body.GetProperty("status").GetString());

        // continue from the reported cursor, never re-sending verified chunks
        for (var i = 2; i < 4; i++)
        {
            var len = Math.Min(chunkSize, bytes.Length - i * chunkSize);
            var chunk = bytes.AsMemory(i * chunkSize, len);
            var resp = await client.UploadChunkAsync(sid, token, fileId, i, chunk,
                TestEnv.HashBytes(chunk.Span));
            Assert.Equal("VERIFIED", resp.Body.GetProperty("status").GetString());
        }

        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(bytes),
            bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var after = await client.GetStateAsync(sid, token);
        Assert.Single(after.Body.GetProperty("completed").EnumerateArray());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task Pause_RejectsChunks_ResumeAccepts()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(41, 2 * Chunk);
        AddSource(env, sources, "movie.bin", bytes);
        var entries = new List<Entry> { FileEntry("movie.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var fileId = fileIds["movie.bin"];

        var first = bytes.AsMemory(0, chunkSize);
        await client.UploadChunkAsync(sid, token, fileId, 0, first, TestEnv.HashBytes(first.Span));

        var pause = await client.PauseAsync(sid, token);
        Assert.Equal("PAUSED", pause.Body.GetProperty("status").GetString());

        var second = bytes.AsMemory(chunkSize, chunkSize);
        var rejected = await client.UploadChunkAsync(sid, token, fileId, 1, second,
            TestEnv.HashBytes(second.Span));
        Assert.Equal(409, rejected.Status);
        Assert.Equal("E_SESSION_STATE", rejected.ErrorCode);

        var resume = await client.ResumeAsync(sid, token);
        Assert.Equal("TRANSFERRING", resume.Body.GetProperty("status").GetString());

        var ok = await client.UploadChunkAsync(sid, token, fileId, 1, second,
            TestEnv.HashBytes(second.Span));
        Assert.Equal("VERIFIED", ok.Body.GetProperty("status").GetString());

        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(bytes),
            bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task Cancel_KeepsVerifiedFiles_PurgesIncompleteStaging()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var doneBytes = Data(51, 1000);
        var partialBytes = Data(52, 2 * Chunk);
        AddSource(env, sources, "done.txt", doneBytes);
        AddSource(env, sources, "partial.bin", partialBytes);
        var entries = new List<Entry>
        {
            FileEntry("done.txt", doneBytes),
            FileEntry("partial.bin", partialBytes),
        };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["done.txt"],
            doneBytes, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var chunk = partialBytes.AsMemory(0, chunkSize);
        await client.UploadChunkAsync(sid, token, fileIds["partial.bin"], 0, chunk,
            TestEnv.HashBytes(chunk.Span));

        var report = ReportOf(await client.CancelAsync(sid, token));
        Assert.Equal("CANCELLED", report.Status);

        // already-verified file stays in place; incomplete one never reaches a final path
        Assert.True(File.Exists(Path.Combine(env.DestinationDir, "done.txt")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "partial.bin")));
        Assert.Equal(TestEnv.HashBytes(doneBytes),
            TestEnv.HashFile(Path.Combine(env.DestinationDir, "done.txt")));

        var byPath = report.Items.ToDictionary(i => i.Path, StringComparer.Ordinal);
        Assert.Equal("VERIFIED", byPath["done.txt"].Outcome);
        Assert.Equal("FAILED", byPath["partial.bin"].Outcome);

        // staging is gone after cancel (SPEC Â§5)
        Assert.False(Directory.Exists(Path.Combine(env.DestinationDir, ".mac2win-staging", sid)));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task SourceSizeChange_ReturnsE_SOURCE_CHANGED_AndFlagsLedger()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(61, 4096);
        AddSource(env, sources, "mutating.txt", bytes);
        var entries = new List<Entry> { FileEntry("mutating.txt", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var chunk = bytes.AsMemory();
        await client.UploadChunkAsync(sid, token, fileIds["mutating.txt"], 0, chunk,
            TestEnv.HashBytes(chunk.Span));

        // sender declares a different size than the manifest â†’ receiver refuses to verify
        var commit = await client.CommitAsync(sid, token, fileIds["mutating.txt"],
            TestEnv.HashBytes(bytes), bytes.Length + 5, MtimeNs(SourceMtime));
        Assert.Equal(409, commit.Status);
        Assert.Equal("E_SOURCE_CHANGED", commit.ErrorCode);
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "mutating.txt")));

        var report = ReportOf(await client.CancelAsync(sid, token));
        var item = Assert.Single(report.Items);
        Assert.Equal("CHANGED_DURING_TRANSFER", item.Outcome);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task Conflict_WithoutResolution_IsRejectedBeforeAnyBytes()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var existing = Encoding.UTF8.GetBytes("existing content\n");
        File.WriteAllBytes(Path.Combine(env.DestinationDir, "readme.txt"), existing);

        var incoming = Data(71, 5);
        AddSource(env, sources, "readme.txt", incoming);
        var entries = new List<Entry> { FileEntry("readme.txt", incoming) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        Assert.Equal("CONFLICT", manifest.GetProperty("planned").EnumerateArray()
            .Single().GetProperty("action").GetString());
        Assert.Single(manifest.GetProperty("conflicts").EnumerateArray());

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.Equal(409, confirm.Status);
        Assert.Equal("E_CONFLICT_UNRESOLVED", confirm.ErrorCode);

        // nothing was overwritten or written while the conflict was unresolved
        Assert.Equal(existing, File.ReadAllBytes(Path.Combine(env.DestinationDir, "readme.txt")));
    }

    [Fact]
    public async Task Conflict_KeepBoth_RenamesAndPreservesOriginal()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var existing = Encoding.UTF8.GetBytes("old\n");
        File.WriteAllBytes(Path.Combine(env.DestinationDir, "readme.txt"), existing);

        var incoming = Data(72, 32);
        AddSource(env, sources, "readme.txt", incoming);
        var entries = new List<Entry> { FileEntry("readme.txt", incoming) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token,
            new Dictionary<string, string> { ["readme.txt"] = "KEEP_BOTH" });

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["readme.txt"],
            incoming, chunkSize);
        Assert.Equal("RENAMED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(existing, File.ReadAllBytes(Path.Combine(env.DestinationDir, "readme.txt")));
        Assert.Equal(incoming, File.ReadAllBytes(Path.Combine(env.DestinationDir, "readme (2).txt")));
        Assert.Equal("RENAMED", Assert.Single(report.Items).Outcome);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task Conflict_Replace_OverwritesOnlyAfterVerification()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var existing = Encoding.UTF8.GetBytes("old\n");
        File.WriteAllBytes(Path.Combine(env.DestinationDir, "readme.txt"), existing);

        var incoming = Data(73, 64);
        AddSource(env, sources, "readme.txt", incoming);
        var entries = new List<Entry> { FileEntry("readme.txt", incoming) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token,
            new Dictionary<string, string> { ["readme.txt"] = "REPLACE" });

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["readme.txt"],
            incoming, chunkSize);
        Assert.Equal("REPLACED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(incoming, File.ReadAllBytes(Path.Combine(env.DestinationDir, "readme.txt")));
        Assert.Equal("REPLACED", Assert.Single(report.Items).Outcome);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task SymlinkAndAppleMetadata_AreExcludedByPolicy_LedgerReconciles()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var ok = Data(81, 77);
        AddSource(env, sources, "ok.txt", ok);
        var dsStore = Data(82, 10);
        AddSource(env, sources, ".DS_Store", dsStore);
        var appleDouble = Data(83, 12);
        AddSource(env, sources, "._ok.txt", appleDouble);

        var entries = new List<Entry>
        {
            FileEntry("ok.txt", ok),
            FileEntry(".DS_Store", dsStore),
            FileEntry("._ok.txt", appleDouble),
            new(Nfc("link"), "symlink", 0, MtimeNs(SourceMtime), 120000, SymlinkTarget: "ok.txt"),
        };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var planned = manifest.GetProperty("planned").EnumerateArray()
            .ToDictionary(p => p.GetProperty("path").GetString()!, p => p.GetProperty("action").GetString()!);
        Assert.Equal("CREATE", planned["ok.txt"]);
        Assert.Equal("EXCLUDED_BY_POLICY", planned[".DS_Store"]);
        Assert.Equal("EXCLUDED_BY_POLICY", planned["._ok.txt"]);
        Assert.Equal("EXCLUDED_BY_POLICY", planned["link"]);

        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["ok.txt"], ok, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(4, report.Totals.Items);
        Assert.Equal(1, report.Totals.Verified);
        Assert.Equal(3, report.Totals.Excluded);
        var byPath = report.Items.ToDictionary(i => i.Path, StringComparer.Ordinal);
        Assert.Equal("EXCLUDED_BY_POLICY", byPath[".DS_Store"].Outcome);
        Assert.Equal("POLICY_DOT_DS_STORE", byPath[".DS_Store"].Reason);
        Assert.Equal("EXCLUDED_BY_POLICY", byPath["._ok.txt"].Outcome);
        Assert.Equal("EXCLUDED_BY_POLICY", byPath["link"].Outcome);
        Assert.Equal("POLICY_SYMLINK_NOT_PRESERVED", byPath["link"].Reason);

        // excluded content must never appear at the destination
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, ".DS_Store")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "._ok.txt")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "link")));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task VerifyAfterWriteDisabled_StillMatchesDeclaredHash()
    {
        await using var env = await TestEnv.StartAsync(o => { o.VerifyAfterWrite = false; return o; });
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(91, 2 * Chunk + 5);
        AddSource(env, sources, "streamed.bin", bytes);
        var entries = new List<Entry> { FileEntry("streamed.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["streamed.bin"],
            bytes, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task SenderDeclaredUnreadable_NeverTransfers()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var ok = Data(95, 10);
        AddSource(env, sources, "readable.txt", ok);
        var entries = new List<Entry>
        {
            FileEntry("readable.txt", ok),
            FileEntry("denied.txt", Array.Empty<byte>(), senderState: "UNREADABLE"),
            FileEntry("icloud.dat", Array.Empty<byte>(), senderState: "CLOUD_PLACEHOLDER"),
        };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        Assert.False(fileIds.ContainsKey("denied.txt"));
        Assert.False(fileIds.ContainsKey("icloud.dat"));
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var commit = await UploadAndCommitAsync(client, sid, token, fileIds["readable.txt"], ok, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(3, report.Totals.Items);
        Assert.Equal(1, report.Totals.Verified);
        Assert.Equal(1, report.Totals.Unreadable);
        Assert.Equal(1, report.Totals.CloudPlaceholder);
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "denied.txt")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "icloud.dat")));
        AssertTransferInvariants(env, sources, report);
    }
}
