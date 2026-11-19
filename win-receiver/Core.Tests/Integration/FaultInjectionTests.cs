using System.Text.Json;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// M3 fault-injection suite (SPEC §10): connection drops mid-chunk/manifest/rename,
/// duplicate and out-of-order chunks, latency/throttling, destination failures,
/// hard-kill of the receiver then resume (crash consistency), simulated sleep/wake,
/// PIN expiry/lockout, and source mutation during transfer. AUTOMATED level: real TLS,
/// real sockets, real files on loopback. Every transfer ends with the SPEC §10 invariants
/// asserted by <see cref="AssertTransferInvariants"/>. Non-ASCII path literals use \u
/// escapes so source encoding can never change meaning.
/// </summary>
public sealed class FaultInjectionTests
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

    private static Entry FileEntry(string path, byte[] data) =>
        new(Nfc(path), "file", data.Length, MtimeNs(SourceMtime), 420);

    private static string DigestOf(IEnumerable<Entry> entries) =>
        ManifestDigest.ComputeHex(entries.Select(e =>
            new ManifestDigest.Entry(Nfc(e.Path), e.Type, e.Size, e.MtimeUtcNs, e.Mode)));

    private static void AddSource(TestEnv env,
        Dictionary<string, (string Disk, byte[] Bytes)> sources, string path, byte[] bytes)
    {
        var rel = path.Replace('/', Path.DirectorySeparatorChar);
        var disk = Path.Combine(env.SourceDir, rel);
        Directory.CreateDirectory(Path.GetDirectoryName(disk)!);
        File.WriteAllBytes(disk, bytes);
        sources[Nfc(path)] = (disk, bytes);
    }

    private static async Task<(string Sid, string Token)> CreateAndApproveAsync(
        ProtocolTestClient client, IReadOnlyList<Entry> entries)
    {
        var files = entries.Count(e => e.Type == "file");
        var bytes = entries.Where(e => e.Type == "file").Sum(e => e.Size);
        var sid = await client.CreateSessionAsync(files, 0, bytes);
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

    private static async Task<int> ConfirmOkAsync(ProtocolTestClient client, string sid, string token)
    {
        var resp = await client.ConfirmAsync(sid, token);
        Assert.True(resp.IsSuccess, $"confirm: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        return resp.Body.GetProperty("chunkSize").GetInt32();
    }

    private static async Task<ApiResponse> UploadChunkOkAsync(ProtocolTestClient client,
        string sid, string token, string fileId, int index, ReadOnlyMemory<byte> chunk)
    {
        var resp = await client.UploadChunkAsync(sid, token, fileId, index, chunk,
            TestEnv.HashBytes(chunk.Span));
        Assert.True(resp.IsSuccess, $"chunk {index}: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        return resp;
    }

    private static async Task<ApiResponse> CommitOkAsync(ProtocolTestClient client, string sid,
        string token, string fileId, byte[] data)
    {
        var resp = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(data),
            data.Length, MtimeNs(SourceMtime));
        Assert.True(resp.IsSuccess, $"commit: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        return resp;
    }

    /// <summary>Uploads chunks [fromIndex..] then commits; asserts every step succeeds.</summary>
    private static async Task<ApiResponse> FinishFileAsync(ProtocolTestClient client, string sid,
        string token, string fileId, byte[] data, int chunkSize, int fromIndex = 0)
    {
        var chunkCount = data.Length == 0 ? 0 : (data.Length + chunkSize - 1) / chunkSize;
        for (var i = fromIndex; i < chunkCount; i++)
        {
            var offset = i * chunkSize;
            var len = Math.Min(chunkSize, data.Length - offset);
            await UploadChunkOkAsync(client, sid, token, fileId, i,
                data.AsMemory(offset, len));
        }
        return await CommitOkAsync(client, sid, token, fileId, data);
    }

    private static SessionReport ReportOf(ApiResponse resp)
    {
        Assert.True(resp.IsSuccess, $"report: {resp.Status} {resp.ErrorCode} {resp.ErrorMessage}");
        var el = resp.Body.TryGetProperty("report", out var r) ? r : resp.Body;
        return el.Deserialize<SessionReport>(Json)!;
    }

    /// <summary>The drop itself must fail the request — by exception or by non-2xx.</summary>
    private static async Task AssertDropsAsync(Func<Task<ApiResponse>> send)
    {
        try
        {
            var resp = await send();
            Assert.False(resp.IsSuccess,
                $"expected the fault-injected request to fail, got {resp.Status} {resp.ErrorCode}");
        }
        catch (Exception ex) when (ex is not Xunit.Sdk.XunitException)
        {
            // transport-level failure — the usual outcome of a mid-body abort
        }
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

        // no partial file exists anywhere under the destination (SPEC §5 atomic writes)
        var partials = Directory.Exists(env.DestinationDir)
            ? Directory.GetFiles(env.DestinationDir, "*.m2wpart", SearchOption.AllDirectories)
            : Array.Empty<string>();
        Assert.Empty(partials);

        // every file the report calls verified matches the source bytes on disk
        foreach (var item in report.Items)
        {
            if (item.Outcome is not ("VERIFIED" or "RENAMED" or "REPLACED")) continue;
            if (!sources.TryGetValue(Nfc(item.Path), out var src)) continue;
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

    // ------------------------------------------- drops: chunk / manifest / rename

    [Fact]
    public async Task TruncatedChunkUpload_ConnectionDropped_RetryVerifies()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(101, 2 * Chunk + 77); // three chunks
        AddSource(env, sources, "drop.bin", bytes);
        var entries = new List<Entry> { FileEntry("drop.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        // the connection dies halfway through chunk 0 (SPEC §10: drops mid-chunk)
        var chunk0 = bytes.AsMemory(0, chunkSize);
        await AssertDropsAsync(() => client.PutChunkTruncatedAsync(
            $"/v1/sessions/{sid}/files/{fileIds["drop.bin"]}/chunks/0",
            chunk0, TestEnv.HashBytes(chunk0.Span), token, bytesBeforeAbort: chunkSize / 2));

        // the session survived: a retry on a healthy connection verifies the chunk
        var retry = await client.UploadChunkAsync(sid, token, fileIds["drop.bin"], 0, chunk0,
            TestEnv.HashBytes(chunk0.Span));
        Assert.True(retry.IsSuccess, $"retry: {retry.Status} {retry.ErrorCode} {retry.ErrorMessage}");
        Assert.Equal("VERIFIED", retry.Body.GetProperty("status").GetString());

        var commit = await FinishFileAsync(client, sid, token, fileIds["drop.bin"], bytes,
            chunkSize, fromIndex: 1);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal("COMPLETED", report.Status);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task TruncatedManifestUpload_DropThenFullBatchAccepted()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(102, 4096);
        AddSource(env, sources, "manifest-drop.txt", bytes);
        var entries = new List<Entry> { FileEntry("manifest-drop.txt", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);

        // the manifest request dies mid-body: nothing may be half-applied
        var json = JsonSerializer.Serialize(new
        {
            batchIndex = 0,
            final = true,
            entries,
            manifestDigest = DigestOf(entries),
        }, Json);
        await AssertDropsAsync(() => client.PostJsonTruncatedAsync(
            $"/v1/sessions/{sid}/manifest", json, token, bytesBeforeAbort: json.Length / 2));

        // the same batch is then accepted in full (a half-applied batch would collide)
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        Assert.Equal("PREFLIGHT_READY", manifest.GetProperty("status").GetString());
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var commit = await FinishFileAsync(client, sid, token, fileIds["manifest-drop.txt"],
            bytes, chunkSize);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task ManifestBatchReplayed_AfterLostResponse_IsIdempotent()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var a = Data(103, 1000);
        var b = Data(104, 4096);
        AddSource(env, sources, "a.txt", a);
        AddSource(env, sources, "b.txt", b);
        var all = new List<Entry> { FileEntry("a.txt", a), FileEntry("b.txt", b) };
        var batch0 = all.Take(1).ToList();
        var batch1 = all.Skip(1).ToList();

        var (sid, token) = await CreateAndApproveAsync(client, all);

        var r0 = await client.SendManifestAsync(sid, token, batch0, final: false,
            digest: null, batchIndex: 0);
        Assert.True(r0.IsSuccess, $"batch0: {r0.Status} {r0.ErrorCode}");

        // response lost: the sender re-sends batch 0 — same fileIds, no duplicate items
        var replay0 = await client.SendManifestAsync(sid, token, batch0, final: false,
            digest: null, batchIndex: 0);
        Assert.True(replay0.IsSuccess, $"replay0: {replay0.Status} {replay0.ErrorCode}");
        Assert.Equal(r0.Body.GetProperty("planned").GetRawText(),
            replay0.Body.GetProperty("planned").GetRawText());
        Assert.Equal(batch0.Count,
            replay0.Body.GetProperty("planned").GetArrayLength());

        var r1 = await client.SendManifestAsync(sid, token, batch1, final: true,
            digest: DigestOf(all), batchIndex: 1);
        Assert.True(r1.IsSuccess, $"batch1: {r1.Status} {r1.ErrorCode}");
        Assert.Equal("PREFLIGHT_READY", r1.Body.GetProperty("status").GetString());

        // response lost again: the final batch replays with its full preflight payload
        var replay1 = await client.SendManifestAsync(sid, token, batch1, final: true,
            digest: DigestOf(all), batchIndex: 1);
        Assert.True(replay1.IsSuccess, $"replay1: {replay1.Status} {replay1.ErrorCode}");
        Assert.Equal("PREFLIGHT_READY", replay1.Body.GetProperty("status").GetString());
        Assert.Equal(DigestOf(all), replay1.Body.GetProperty("manifestDigest").GetString());

        // a stale batch index (skipping past accepted batches) is still rejected
        var stale = await client.SendManifestAsync(sid, token, batch0, final: false,
            digest: null, batchIndex: 0);
        Assert.Equal(409, stale.Status);
        Assert.Equal("E_SESSION_STATE", stale.ErrorCode);

        // planned fileIds span BOTH batches (each response covers only its own entries)
        var fileIds = PlannedFileIds(r0.Body);
        foreach (var kv in PlannedFileIds(r1.Body)) fileIds[kv.Key] = kv.Value;
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await FinishFileAsync(client, sid, token, fileIds["a.txt"], a, chunkSize);
        await FinishFileAsync(client, sid, token, fileIds["b.txt"], b, chunkSize);

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(2, report.Totals.Verified);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task ConfirmReplayed_AfterLostResponse_IsIdempotent()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(105, 4096);
        AddSource(env, sources, "confirm.txt", bytes);
        var entries = new List<Entry> { FileEntry("confirm.txt", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);

        var first = await client.ConfirmAsync(sid, token);
        Assert.True(first.IsSuccess, $"confirm: {first.Status} {first.ErrorCode}");

        // response lost: replaying confirm must not fail (names are already fixed)
        var replay = await client.ConfirmAsync(sid, token);
        Assert.True(replay.IsSuccess, $"replay confirm: {replay.Status} {replay.ErrorCode}");
        Assert.Equal("TRANSFERRING", replay.Body.GetProperty("status").GetString());

        var chunkSize = first.Body.GetProperty("chunkSize").GetInt32();
        await FinishFileAsync(client, sid, token, fileIds["confirm.txt"], bytes, chunkSize);
        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task CommitResponseLost_ReplayIsIdempotent_NoDoubleRename()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        // a backslash in the manifest path forces a sanitized rename (outcome RENAMED)
        var bytes = Data(106, 4096);
        var manifestPath = "bad\\name.txt";
        AddSource(env, sources, manifestPath, bytes);
        var entries = new List<Entry> { FileEntry(manifestPath, bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await UploadChunkOkAsync(client, sid, token, fileIds[manifestPath], 0, bytes);

        var commit = await CommitOkAsync(client, sid, token, fileIds[manifestPath], bytes);
        Assert.Equal("RENAMED", commit.Body.GetProperty("outcome").GetString());
        var finalPath = commit.Body.GetProperty("finalPath").GetString()!;
        Assert.True(File.Exists(finalPath));

        // the rename happened but the response was lost: the replay must return the same
        // outcome and must not move or duplicate anything (SPEC §10 drops mid-rename)
        var replay = await client.CommitAsync(sid, token, fileIds[manifestPath],
            TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(SourceMtime));
        Assert.True(replay.IsSuccess, $"replay commit: {replay.Status} {replay.ErrorCode}");
        Assert.Equal("RENAMED", replay.Body.GetProperty("outcome").GetString());
        Assert.Equal(finalPath, replay.Body.GetProperty("finalPath").GetString());

        // exactly one final file, and no stray sanitized sibling
        var destFiles = Directory.GetFiles(env.DestinationDir, "*", SearchOption.AllDirectories)
            .Where(f => !f.Contains(".mac2win-staging")).ToList();
        Assert.Equal(finalPath, Assert.Single(destFiles));

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(1, report.Totals.Renamed);
        AssertTransferInvariants(env, sources, report);
    }

    // ------------------------------------- duplicate / out-of-order / mutation

    [Fact]
    public async Task DuplicateChunkUpload_IsIdempotent()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(107, Chunk + 123);
        AddSource(env, sources, "dup.bin", bytes);
        var entries = new List<Entry> { FileEntry("dup.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        var chunk0 = bytes.AsMemory(0, chunkSize);
        var first = await UploadChunkOkAsync(client, sid, token, fileIds["dup.bin"], 0, chunk0);
        Assert.Equal("VERIFIED", first.Body.GetProperty("status").GetString());

        // the sender re-sends a chunk whose response was lost: same bytes ⇒ idempotent
        var dup = await client.UploadChunkAsync(sid, token, fileIds["dup.bin"], 0, chunk0,
            TestEnv.HashBytes(chunk0.Span));
        Assert.True(dup.IsSuccess, $"dup: {dup.Status} {dup.ErrorCode}");
        Assert.Equal("ALREADY_VERIFIED", dup.Body.GetProperty("status").GetString());

        var commit = await FinishFileAsync(client, sid, token, fileIds["dup.bin"], bytes,
            chunkSize, fromIndex: 1);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task OutOfOrderChunks_VerifyInAnyOrder()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(108, 3 * Chunk + 5); // four chunks
        AddSource(env, sources, "reordered.bin", bytes);
        var entries = new List<Entry> { FileEntry("reordered.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var fileId = fileIds["reordered.bin"];

        // deliver out of order: 2, 0, 3, 1 — the receiver keys chunks by index
        foreach (var i in new[] { 2, 0, 3, 1 })
        {
            var offset = i * chunkSize;
            var len = Math.Min(chunkSize, bytes.Length - offset);
            var resp = await UploadChunkOkAsync(client, sid, token, fileId, i,
                bytes.AsMemory(offset, len));
            Assert.Equal("VERIFIED", resp.Body.GetProperty("status").GetString());
        }

        var commit = await CommitOkAsync(client, sid, token, fileId, bytes);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task SourceMutated_RejectedForAlreadyVerifiedChunk_OriginalStillVerifies()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var original = Data(109, 4096);
        var mutated = Data(110, 4096); // same length, different bytes (in-place source edit)
        AddSource(env, sources, "mutable.txt", original);
        var entries = new List<Entry> { FileEntry("mutable.txt", original) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var fileId = fileIds["mutable.txt"];

        var chunk = original.AsMemory();
        await UploadChunkOkAsync(client, sid, token, fileId, 0, chunk);

        // the source changed under the transfer: a re-send with different content for an
        // already-verified chunk is refused (SPEC §5: restart that file and flag it)
        var resent = await client.UploadChunkAsync(sid, token, fileId, 0, mutated,
            TestEnv.HashBytes(mutated));
        Assert.Equal(409, resent.Status);
        Assert.Equal("E_SOURCE_CHANGED", resent.ErrorCode);

        // the verified copy was not overwritten: the original bytes still commit
        var commit = await CommitOkAsync(client, sid, token, fileId, original);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    // ------------------------------------------------ chaos proxy: sever / latency

    [Fact]
    public async Task ChaosProxy_SeverMidChunk_RetryCompletes()
    {
        await using var env = await TestEnv.StartAsync();
        await using var proxy = ChaosProxy.Start(env.Server.Port);
        using var client = new ProtocolTestClient(
            new Uri($"https://127.0.0.1:{proxy.Port}"), env.Server.CertFingerprint);
        await client.AuthenticateAsync(TestEnv.TestPin);
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(111, 2 * Chunk); // two full chunks
        AddSource(env, sources, "severed.bin", bytes);
        var entries = new List<Entry> { FileEntry("severed.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        var fileId = fileIds["severed.bin"];

        // sever once the connection is well into the 1 MiB chunk upload; reconnect first so
        // the PUT does not ride the pre-armed keep-alive connection (budget is per-connection)
        proxy.SeverAfterClientBytes = 64 * 1024;
        client.Reconnect(new Uri($"https://127.0.0.1:{proxy.Port}"));
        var chunk0 = bytes.AsMemory(0, chunkSize);
        await AssertDropsAsync(() => client.UploadChunkAsync(sid, token, fileId, 0, chunk0,
            TestEnv.HashBytes(chunk0.Span)));
        proxy.SeverAfterClientBytes = null;

        // a fresh connection retries the same chunk (verified or not, both are correct)
        var retry = await client.UploadChunkAsync(sid, token, fileId, 0, chunk0,
            TestEnv.HashBytes(chunk0.Span));
        Assert.True(retry.IsSuccess, $"retry: {retry.Status} {retry.ErrorCode} {retry.ErrorMessage}");
        Assert.Contains(retry.Body.GetProperty("status").GetString(),
            new[] { "VERIFIED", "ALREADY_VERIFIED" });

        var commit = await FinishFileAsync(client, sid, token, fileId, bytes, chunkSize,
            fromIndex: 1);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task ChaosProxy_LatencyAndThrottling_TransferStillVerifies()
    {
        await using var env = await TestEnv.StartAsync();
        await using var proxy = ChaosProxy.Start(env.Server.Port);
        proxy.Latency = TimeSpan.FromMilliseconds(2);
        proxy.ThrottleClientBytesPerSecond = 4 * 1024 * 1024; // 4 MiB/s uplink cap
        using var client = new ProtocolTestClient(
            new Uri($"https://127.0.0.1:{proxy.Port}"), env.Server.CertFingerprint);
        await client.AuthenticateAsync(TestEnv.TestPin);
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var big = Data(112, 1500 * 1024);
        var small = Data(113, 8 * 1024);
        AddSource(env, sources, "slow.bin", big);
        AddSource(env, sources, "slow.txt", small);
        var entries = new List<Entry> { FileEntry("slow.bin", big), FileEntry("slow.txt", small) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        await FinishFileAsync(client, sid, token, fileIds["slow.bin"], big, chunkSize);
        await FinishFileAsync(client, sid, token, fileIds["slow.txt"], small, chunkSize);

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(2, report.Totals.Verified);
        AssertTransferInvariants(env, sources, report);
    }

    // --------------------------------------- hard kill / resume / sleep-wake

    [Fact]
    public async Task HardKillReceiver_DuringTransfer_ResumeFromState_Completes()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var aBytes = Data(114, 1000);          // committed before the kill
        var bBytes = Data(115, 2 * Chunk + 5); // partially uploaded before the kill
        var cBytes = Data(116, 4096);          // untouched before the kill
        AddSource(env, sources, "a.txt", aBytes);
        AddSource(env, sources, "b.bin", bBytes);
        AddSource(env, sources, "c.dat", cBytes);
        var entries = new List<Entry>
        {
            FileEntry("a.txt", aBytes), FileEntry("b.bin", bBytes), FileEntry("c.dat", cBytes),
        };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);

        await FinishFileAsync(client, sid, token, fileIds["a.txt"], aBytes, chunkSize);
        await UploadChunkOkAsync(client, sid, token, fileIds["b.bin"], 0,
            bBytes.AsMemory(0, chunkSize));

        // ——— hard kill of the receiver, then a fresh start over the same tree ———
        await env.RestartServerAsync();

        // the sender reconnects: its device identity survived (devices.json) — no re-pair
        client.Reconnect(env.BaseUri);
        await client.ReauthenticateAsync();

        // the session and its token survived (session.json): no re-approval
        var (status, token2) = await client.GetSessionAsync(sid);
        Assert.Equal("TRANSFERRING", status);
        Assert.Equal(token, token2);

        // resume state: a.txt completed, b.bin continues at chunk 1
        var state = await client.GetStateAsync(sid, token);
        Assert.True(state.IsSuccess, $"state: {state.Status} {state.ErrorCode}");
        Assert.Equal("TRANSFERRING", state.Body.GetProperty("status").GetString());
        var completed = state.Body.GetProperty("completed").EnumerateArray()
            .Select(e => e.GetProperty("path").GetString()).ToList();
        Assert.Equal("a.txt", Assert.Single(completed));
        var partial = state.Body.GetProperty("partial").EnumerateArray()
            .Single(e => e.GetProperty("path").GetString() == "b.bin");
        Assert.Equal(1, partial.GetProperty("nextChunk").GetInt32());
        Assert.Equal(new[] { 0 },
            partial.GetProperty("verifiedChunks").EnumerateArray().Select(x => x.GetInt32()));

        // finish b (chunk 0 is NOT re-sent — resume skips verified chunks, SPEC §9)
        var commitB = await FinishFileAsync(client, sid, token, fileIds["b.bin"], bBytes,
            chunkSize, fromIndex: 1);
        Assert.Equal("VERIFIED", commitB.Body.GetProperty("outcome").GetString());
        var commitC = await FinishFileAsync(client, sid, token, fileIds["c.dat"], cBytes,
            chunkSize);
        Assert.Equal("VERIFIED", commitC.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal("COMPLETED", report.Status);
        Assert.Equal(3, report.Totals.Verified);
        Assert.Equal(aBytes.Length + bBytes.Length + cBytes.Length, report.Totals.BytesVerified);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task HardKillReceiver_DuringManifest_ReplayedBatchAcceptedAfterRestart()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var a = Data(117, 4096);
        var b = Data(118, 1000);
        AddSource(env, sources, "first.txt", a);
        AddSource(env, sources, "second.txt", b);
        var all = new List<Entry> { FileEntry("first.txt", a), FileEntry("second.txt", b) };
        var batch0 = all.Take(1).ToList();
        var batch1 = all.Skip(1).ToList();

        var (sid, token) = await CreateAndApproveAsync(client, all);
        var r0 = await client.SendManifestAsync(sid, token, batch0, final: false,
            digest: null, batchIndex: 0);
        Assert.True(r0.IsSuccess, $"batch0: {r0.Status} {r0.ErrorCode}");

        // ——— hard kill right after batch 0 was accepted ———
        await env.RestartServerAsync();
        client.Reconnect(env.BaseUri);
        await client.ReauthenticateAsync();

        var (status, token2) = await client.GetSessionAsync(sid);
        Assert.Equal("MANIFEST_RECEIVING", status);
        Assert.Equal(token, token2);

        // the sender never saw batch 0's response: the replay is accepted idempotently
        // with the SAME fileIds rebuilt from the persisted snapshot
        var replay0 = await client.SendManifestAsync(sid, token, batch0, final: false,
            digest: null, batchIndex: 0);
        Assert.True(replay0.IsSuccess, $"replay0: {replay0.Status} {replay0.ErrorCode} {replay0.ErrorMessage}");
        Assert.Equal(r0.Body.GetProperty("planned").GetRawText(),
            replay0.Body.GetProperty("planned").GetRawText());

        var r1 = await client.SendManifestAsync(sid, token, batch1, final: true,
            digest: DigestOf(all), batchIndex: 1);
        Assert.True(r1.IsSuccess, $"batch1: {r1.Status} {r1.ErrorCode}");
        Assert.Equal("PREFLIGHT_READY", r1.Body.GetProperty("status").GetString());

        var fileIds = PlannedFileIds(r0.Body);
        foreach (var kv in PlannedFileIds(r1.Body)) fileIds[kv.Key] = kv.Value;
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await FinishFileAsync(client, sid, token, fileIds["first.txt"], a, chunkSize);
        await FinishFileAsync(client, sid, token, fileIds["second.txt"], b, chunkSize);

        var report = ReportOf(await client.CompleteAsync(sid, token));
        Assert.Equal(2, report.Totals.Verified);
        AssertTransferInvariants(env, sources, report);
    }

    [Fact]
    public async Task SleepWake_ReconnectWithinIdleWindow_ResumeWorks()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.IdleTimeout = TimeSpan.FromSeconds(30);
            return o;
        });
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(119, 2 * Chunk);
        AddSource(env, sources, "sleeper.bin", bytes);
        var entries = new List<Entry> { FileEntry("sleeper.bin", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await UploadChunkOkAsync(client, sid, token, fileIds["sleeper.bin"], 0,
            bytes.AsMemory(0, chunkSize));

        // the Mac sleeps: every connection drops and time passes (inside the idle window)
        client.Reconnect(env.BaseUri);
        await Task.Delay(1200);

        // wake: the session is still alive with its progress intact
        var state = await client.GetStateAsync(sid, token);
        Assert.True(state.IsSuccess, $"state: {state.Status} {state.ErrorCode} {state.ErrorMessage}");
        Assert.Equal("TRANSFERRING", state.Body.GetProperty("status").GetString());
        var partial = Assert.Single(state.Body.GetProperty("partial").EnumerateArray());
        Assert.Equal(1, partial.GetProperty("nextChunk").GetInt32());

        var commit = await FinishFileAsync(client, sid, token, fileIds["sleeper.bin"], bytes,
            chunkSize, fromIndex: 1);
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var report = ReportOf(await client.CompleteAsync(sid, token));
        AssertTransferInvariants(env, sources, report);
    }

    // ------------------------------------------------------- PIN faults

    [Fact]
    public async Task ExpiredPin_PairingRejected_EvenWithCorrectPin()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            // test-only knob; protocol default 5 min unchanged.
            // 250 ms was too tight: the window opened when the PIN was minted inside
            // StartAsync, so a cold start (TLS handshake + JIT) could burn it before the
            // first Pair call — observed failing on a loaded CI runner. 2 s still proves
            // expiry while leaving headroom for start-up; the assertions are unchanged.
            o.PinMaxAge = TimeSpan.FromSeconds(2);
            return o;
        });
        using var client = env.CreateClient();

        var fresh = await client.PairRawAsync(TestEnv.TestPin);
        Assert.True(fresh.IsSuccess, $"first pair: {fresh.Status} {fresh.ErrorCode}");

        await Task.Delay(2500); // the displayed PIN ages out

        var expired = await client.PairRawAsync(TestEnv.TestPin); // correct, but too late
        Assert.Equal(403, expired.Status);
        Assert.Equal("E_PIN_EXPIRED", expired.ErrorCode);
        Assert.Null(client.DeviceId); // no device was granted
    }

    [Fact]
    public async Task PinLockoutBackoffExpires_ThenCorrectPinPairs()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        for (var i = 1; i <= 4; i++)
        {
            var wrong = await client.PairRawAsync("111111");
            Assert.Equal("E_PIN_INVALID", wrong.ErrorCode);
        }
        var fifth = await client.PairRawAsync("111111");
        Assert.Equal(429, fifth.Status);
        Assert.Equal("E_PIN_LOCKED", fifth.ErrorCode);

        // first escalating backoff is 1 s (SPEC §4: 1s, 2s, 4s, 8s, 16s)
        await Task.Delay(1100);
        var afterBackoff = await client.PairRawAsync(TestEnv.TestPin);
        Assert.True(afterBackoff.IsSuccess,
            $"pair after backoff: {afterBackoff.Status} {afterBackoff.ErrorCode}");
        // PairRawAsync doesn't self-assign DeviceId (PairAsync does); assert the grant itself
        Assert.False(string.IsNullOrEmpty(
            afterBackoff.Body.GetProperty("deviceId").GetString()));
    }

    // ------------------------------------------------ destination failure

    [Fact]
    public async Task DestinationRenameFails_NoPartialAtFinalPath_LedgerFails()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();
        var sources = new Dictionary<string, (string Disk, byte[] Bytes)>(StringComparer.Ordinal);

        var bytes = Data(120, 4096);
        AddSource(env, sources, "target.dat", bytes);
        var entries = new List<Entry> { FileEntry("target.dat", bytes) };

        var (sid, token) = await CreateAndApproveAsync(client, entries);
        var manifest = await SendFinalManifestAsync(client, sid, token, entries);
        var fileIds = PlannedFileIds(manifest);
        var chunkSize = await ConfirmOkAsync(client, sid, token);
        await UploadChunkOkAsync(client, sid, token, fileIds["target.dat"], 0, bytes);

        // a directory squats the final path between planning and the atomic rename
        // (the "disk full / destination failure" class of faults, SPEC §10)
        Directory.CreateDirectory(Path.Combine(env.DestinationDir, "target.dat"));

        var commit = await client.CommitAsync(sid, token, fileIds["target.dat"],
            TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal(500, commit.Status);
        Assert.Equal("E_DESTINATION_ERROR", commit.ErrorCode);
        Assert.False(commit.Body.GetProperty("error").GetProperty("retryable").GetBoolean());

        // the squatter is untouched and no .m2wpart ever appears at the final path
        Assert.True(Directory.Exists(Path.Combine(env.DestinationDir, "target.dat")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "target.dat")));

        // the ledger still reconciles: the item fails terminally, staging is purged
        var report = ReportOf(await client.CancelAsync(sid, token));
        Assert.Equal("CANCELLED", report.Status);
        Assert.Equal("FAILED", Assert.Single(report.Items).Outcome);
        AssertTransferInvariants(env, sources, report);
    }
}
