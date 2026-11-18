using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// M4 receiver-UI support APIs (SPEC §8): the configured default conflict policy must
/// resolve conflicts the sender left unasked, and the local-only session info/report
/// accessors must back the progress list, history, and exportable report. AUTOMATED —
/// real TLS, real sockets, real files, same invariants as the transfer suite.
/// </summary>
public sealed class UiSupportTests
{
    private const int Chunk = 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly DateTime SourceMtime = new(2024, 5, 1, 12, 0, 0, DateTimeKind.Utc);

    private static byte[] Data(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string MtimeNs(DateTime utc) =>
        ((utc - DateTime.UnixEpoch).Ticks * 100L).ToString();

    private static Entry FileEntry(string path, byte[] data) =>
        new(path, "file", data.Length, MtimeNs(SourceMtime), 420);

    private static string DigestOf(IEnumerable<Entry> entries) =>
        ManifestDigest.ComputeHex(entries.Select(e =>
            new ManifestDigest.Entry(e.Path, e.Type, e.Size, e.MtimeUtcNs, e.Mode)));

    // ------------------------------------------------- default conflict policy

    [Theory]
    [InlineData("REPLACE", "REPLACED")]
    [InlineData("SKIP", "SKIPPED_BY_USER")]
    [InlineData("KEEP_BOTH", "RENAMED")]
    public async Task SenderOmitsApplyToAll_ReceiverDefaultResolvesConflict(
        string defaultPolicy, string expectedOutcome)
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.DefaultConflictPolicy = defaultPolicy;
            return o;
        });
        var client = await env.AuthenticatedClientAsync();

        var existing = Encoding.UTF8.GetBytes("old\n");
        File.WriteAllBytes(Path.Combine(env.DestinationDir, "readme.txt"), existing);

        var incoming = Data(72, 64);
        File.WriteAllBytes(Path.Combine(env.SourceDir, "readme.txt"), incoming);
        var entries = new List<Entry> { FileEntry("readme.txt", incoming) };

        var sid = await client.CreateSessionAsync(1, 0, incoming.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess);
        Assert.Single(manifest.Body.GetProperty("conflicts").EnumerateArray());

        // the sender omits applyToAllDefault entirely (protocol §2.8 optional field)
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess,
            $"confirm: {confirm.Status} {confirm.ErrorCode} {confirm.ErrorMessage}");

        // echo in the confirm response tells the sender what the receiver applied
        var echo = confirm.Body.TryGetProperty("conflictResolutions", out var echoEl)
            ? echoEl.Deserialize<Dictionary<string, string>>(Json)!
            : new Dictionary<string, string>(StringComparer.Ordinal);
        Assert.Equal(defaultPolicy, Assert.Single(echo).Value);

        string? fileId = null;
        foreach (var p in manifest.Body.GetProperty("planned").EnumerateArray())
            if (p.TryGetProperty("fileId", out var fid)) fileId = fid.GetString();
        Assert.NotNull(fileId);

        // SKIPped files must never be uploaded — only REPLACE/RENAME write data
        if (expectedOutcome != "SKIPPED_BY_USER")
        {
            for (var i = 0; i < incoming.Length; i += Chunk)
            {
                var len = Math.Min(Chunk, incoming.Length - i);
                var chunkBytes = incoming.AsMemory(i, len);
                var chunk = await client.UploadChunkAsync(sid, token, fileId!, i / Chunk,
                    chunkBytes, TestEnv.HashBytes(chunkBytes.Span));
                Assert.True(chunk.IsSuccess);
            }
            var commit = await client.CommitAsync(sid, token, fileId!,
                TestEnv.HashBytes(incoming), incoming.Length, MtimeNs(SourceMtime));
            Assert.Equal(expectedOutcome, commit.Body.GetProperty("outcome").GetString());
        }

        var reportResp = await client.CompleteAsync(sid, token);
        Assert.True(reportResp.IsSuccess);
        var report = reportResp.Body.TryGetProperty("report", out var r)
            ? r : reportResp.Body;
        Assert.Equal(expectedOutcome,
            Assert.Single(report.Deserialize<SessionReport>(Json)!.Items).Outcome);

        // destination end state matches the policy
        var dst = Path.Combine(env.DestinationDir, "readme.txt");
        var renamed = Path.Combine(env.DestinationDir, "readme (2).txt");
        switch (expectedOutcome)
        {
            case "REPLACED":
                Assert.Equal(incoming, File.ReadAllBytes(dst));
                break;
            case "SKIPPED":
                Assert.Equal(existing, File.ReadAllBytes(dst));
                break;
            case "RENAMED":
                Assert.Equal(existing, File.ReadAllBytes(dst));
                Assert.Equal(incoming, File.ReadAllBytes(renamed));
                break;
        }
    }

    [Fact]
    public async Task SenderExplicitApplyToAll_OverridesReceiverDefault()
    {
        // receiver default = REPLACE, sender explicitly says ASK → unresolved conflict
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.DefaultConflictPolicy = "REPLACE";
            return o;
        });
        var client = await env.AuthenticatedClientAsync();

        File.WriteAllBytes(Path.Combine(env.DestinationDir, "readme.txt"),
            Encoding.UTF8.GetBytes("old\n"));
        var incoming = Data(73, 16);
        File.WriteAllBytes(Path.Combine(env.SourceDir, "readme.txt"), incoming);
        var entries = new List<Entry> { FileEntry("readme.txt", incoming) };

        var sid = await client.CreateSessionAsync(1, 0, incoming.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess);

        var confirm = await client.ConfirmAsync(sid, token, applyToAll: "ASK");
        Assert.Equal(409, confirm.Status);
        Assert.Equal("E_CONFLICT_UNRESOLVED", confirm.ErrorCode);
    }

    [Fact]
    public async Task DefaultPolicy_AppliesOnlyToConflicts_NotToCleanCreates()
    {
        // a clean transfer with DefaultConflictPolicy=REPLACE must not perturb anything
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.DefaultConflictPolicy = "REPLACE";
            return o;
        });
        var client = await env.AuthenticatedClientAsync();

        var bytes = Data(74, 2048);
        File.WriteAllBytes(Path.Combine(env.SourceDir, "fresh.txt"), bytes);
        var entries = new List<Entry> { FileEntry("fresh.txt", bytes) };

        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess);
        Assert.Empty(manifest.Body.GetProperty("conflicts").EnumerateArray());

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess);
        var fileId = manifest.Body.GetProperty("planned")[0].GetProperty("fileId").GetString()!;
        var chunk = await client.UploadChunkAsync(sid, token, fileId, 0, bytes,
            TestEnv.HashBytes(bytes));
        Assert.True(chunk.IsSuccess);
        var commit = await client.CommitAsync(sid, token, fileId,
            TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var reportResp = await client.CompleteAsync(sid, token);
        Assert.True(reportResp.IsSuccess);
        Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(env.DestinationDir, "fresh.txt")));
    }

    // ------------------------------------------------- session info + reports

    [Fact]
    public async Task SessionInfos_TrackProgressDuringTransfer_AndReportAfter()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();

        Assert.Empty(env.Server.GetSessionInfos());

        var bytes = Data(81, 3 * 1024 * 1024); // 3 MiB = 3 chunks at 1 MiB
        File.WriteAllBytes(Path.Combine(env.SourceDir, "big.bin"), bytes);
        var entries = new List<Entry> { FileEntry("big.bin", bytes) };

        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);

        // awaiting approval: progress row exists with probe totals, report not yet available
        // (auto-approve handler runs async, so status may already be MANIFEST_RECEIVING)
        var info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal(sid, info.Id);
        Assert.Contains(info.Status, new[] { "AWAITING_APPROVAL", "MANIFEST_RECEIVING" });
        Assert.Equal(1, info.FilesTotal);
        Assert.Equal(bytes.Length, info.BytesTotal);
        Assert.Equal(0, info.BytesReceived);
        Assert.Null(env.Server.GetSessionReport(sid));

        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess);
        var fileId = manifest.Body.GetProperty("planned")[0].GetProperty("fileId").GetString()!;

        // preflight done but not confirmed: still zero received bytes
        info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal(0, info.BytesReceived);
        Assert.Equal(1, info.FilesTotal);
        Assert.Null(env.Server.GetSessionReport(sid));

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess);

        // two of three chunks verified → in-flight progress, still no report
        for (var i = 0; i < 2; i++)
        {
            var offset = i * Chunk;
            var len = Math.Min(Chunk, bytes.Length - offset);
            var chunkBytes = bytes.AsMemory(offset, len);
            var chunk = await client.UploadChunkAsync(sid, token, fileId, i, chunkBytes,
                TestEnv.HashBytes(chunkBytes.Span));
            Assert.True(chunk.IsSuccess);
        }
        info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal("TRANSFERRING", info.Status);
        Assert.Equal(2L * Chunk, info.BytesReceived);
        Assert.Equal(bytes.Length, info.BytesTotal);
        Assert.Equal(0, info.FilesCompleted);
        Assert.Null(env.Server.GetSessionReport(sid));

        // finish: third chunk + commit + complete
        var lastOffset = 2 * Chunk;
        var lastLen = bytes.Length - lastOffset;
        var lastBytes = bytes.AsMemory(lastOffset, lastLen);
        var last = await client.UploadChunkAsync(sid, token, fileId, 2, lastBytes,
            TestEnv.HashBytes(lastBytes.Span));
        Assert.True(last.IsSuccess);
        var commit = await client.CommitAsync(sid, token, fileId,
            TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal(1, info.FilesCompleted);
        Assert.Equal(bytes.Length, info.BytesReceived);

        var reportResp = await client.CompleteAsync(sid, token);
        Assert.True(reportResp.IsSuccess);

        info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal("COMPLETED", info.Status);
        Assert.Equal(bytes.Length, info.BytesReceived);

        // terminal session now exposes a report for history/export
        var report = env.Server.GetSessionReport(sid);
        Assert.NotNull(report);
        Assert.Equal(1, report!.Totals.Verified);
        Assert.Equal(bytes.Length, report.Totals.BytesVerified);
        Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(env.DestinationDir, "big.bin")));
    }

    [Fact]
    public async Task SessionReport_NullForUnknownOrLiveSession()
    {
        await using var env = await TestEnv.StartAsync();
        var client = await env.AuthenticatedClientAsync();

        Assert.Null(env.Server.GetSessionReport("nope"));

        var bytes = Data(82, 128);
        File.WriteAllBytes(Path.Combine(env.SourceDir, "a.txt"), bytes);
        var entries = new List<Entry> { FileEntry("a.txt", bytes) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        Assert.Null(env.Server.GetSessionReport(sid)); // awaiting approval → live, no report
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess);
        Assert.Null(env.Server.GetSessionReport(sid)); // still live
    }

    [Fact]
    public async Task DeniedSession_KeepsInfoRow_AndExposesDeniedReport()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.ApprovalHandler = (_, _) => Task.FromResult(ApprovalDecision.Deny);
            return o;
        });
        var client = await env.AuthenticatedClientAsync();

        var sid = await client.CreateSessionAsync(1, 0, 10);
        var resp = await client.AwaitDenialAsync(sid);

        var info = Assert.Single(env.Server.GetSessionInfos());
        Assert.Equal(sid, info.Id);
        Assert.Equal("DENIED", info.Status);

        var report = env.Server.GetSessionReport(sid);
        Assert.NotNull(report);
        Assert.Equal("DENIED", report!.Status);
    }
}
