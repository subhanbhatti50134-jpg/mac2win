using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// Security and pairing integration tests (M1 subset of M2): PIN lockout, bearer
/// enforcement, hostile-path rejection, destination resource limits, and the safe
/// default that a receiver without an approval handler denies everything (SPEC §7).
/// Real TLS + real sockets (AUTOMATED).
/// </summary>
public sealed class AuthAndSecurityTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly DateTime SourceMtime = new(2024, 5, 1, 12, 0, 0, DateTimeKind.Utc);

    private static string MtimeNs(DateTime utc) =>
        ((utc - DateTime.UnixEpoch).Ticks * 100L).ToString();

    private static Entry FileEntry(string path, long size) =>
        new(path.Normalize(System.Text.NormalizationForm.FormC), "file", size,
            MtimeNs(SourceMtime), 420);

    private static string DigestOf(IEnumerable<Entry> entries) =>
        ManifestDigest.ComputeHex(entries.Select(e =>
            new ManifestDigest.Entry(e.Path, e.Type, e.Size, e.MtimeUtcNs, e.Mode)));

    // --------------------------------------------------------------------- PIN

    [Fact]
    public async Task WrongPin_ReturnsE_PIN_INVALID()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        var resp = await client.PairRawAsync("000000");
        Assert.Equal(403, resp.Status);
        Assert.Equal("E_PIN_INVALID", resp.ErrorCode);
        Assert.True(resp.Body.GetProperty("error").GetProperty("retryable").GetBoolean());
        Assert.Null(client.DeviceId);
    }

    [Fact]
    public async Task FiveFailedAttempts_ThenE_PIN_LOCKED()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        for (var i = 1; i <= 4; i++)
        {
            var resp = await client.PairRawAsync("111111");
            Assert.Equal(403, resp.Status);
            Assert.Equal("E_PIN_INVALID", resp.ErrorCode);
        }

        var fifth = await client.PairRawAsync("111111");
        Assert.Equal(429, fifth.Status);
        Assert.Equal("E_PIN_LOCKED", fifth.ErrorCode);
        Assert.True(fifth.Body.GetProperty("error").GetProperty("retryable").GetBoolean());

        // the correct PIN is refused too while the backoff is active (SPEC §4)
        var duringLockout = await client.PairRawAsync(TestEnv.TestPin);
        Assert.Equal(429, duringLockout.Status);
        Assert.Equal("E_PIN_LOCKED", duringLockout.ErrorCode);
    }

    [Fact]
    public async Task Health_RequiresNoAuth_AndAdvertisesPinnedFingerprint()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        var health = await client.GetAsync("/v1/health");
        Assert.True(health.IsSuccess);
        Assert.Equal(1, health.Body.GetProperty("protocolVersion").GetInt32());
        Assert.Equal(env.Server.CertFingerprint,
            health.Body.GetProperty("certFingerprintSha256").GetString());
        Assert.Equal("TEST-PC", health.Body.GetProperty("deviceName").GetString());
        Assert.False(string.IsNullOrEmpty(health.Body.GetProperty("serverNonce").GetString()));
    }

    [Fact]
    public async Task CertificatePinMismatch_IsRejectedByTheClient()
    {
        await using var env = await TestEnv.StartAsync();
        // a client pinning the WRONG fingerprint must not be able to talk to the server:
        // the TLS handshake itself fails (no accept-all path anywhere, SPEC §7)
        using var client = new ProtocolTestClient(env.BaseUri,
            new string('0', 64));
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("/v1/health"));
        Assert.NotNull(ex.InnerException); // AuthenticationException from the pin check
    }

    // ----------------------------------------------------------------- tokens

    [Fact]
    public async Task MissingBearer_Returns401E_UNAUTHORIZED()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var resp = await client.GetAsync("/v1/destination"); // no Authorization header
        Assert.Equal(401, resp.Status);
        Assert.Equal("E_UNAUTHORIZED", resp.ErrorCode);
    }

    [Fact]
    public async Task SessionEndpoints_RequireSessionToken_NotDeviceToken()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[10];
        var sid = await client.CreateSessionAsync(1, 0, 10);

        // the device token is deliberately NOT a session token (protocol §3.2)
        var resp = await client.SendManifestAsync(sid, client.DeviceToken!,
            new List<Entry> { FileEntry("x.txt", 10) }, final: true, digest: null);
        Assert.Equal(401, resp.Status);
        Assert.Equal("E_UNAUTHORIZED", resp.ErrorCode);
        _ = bytes;
    }

    [Fact]
    public async Task UnknownSession_Returns404E_SESSION_NOT_FOUND()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var resp = await client.GetAsync("/v1/sessions/00000000-0000-0000-0000-000000000000",
            client.DeviceToken);
        Assert.Equal(404, resp.Status);
        Assert.Equal("E_SESSION_NOT_FOUND", resp.ErrorCode);
    }

    [Fact]
    public async Task ApprovalHandlerMissing_SessionIsDenied()
    {
        // SPEC §7 safe default: no wired approval UI ⇒ nothing is ever accepted
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.ApprovalHandler = null;
            return o;
        });
        using var client = await env.AuthenticatedClientAsync();

        var sid = await client.CreateSessionAsync(1, 0, 10);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        string status = "AWAITING_APPROVAL";
        while (DateTimeOffset.UtcNow < deadline)
        {
            var (s, _) = await client.GetSessionAsync(sid);
            status = s;
            if (status is "DENIED" or "EXPIRED") break;
            await Task.Delay(25);
        }
        Assert.Equal("DENIED", status);
    }

    // ------------------------------------------------------------ hostile paths

    [Fact]
    public async Task PathTraversalManifest_IsRejected_AndNothingIsWrittenOutsideDestination()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var okBytes = new byte[4];
        new Random(123).NextBytes(okBytes);
        var hostile = new List<Entry>
        {
            FileEntry("../../evil1.txt", 4),
            FileEntry("/abs/evil2.txt", 4),
            FileEntry("C:/Windows/evil3.txt", 4),
            FileEntry("\\\\server\\share\\evil4.txt", 4),
            FileEntry("deep/../../../evil5.txt", 4),
            FileEntry("ok.txt", 4),
        };

        var sid = await client.CreateSessionAsync(6, 0, 24);
        var token = await client.AwaitApprovalAsync(sid);
        var digest = DigestOf(hostile);
        var manifest = await client.SendManifestAsync(sid, token, hostile, final: true, digest: digest);
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var planned = manifest.Body.GetProperty("planned").EnumerateArray()
            .ToDictionary(p => p.GetProperty("path").GetString()!,
                p => (Action: p.GetProperty("action").GetString()!,
                      Reason: p.TryGetProperty("reason", out var r) ? r.GetString() : null));
        Assert.Equal("PATH_TRAVERSAL", planned["../../evil1.txt"].Reason);
        Assert.Equal("ROOTED", planned["/abs/evil2.txt"].Reason);
        Assert.Equal("DRIVE_LETTER", planned["C:/Windows/evil3.txt"].Reason);
        Assert.Equal("UNC", planned["\\\\server\\share\\evil4.txt"].Reason);
        Assert.Equal("PATH_TRAVERSAL", planned["deep/../../../evil5.txt"].Reason);
        Assert.Equal("CREATE", planned["ok.txt"].Action);
        Assert.Equal(5, manifest.Body.GetProperty("rejected").GetArrayLength());

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);

        var fileId = manifest.Body.GetProperty("planned").EnumerateArray()
            .Single(p => p.GetProperty("path").GetString() == "ok.txt")
            .GetProperty("fileId").GetString()!;
        var chunkResp = await client.UploadChunkAsync(sid, token, fileId, 0, okBytes,
            TestEnv.HashBytes(okBytes));
        Assert.Equal("VERIFIED", chunkResp.Body.GetProperty("status").GetString());
        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(okBytes),
            okBytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var complete = await client.CompleteAsync(sid, token);
        Assert.True(complete.IsSuccess, complete.ErrorMessage);
        var report = complete.Body.Deserialize<SessionReport>(Json)!;

        // hostile entries are ledgered as FAILED/E_PATH_REJECTED, never transferred
        Assert.Equal(6, report.Totals.Items);
        Assert.Equal(1, report.Totals.Verified);
        Assert.Equal(5, report.Totals.Failed);
        foreach (var item in report.Items.Where(i => i.Outcome == "FAILED"))
            Assert.Equal("E_PATH_REJECTED", item.ErrorCode);

        // nothing escaped the destination directory
        var parent = Directory.GetParent(env.DestinationDir)!.FullName;
        foreach (var leaked in new[] { "evil1.txt", "evil2.txt", "evil3.txt", "evil4.txt", "evil5.txt" })
        {
            Assert.False(File.Exists(Path.Combine(parent, leaked)), leaked + " leaked to parent");
            Assert.False(File.Exists(Path.Combine(parent, "..", leaked)), leaked + " leaked upward");
        }
        Assert.False(Directory.Exists(Path.Combine(env.DestinationDir, "Windows")));
        Assert.False(Directory.Exists(Path.Combine(parent, "abs")));
        Assert.True(File.Exists(Path.Combine(env.DestinationDir, "ok.txt")));
    }

    [Fact]
    public async Task DeeplyNestedPath_IsStillInsideDestination()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var deep = string.Join('/', Enumerable.Repeat("level", 40)) + "/leaf.bin";
        var bytes = new byte[16];
        new Random(7).NextBytes(bytes);
        var entries = new List<Entry> { FileEntry(deep, bytes.Length) };

        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);

        var fileId = manifest.Body.GetProperty("planned").EnumerateArray().Single()
            .GetProperty("fileId").GetString()!;
        var chunk = await client.UploadChunkAsync(sid, token, fileId, 0, bytes,
            TestEnv.HashBytes(bytes));
        Assert.Equal("VERIFIED", chunk.Body.GetProperty("status").GetString());
        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(bytes),
            bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

        var finalPath = commit.Body.GetProperty("finalPath").GetString()!;
        Assert.StartsWith(Path.GetFullPath(env.DestinationDir), finalPath,
            StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(finalPath));
        Assert.Equal(TestEnv.HashBytes(bytes), TestEnv.HashFile(finalPath));
    }

    // -------------------------------------------------------- resource limits

    [Fact]
    public async Task InsufficientStorage_FailsConfirmWith507()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.DestinationInfoFactory = path => new FakeDestinationInfo(path)
            {
                FreeBytes = 10,
                FileSystem = "NTFS",
            };
            return o;
        });
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[100];
        var entries = new List<Entry> { FileEntry("big.bin", bytes.Length) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.Equal(507, confirm.Status);
        Assert.Equal("E_INSUFFICIENT_STORAGE", confirm.ErrorCode);
        Assert.True(confirm.Body.GetProperty("error").GetProperty("retryable").GetBoolean());
    }

    [Fact]
    public async Task Fat32Destination_FailsPreflightForFilesOver4GiB()
    {
        const long fiveGiB = 5L * 1024 * 1024 * 1024;
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.DestinationInfoFactory = path => new FakeDestinationInfo(path)
            {
                FreeBytes = 100L * 1024 * 1024 * 1024,
                FileSystem = "FAT32",
                MaxFileSize = 4L * 1024 * 1024 * 1024 - 1,
            };
            return o;
        });
        using var client = await env.AuthenticatedClientAsync();

        var entries = new List<Entry> { FileEntry("huge.iso", fiveGiB) };
        var sid = await client.CreateSessionAsync(1, 0, fiveGiB);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        // preflight predicts the problem before a single byte moves (SPEC §6.2)
        var problem = Assert.Single(manifest.Body.GetProperty("predictedProblems").EnumerateArray());
        Assert.Equal("P_FAT32_4GB", problem.GetProperty("code").GetString());
        Assert.Equal("huge.iso", problem.GetProperty("path").GetString());

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.Equal(413, confirm.Status);
        Assert.Equal("E_LIMIT_EXCEEDED", confirm.ErrorCode);
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "huge.iso")));
    }

    [Fact]
    public async Task OutOfOrderManifestBatch_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var entries = new List<Entry> { FileEntry("a.txt", 1) };
        var sid = await client.CreateSessionAsync(1, 0, 1);
        var token = await client.AwaitApprovalAsync(sid);

        var resp = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries), batchIndex: 3);
        Assert.Equal(400, resp.Status);
        Assert.Equal("E_BAD_REQUEST", resp.ErrorCode);
    }

    [Fact]
    public async Task ManifestDigestMismatch_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var entries = new List<Entry> { FileEntry("a.txt", 1) };
        var sid = await client.CreateSessionAsync(1, 0, 1);
        var token = await client.AwaitApprovalAsync(sid);

        var wrong = new string('a', 64);
        var resp = await client.SendManifestAsync(sid, token, entries, final: true, digest: wrong);
        Assert.Equal(400, resp.Status);
        Assert.Equal("E_BAD_REQUEST", resp.ErrorCode);
    }

    [Fact]
    public async Task CorruptedChunkHash_IsRejected_AndNothingPersisted()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[32];
        new Random(9).NextBytes(bytes);
        var entries = new List<Entry> { FileEntry("x.bin", bytes.Length) };

        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);
        var fileId = manifest.Body.GetProperty("planned").EnumerateArray().Single()
            .GetProperty("fileId").GetString()!;

        // declare the WRONG hash for the body we send (simulated wire corruption)
        var corrupt = await client.UploadChunkAsync(sid, token, fileId, 0, bytes,
            new string('0', 64));
        Assert.Equal(422, corrupt.Status);
        Assert.Equal("E_CHUNK_HASH_MISMATCH", corrupt.ErrorCode);
        Assert.True(corrupt.Body.GetProperty("error").GetProperty("retryable").GetBoolean());

        // the staged part file must not have been persisted for the bad chunk
        var staging = Path.Combine(env.DestinationDir, ".mac2win-staging", sid);
        if (Directory.Exists(staging))
            Assert.Empty(Directory.GetFiles(staging, "*.m2wpart"));

        // the sender retries with the correct hash and the transfer continues
        var good = await client.UploadChunkAsync(sid, token, fileId, 0, bytes,
            TestEnv.HashBytes(bytes));
        Assert.Equal("VERIFIED", good.Body.GetProperty("status").GetString());
        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(bytes),
            bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());
        Assert.True(File.Exists(Path.Combine(env.DestinationDir, "x.bin")));
    }
}

/// <summary>Pretend volume for preflight tests (low disk, FAT32) without real hardware.</summary>
internal sealed class FakeDestinationInfo : IDestinationInfo
{
    private readonly string _path;

    public FakeDestinationInfo(string path) => _path = path;

    public long FreeBytes { get; set; } = long.MaxValue;
    public string FileSystem { get; set; } = "NTFS";
    public long MaxFileSize { get; set; } = long.MaxValue;
    public bool Writable { get; set; } = true;

    public DestinationSnapshot GetInfo() =>
        new(_path, FreeBytes, FileSystem, Writable, LongPathsEnabled: true, MaxFileSize);
}
