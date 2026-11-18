using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// M2 unauthorized + malicious-client suite (SPEC §13 "unauthorized and malicious-client
/// tests pass"). Real TLS, real sockets, real Kestrel — AUTOMATED. Covers tampered
/// pairing material, replay/expiry of challenges, unknown devices, version mismatches,
/// cross-session token use, oversized and malformed bodies, hostile paths (control chars,
/// reserved names, depth, backslash traversal), chunk abuse, rate limiting, body stalls,
/// idle expiry, device revocation, and internal-error leakage (docs/SECURITY.md T2–T8,
/// T10).
/// </summary>
public sealed class MaliciousClientTests
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

    // ------------------------------------------------------------ pairing tamper

    [Fact]
    public async Task TamperedPinProof_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();
        client.TamperPinProof = true;

        var resp = await client.PairRawAsync(TestEnv.TestPin);
        Assert.Equal(403, resp.Status);
        Assert.Equal("E_PIN_INVALID", resp.ErrorCode);
        Assert.Null(client.DeviceId);
    }

    [Fact]
    public async Task TamperedHelloSignature_IsUnauthorized()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();
        await client.PairAsync(TestEnv.TestPin); // valid pairing, device known

        client.TamperSignature = true;
        var resp = await client.HelloRawAsync();
        Assert.Equal(401, resp.Status);
        Assert.Equal("E_UNAUTHORIZED", resp.ErrorCode);
        Assert.Null(client.DeviceToken);
    }

    [Fact]
    public async Task ReplayedServerNonce_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        var challenge = await client.PostJsonAsync("/v1/auth/challenge", new { });
        var nonce = challenge.Body.GetProperty("serverNonce").GetString()!;
        var body = await client.BuildPairBodyAsync(TestEnv.TestPin, nonce);

        var first = await client.PostRawAsync("/v1/pair", body);
        Assert.True(first.IsSuccess, first.ErrorMessage);

        var replay = await client.PostRawAsync("/v1/pair", body); // same nonce, same body
        Assert.Equal(400, replay.Status);
        Assert.Equal("E_BAD_REQUEST", replay.ErrorCode);
    }

    [Fact]
    public async Task ExpiredServerNonce_IsRejected()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.ChallengeTtl = TimeSpan.FromMilliseconds(250);
            return o;
        });
        using var client = env.CreateClient();

        var resp = await client.PairRawAsync(TestEnv.TestPin,
            challengeDelay: TimeSpan.FromMilliseconds(500));
        Assert.Equal(400, resp.Status);
        Assert.Equal("E_BAD_REQUEST", resp.ErrorCode);
        Assert.Contains("expired", resp.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnknownDeviceId_GetsE_NOT_PAIRED()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();
        await client.PairAsync(TestEnv.TestPin);

        client.DeviceId = Guid.NewGuid().ToString(); // never paired with this receiver
        var resp = await client.HelloRawAsync();
        Assert.Equal(403, resp.Status);
        Assert.Equal("E_NOT_PAIRED", resp.ErrorCode);
    }

    [Fact]
    public async Task WrongProtocolVersion_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();
        client.PairProtocolVersion = 2;

        var resp = await client.PairRawAsync(TestEnv.TestPin);
        Assert.Equal(400, resp.Status);
        Assert.Equal("E_UNSUPPORTED_VERSION", resp.ErrorCode);
    }

    [Fact]
    public async Task CrossSessionToken_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var sid1 = await client.CreateSessionAsync(1, 0, 10);
        var sid2 = await client.CreateSessionAsync(1, 0, 10);
        var token1 = await client.AwaitApprovalAsync(sid1);
        _ = await client.AwaitApprovalAsync(sid2);

        // session token of sid1 must not address sid2
        var resp = await client.GetStateAsync(sid2, token1);
        Assert.Equal(401, resp.Status);
        Assert.Equal("E_UNAUTHORIZED", resp.ErrorCode);
    }

    // ----------------------------------------------------------- resource caps

    [Fact]
    public async Task ManifestWith1001Entries_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var entries = Enumerable.Range(0, 1001).Select(i => FileEntry($"f{i:D4}.bin", 1)).ToList();
        var sid = await client.CreateSessionAsync(entries.Count, 0, entries.Count);
        var token = await client.AwaitApprovalAsync(sid);

        var resp = await client.SendManifestAsync(sid, token, entries, final: true, digest: null);
        Assert.Equal(413, resp.Status);
        Assert.Equal("E_MANIFEST_TOO_LARGE", resp.ErrorCode);

        // batch not consumed: the session is still collecting the manifest
        var (status, _) = await client.GetSessionAsync(sid);
        Assert.Equal("MANIFEST_RECEIVING", status);
    }

    [Fact]
    public async Task OversizedManifestBody_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        // 100 × ~15 KB paths ⇒ body over the 1 MiB manifest cap, entry count still legal
        var longName = new string('p', 15_000);
        var entries = Enumerable.Range(0, 100)
            .Select(i => FileEntry($"{i:D3}/{longName}.bin", 1)).ToList();
        var sid = await client.CreateSessionAsync(entries.Count, 0, 1);
        var token = await client.AwaitApprovalAsync(sid);

        var resp = await client.SendManifestAsync(sid, token, entries, final: true, digest: null);
        Assert.Equal(413, resp.Status);
        Assert.Equal("E_MANIFEST_TOO_LARGE", resp.ErrorCode);
    }

    [Fact]
    public async Task OversizedControlBody_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        var resp = await client.PostJsonAsync("/v1/pair",
            new { pad = new string('x', 2 * 1024 * 1024) });
        Assert.Equal(413, resp.Status);
        Assert.Equal("E_LIMIT_EXCEEDED", resp.ErrorCode);
    }

    [Fact]
    public async Task GarbageOrIncompleteJson_IsBadRequest()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();

        var syntax = await client.PostRawAsync("/v1/pair", "{\"protocolVersion\": ");
        Assert.Equal(400, syntax.Status);
        Assert.Equal("E_BAD_REQUEST", syntax.ErrorCode);

        var missingFields = await client.PostRawAsync("/v1/pair", "{}");
        Assert.Equal(400, missingFields.Status);
        Assert.Equal("E_BAD_REQUEST", missingFields.ErrorCode);
        Assert.Contains("missing", missingFields.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------ hostile paths

    [Fact]
    public async Task ControlCharacterPath_IsLedgeredRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var entries = new List<Entry> { FileEntry("bad\tname.txt", 4), FileEntry("ok.txt", 4) };
        var sid = await client.CreateSessionAsync(2, 0, 8);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var planned = manifest.Body.GetProperty("planned").EnumerateArray()
            .ToDictionary(p => p.GetProperty("path").GetString()!,
                p => (Action: p.GetProperty("action").GetString()!,
                      Reason: p.TryGetProperty("reason", out var r) ? r.GetString() : null));
        Assert.Equal("REJECTED", planned["bad\tname.txt"].Action);
        Assert.Equal("CONTROL_CHARACTER", planned["bad\tname.txt"].Reason);
        Assert.Equal("CREATE", planned["ok.txt"].Action);
    }

    [Fact]
    public async Task ReservedDeviceName_IsSanitizedDeterministically()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var entries = new List<Entry> { FileEntry("CON.txt", 4), FileEntry("com1/data.bin", 4) };
        var sid = await client.CreateSessionAsync(2, 1, 8);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var planned = manifest.Body.GetProperty("planned").EnumerateArray()
            .ToDictionary(p => p.GetProperty("path").GetString()!,
                p => (Action: p.GetProperty("action").GetString()!,
                      Reason: p.TryGetProperty("reason", out var r) ? r.GetString() : null,
                      FinalPath: p.TryGetProperty("finalPath", out var f) ? f.GetString() : null));
        Assert.Equal("RENAME", planned["CON.txt"].Action);
        Assert.Equal("SANITIZED", planned["CON.txt"].Reason);
        Assert.Equal("CON_.txt", planned["CON.txt"].FinalPath);
        Assert.Equal("RENAME", planned["com1/data.bin"].Action);
        Assert.Equal("com1_/data.bin", planned["com1/data.bin"].FinalPath);
    }

    [Fact]
    public async Task PathBeyondDepthLimit_IsLedgeredRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        // 70 segments > ProtocolConstants.MaxPathDepth (64); the 41-segment transfer in
        // AuthAndSecurityTests proves legal depth still transfers
        var deep = string.Join('/', Enumerable.Repeat("level", 69)) + "/leaf.bin";
        var entries = new List<Entry> { FileEntry(deep, 4) };
        var sid = await client.CreateSessionAsync(1, 0, 4);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var planned = manifest.Body.GetProperty("planned").EnumerateArray().Single();
        Assert.Equal("REJECTED", planned.GetProperty("action").GetString());
        Assert.Equal("PATH_TOO_DEEP", planned.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task BackslashTraversal_IsSanitizedAndLandsInsideDestination()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[8];
        new Random(3).NextBytes(bytes);
        var entries = new List<Entry> { FileEntry("..\\..\\evil.dll", bytes.Length) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);

        var planned = manifest.Body.GetProperty("planned").EnumerateArray().Single();
        Assert.Equal("RENAME", planned.GetProperty("action").GetString());
        Assert.Equal("SANITIZED", planned.GetProperty("reason").GetString());
        var finalRel = planned.GetProperty("finalPath").GetString()!;
        Assert.Equal(".._.._evil.dll", finalRel);

        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);
        var fileId = planned.GetProperty("fileId").GetString()!;
        var chunk = await client.UploadChunkAsync(sid, token, fileId, 0, bytes,
            TestEnv.HashBytes(bytes));
        Assert.Equal("VERIFIED", chunk.Body.GetProperty("status").GetString());
        var commit = await client.CommitAsync(sid, token, fileId, TestEnv.HashBytes(bytes),
            bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal("RENAMED", commit.Body.GetProperty("outcome").GetString());

        // the file exists inside the destination under the sanitized name, nowhere else
        var finalAbs = Path.GetFullPath(Path.Combine(env.DestinationDir, finalRel));
        Assert.True(File.Exists(finalAbs));
        Assert.StartsWith(Path.GetFullPath(env.DestinationDir), finalAbs,
            StringComparison.OrdinalIgnoreCase);
        var parent = Directory.GetParent(env.DestinationDir)!.FullName;
        Assert.False(File.Exists(Path.Combine(parent, "evil.dll")));
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "..", "evil.dll")));
        Assert.Equal(TestEnv.HashBytes(bytes), TestEnv.HashFile(finalAbs));
    }

    // -------------------------------------------------------------- chunk abuse

    [Fact]
    public async Task NegativeAndOutOfRangeChunkIndex_AreBadRequests()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[10];
        var entries = new List<Entry> { FileEntry("x.bin", bytes.Length) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);
        var fileId = manifest.Body.GetProperty("planned").EnumerateArray().Single()
            .GetProperty("fileId").GetString()!;

        var negative = await client.UploadChunkAsync(sid, token, fileId, -1, bytes,
            TestEnv.HashBytes(bytes));
        Assert.Equal(400, negative.Status);
        Assert.Equal("E_BAD_REQUEST", negative.ErrorCode);

        var wayBeyond = await client.UploadChunkAsync(sid, token, fileId, 999_999, bytes,
            TestEnv.HashBytes(bytes));
        Assert.Equal(400, wayBeyond.Status);
        Assert.Equal("E_BAD_REQUEST", wayBeyond.ErrorCode);
    }

    [Fact]
    public async Task UnknownFileId_Commit_Is404()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[10];
        var entries = new List<Entry> { FileEntry("x.bin", bytes.Length) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);

        var resp = await client.CommitAsync(sid, token, "f-4242",
            TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(SourceMtime));
        Assert.Equal(404, resp.Status);
        Assert.Equal("E_SESSION_NOT_FOUND", resp.ErrorCode);
    }

    [Fact]
    public async Task ChunkBodyLengthMismatch_IsRejected()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = await env.AuthenticatedClientAsync();

        var bytes = new byte[10];
        var entries = new List<Entry> { FileEntry("x.bin", bytes.Length) };
        var sid = await client.CreateSessionAsync(1, 0, bytes.Length);
        var token = await client.AwaitApprovalAsync(sid);
        var manifest = await client.SendManifestAsync(sid, token, entries, final: true,
            digest: DigestOf(entries));
        Assert.True(manifest.IsSuccess, manifest.ErrorMessage);
        var confirm = await client.ConfirmAsync(sid, token);
        Assert.True(confirm.IsSuccess, confirm.ErrorMessage);
        var fileId = manifest.Body.GetProperty("planned").EnumerateArray().Single()
            .GetProperty("fileId").GetString()!;

        // 2000-byte body for a chunk the manifest says is 10 bytes: rejected before reading
        var oversized = new byte[2000];
        new Random(5).NextBytes(oversized);
        var resp = await client.UploadChunkAsync(sid, token, fileId, 0, oversized,
            TestEnv.HashBytes(oversized));
        Assert.Equal(400, resp.Status);
        Assert.Equal("E_BAD_REQUEST", resp.ErrorCode);
        Assert.False(File.Exists(Path.Combine(env.DestinationDir, "x.bin")));
    }

    // ------------------------------------------------------------- DoS defenses

    [Fact]
    public async Task AuthBurst_IsRateLimited()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.AuthRateLimit = 10;
            o.AuthRateWindow = TimeSpan.FromMinutes(1);
            return o;
        });
        using var client = env.CreateClient();

        ApiResponse? last = null;
        for (var i = 0; i < 15 && (last is null || last.Status != 429); i++)
            last = await client.PostJsonAsync("/v1/auth/challenge", new { });

        Assert.NotNull(last);
        Assert.Equal(429, last!.Status);
        Assert.Equal("E_RATE_LIMITED", last.ErrorCode);
        Assert.True(last.Body.GetProperty("error").GetProperty("retryable").GetBoolean());
    }

    [Fact]
    public async Task ChallengeStore_StaysBounded()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.MaxPendingChallenges = 32;
            return o;
        });
        using var client = env.CreateClient();

        for (var i = 0; i < 64; i++)
        {
            var health = await client.GetAsync("/v1/health");
            Assert.True(health.IsSuccess);
        }
        Assert.InRange(env.Server.PendingChallengeCount, 1, 32);
    }

    [Fact]
    public void RateLimiter_SlidesWindowAndZeroDisables()
    {
        var limiter = new AuthRateLimiter(2, TimeSpan.FromMilliseconds(250));
        Assert.True(limiter.TryAcquire("10.0.0.1"));
        Assert.True(limiter.TryAcquire("10.0.0.1"));
        Assert.False(limiter.TryAcquire("10.0.0.1")); // over budget inside the window
        Assert.True(limiter.TryAcquire("10.0.0.2"));  // budget is per client key

        Thread.Sleep(300); // window slides (sleeps only lengthen it)
        Assert.True(limiter.TryAcquire("10.0.0.1"));

        var disabled = new AuthRateLimiter(0, TimeSpan.FromSeconds(1));
        Assert.True(disabled.TryAcquire("anyone")); // 0 ⇒ limiter off
    }

    [Fact]
    public async Task StalledRequestBody_TimesOutWith408E_IDLE_TIMEOUT()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.BodyStallTimeout = TimeSpan.FromMilliseconds(750);
            return o;
        });

        // raw TLS socket: headers promise 100000 bytes, only a few arrive, then silence
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, env.Server.Port);
        await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
            (_, certificate, _, _) => certificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())).ToLowerInvariant(),
                env.Server.CertFingerprint, StringComparison.Ordinal));
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        });

        var request = Encoding.ASCII.GetBytes(
            "POST /v1/pair HTTP/1.1\r\nHost: localhost\r\n" +
            "Content-Type: application/json\r\nContent-Length: 100000\r\n\r\n{\"pad\":");
        await ssl.WriteAsync(request);

        ssl.ReadTimeout = 15_000; // milliseconds
        var buffer = new byte[8192];
        var received = new StringBuilder();
        while (!received.ToString().Contains("E_IDLE_TIMEOUT", StringComparison.Ordinal))
        {
            int n;
            try
            {
                n = await ssl.ReadAsync(buffer);
            }
            catch (IOException) when (received.Length > 0)
            {
                break; // server closed after the early response
            }
            if (n == 0) break;
            received.Append(Encoding.ASCII.GetString(buffer, 0, n));
        }

        var text = received.ToString();
        Assert.Contains("408", text);
        Assert.Contains("E_IDLE_TIMEOUT", text);
    }

    // ------------------------------------------------------- expiry & revocation

    [Fact]
    public async Task IdleExpiry_Returns410AndPurgesStaging()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.IdleTimeout = TimeSpan.FromMilliseconds(400);
            return o;
        });
        using var client = await env.AuthenticatedClientAsync();

        var sid = await client.CreateSessionAsync(1, 0, 10);
        _ = await client.AwaitApprovalAsync(sid); // last activity is here

        await Task.Delay(900); // > IdleTimeout, no requests in between

        var resp = await client.GetAsync($"/v1/sessions/{sid}", client.DeviceToken);
        Assert.Equal(410, resp.Status);
        Assert.Equal("E_SESSION_EXPIRED", resp.ErrorCode);

        // SPEC §5: expiry purges staging; verified files (none here) would stay in place
        Assert.False(Directory.Exists(
            Path.Combine(env.DestinationDir, ".mac2win-staging", sid)));
    }

    [Fact]
    public async Task RevokedDevice_LosesAccess_AndCanRePairWithFreshPin()
    {
        await using var env = await TestEnv.StartAsync();
        using var client = env.CreateClient();
        var deviceToken = await client.AuthenticateAsync(TestEnv.TestPin);
        var deviceId = client.DeviceId!;
        var sid = await client.CreateSessionAsync(1, 0, 10);
        var sessionToken = await client.AwaitApprovalAsync(sid);

        Assert.Contains(env.Server.TrustedDevices, d => d.DeviceId == deviceId);

        env.Server.RevokeDevice(deviceId);

        // device token invalidated immediately
        var destination = await client.GetAsync("/v1/destination", deviceToken);
        Assert.Equal(401, destination.Status);
        Assert.Equal("E_UNAUTHORIZED", destination.ErrorCode);

        // session tokens of sessions it owns are invalidated too
        var state = await client.GetStateAsync(sid, sessionToken);
        Assert.Equal(401, state.Status);
        Assert.Equal("E_UNAUTHORIZED", state.ErrorCode);

        // re-hello with the old pairing says "not paired"
        var hello = await client.HelloRawAsync();
        Assert.Equal(403, hello.Status);
        Assert.Equal("E_NOT_PAIRED", hello.ErrorCode);

        Assert.DoesNotContain(env.Server.TrustedDevices, d => d.DeviceId == deviceId);

        // re-pairing with the (test-fixed) PIN re-enrolls the device and restores access
        var newToken = await client.AuthenticateAsync(TestEnv.TestPin);
        Assert.NotEqual(deviceToken, newToken);
        Assert.Contains(env.Server.TrustedDevices, d => d.DeviceId == client.DeviceId);
        var again = await client.GetAsync("/v1/destination", newToken);
        Assert.True(again.IsSuccess, again.ErrorMessage);
    }

    // ------------------------------------------------------------- error hygiene

    [Fact]
    public async Task ErrorResponses_DoNotLeakInternals()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            // factory succeeds (env setup calls it) but GetInfo explodes per-request
            o.DestinationInfoFactory = _ => new ExplodingDestinationInfo();
            return o;
        });
        using var client = await env.AuthenticatedClientAsync();

        var resp = await client.GetAsync("/v1/destination", client.DeviceToken);
        Assert.Equal(500, resp.Status);
        Assert.Equal("E_INTERNAL", resp.ErrorCode);
        Assert.Equal("internal error", resp.ErrorMessage);
        Assert.DoesNotContain("Secret", resp.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" disk", resp.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("   at ", resp.ErrorMessage, StringComparison.Ordinal); // no stack
    }

    /// <summary>Destination whose volume facts cannot be read (simulates disk failure).</summary>
    private sealed class ExplodingDestinationInfo : IDestinationInfo
    {
        public DestinationSnapshot GetInfo() =>
            throw new IOException("disk exploded at C:\\Secret\\Users\\alice");
    }
}
