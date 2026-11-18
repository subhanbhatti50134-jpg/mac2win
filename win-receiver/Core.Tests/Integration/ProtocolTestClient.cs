using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core;

namespace Mac2WinReceiver.Core.Tests.Integration;

public sealed record ApiResponse(int Status, JsonElement Body)
{
    public bool IsSuccess => Status is >= 200 and < 300;

    public string ErrorCode =>
        Body.TryGetProperty("error", out var e) && e.TryGetProperty("code", out var c)
            ? c.GetString() ?? "?"
            : "?";

    public string ErrorMessage =>
        Body.TryGetProperty("error", out var e) && e.TryGetProperty("message", out var m)
            ? m.GetString() ?? ""
            : "";
}

public sealed record Entry(
    string Path, string Type, long Size, string MtimeUtcNs, long Mode,
    string? CtimeUtcNs = null, string? SymlinkTarget = null, string? SenderState = null);

/// <summary>
/// Test-harness protocol client (plays the Mac sender's role over real TLS + real sockets).
/// Certificate validation pins the server fingerprint supplied out-of-band by the test
/// fixture — there is deliberately no "accept any certificate" path (SPEC §7).
/// </summary>
public sealed class ProtocolTestClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;
    private ECDsa? _deviceKey;

    public string PinnedFingerprint { get; }
    /// <summary>Paired device id (settable so hostile-hello tests can send an unknown one).</summary>
    public string? DeviceId { get; set; }
    public string? DeviceToken { get; private set; }

    public ProtocolTestClient(Uri baseUri, string pinnedFingerprint)
    {
        PinnedFingerprint = pinnedFingerprint.ToLowerInvariant();
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
        {
            if (cert is null) return false;
            var actual = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
            return string.Equals(actual, PinnedFingerprint, StringComparison.Ordinal);
        };
        _http = new HttpClient(handler)
        {
            BaseAddress = baseUri,
            Timeout = TimeSpan.FromMinutes(10),
        };
    }

    // ------------------------------------------------------------- raw requests

    public async Task<ApiResponse> GetAsync(string path, string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
        return await ToApiResponse(resp);
    }

    public async Task<ApiResponse> PostJsonAsync(string path, object body, string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path);
        if (bearer is not null) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        req.Content = new StringContent(JsonSerializer.Serialize(body, Json),
            Encoding.UTF8, "application/json");
        using var resp = await _http.SendAsync(req);
        return await ToApiResponse(resp);
    }

    /// <summary>POST with a raw body string (malformed-JSON / oversized-body tests).</summary>
    public async Task<ApiResponse> PostRawAsync(string path, string rawJson, string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path);
        if (bearer is not null) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        req.Content = new StringContent(rawJson, Encoding.UTF8, "application/json");
        using var resp = await _http.SendAsync(req);
        return await ToApiResponse(resp);
    }

    public async Task<ApiResponse> PutChunkAsync(string path, ReadOnlyMemory<byte> body,
        string sha256Hex, string bearer)
    {
        using var req = new HttpRequestMessage(HttpMethod.Put, path);
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
        req.Headers.TryAddWithoutValidation("X-Chunk-Sha256", sha256Hex);
        var content = new ByteArrayContent(body.ToArray());
        content.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream");
        req.Content = content;
        using var resp = await _http.SendAsync(req);
        return await ToApiResponse(resp);
    }

    private static async Task<ApiResponse> ToApiResponse(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        return new ApiResponse((int)resp.StatusCode, doc.RootElement.Clone());
    }

    // ------------------------------------------------------------- auth flow

    public async Task<string> AuthenticateAsync(string pin)
    {
        var health = await GetAsync("/v1/health");
        if (!health.IsSuccess) throw new InvalidOperationException("health failed: " + health.Status);
        var fp = health.Body.GetProperty("certFingerprintSha256").GetString();
        if (!string.Equals(fp, PinnedFingerprint, StringComparison.Ordinal))
            throw new InvalidOperationException("pinned fingerprint mismatch");

        var deviceId = await PairAsync(pin);
        DeviceId = deviceId;
        DeviceToken = await HelloAsync();
        return DeviceToken;
    }

    /// <summary>When true, <see cref="PairRawAsync"/> corrupts the pinProof (tamper tests).</summary>
    public bool TamperPinProof { get; set; }

    /// <summary>When true, hello requests corrupt the signature (tamper tests).</summary>
    public bool TamperSignature { get; set; }

    /// <summary>protocolVersion sent by /v1/pair (wrong-version tests).</summary>
    public int PairProtocolVersion { get; set; } = ProtocolConstants.ProtocolVersion;

    /// <summary>
    /// Pairs with the receiver using the PIN-bound proof. Returns the raw response so
    /// security tests can assert on failures (wrong PIN, lockout) without exceptions.
    /// </summary>
    public async Task<ApiResponse> PairRawAsync(string pin, TimeSpan? challengeDelay = null)
    {
        var challenge = await PostJsonAsync("/v1/auth/challenge", new { });
        var serverNonce = challenge.Body.GetProperty("serverNonce").GetString()!;
        if (challengeDelay is { } delay)
            await Task.Delay(delay); // let the challenge expire before pairing (TTL tests)
        var body = await BuildPairBodyAsync(pin, serverNonce);
        return await PostRawAsync("/v1/pair", body);
    }

    /// <summary>
    /// Builds the exact JSON body for /v1/pair against an already-obtained
    /// <paramref name="serverNonce"/> (replay/expiry tests post it more than once).
    /// </summary>
    public async Task<string> BuildPairBodyAsync(string pin, string serverNonce)
    {
        _deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pubkeyDer = _deviceKey.ExportSubjectPublicKeyInfo();
        var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var pubkeyB64 = Convert.ToBase64String(pubkeyDer);

        var proof = PairingProof.ComputeProof(pin, PinnedFingerprint, clientNonce, serverNonce, pubkeyB64);
        if (TamperPinProof) proof[0] ^= 0xFF; // still valid base64, wrong bytes ⇒ E_PIN_INVALID

        return JsonSerializer.Serialize(new
        {
            protocolVersion = PairProtocolVersion,
            deviceName = "integration-test-mac",
            devicePublicKey = pubkeyB64,
            clientNonce,
            serverNonce,
            pinProof = Convert.ToBase64String(proof),
        }, Json);
    }

    public async Task<string> PairAsync(string pin)
    {
        var pair = await PairRawAsync(pin);
        if (!pair.IsSuccess)
            throw new InvalidOperationException($"pair failed: {pair.Status} {pair.ErrorCode} {pair.ErrorMessage}");
        DeviceId = pair.Body.GetProperty("deviceId").GetString()!;
        return DeviceId;
    }

    public async Task<string> HelloAsync()
    {
        var hello = await HelloRawAsync();
        if (!hello.IsSuccess)
            throw new InvalidOperationException($"hello failed: {hello.Status} {hello.ErrorCode} {hello.ErrorMessage}");
        return hello.Body.GetProperty("deviceToken").GetString()!;
    }

    /// <summary>Raw hello response (tamper tests assert on the failure without exceptions).</summary>
    public async Task<ApiResponse> HelloRawAsync()
    {
        var challenge = await PostJsonAsync("/v1/auth/challenge", new { });
        var serverNonce = challenge.Body.GetProperty("serverNonce").GetString()!;
        var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var message = Encoding.UTF8.GetBytes($"{clientNonce}|{serverNonce}");
        var signature = _deviceKey!.SignData(message, HashAlgorithmName.SHA256);
        if (TamperSignature) signature[0] ^= 0xFF; // valid base64, wrong bytes ⇒ E_UNAUTHORIZED

        return await PostJsonAsync("/v1/auth/hello", new
        {
            deviceId = DeviceId,
            deviceName = "integration-test-mac",
            clientNonce,
            serverNonce,
            signature = Convert.ToBase64String(signature),
        });
    }

    // -------------------------------------------------------------- sessions

    public async Task<string> CreateSessionAsync(long files, long dirs, long bytes)
    {
        var resp = await PostJsonAsync("/v1/sessions", new
        {
            summary = new { fileCount = files, dirCount = dirs, symlinkCount = 0, totalBytes = bytes },
            sourceDevice = new { name = "integration-test-mac" },
        }, DeviceToken);
        if (resp.Status != 202)
            throw new InvalidOperationException($"create session failed: {resp.Status} {resp.ErrorCode}");
        return resp.Body.GetProperty("sessionId").GetString()!;
    }

    public async Task<(string Status, string? SessionToken)> GetSessionAsync(string sessionId)
    {
        var resp = await GetAsync($"/v1/sessions/{sessionId}", DeviceToken);
        if (!resp.IsSuccess) throw new InvalidOperationException($"get session: {resp.Status} {resp.ErrorCode}");
        return (resp.Body.GetProperty("status").GetString()!,
            resp.Body.TryGetProperty("sessionToken", out var t) ? t.GetString() : null);
    }

    public async Task<string> AwaitApprovalAsync(string sessionId, TimeSpan? timeout = null)
    {
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (DateTimeOffset.UtcNow < deadline)
        {
            var (status, token) = await GetSessionAsync(sessionId);
            if (status == "MANIFEST_RECEIVING" && !string.IsNullOrEmpty(token))
                return token!;
            if (status is "DENIED" or "EXPIRED")
                throw new InvalidOperationException($"session {status}");
            await Task.Delay(25);
        }
        throw new TimeoutException("approval not granted in time");
    }

    public async Task<ApiResponse> SendManifestAsync(string sessionId, string token,
        IReadOnlyList<Entry> entries, bool final, string? digest = null, int batchIndex = 0)
    {
        var payload = new Dictionary<string, object?>
        {
            ["batchIndex"] = batchIndex,
            ["final"] = final,
            ["entries"] = entries,
        };
        if (digest is not null) payload["manifestDigest"] = digest;
        return await PostJsonAsync($"/v1/sessions/{sessionId}/manifest", payload, token);
    }

    public async Task<ApiResponse> ConfirmAsync(string sessionId, string token,
        IReadOnlyDictionary<string, string>? resolutions = null, string? applyToAll = null)
    {
        return await PostJsonAsync($"/v1/sessions/{sessionId}/confirm", new
        {
            conflictResolutions = resolutions ?? new Dictionary<string, string>(),
            applyToAllDefault = applyToAll ?? "ASK",
        }, token);
    }

    public async Task<ApiResponse> GetStateAsync(string sessionId, string token, string? cursor = null)
    {
        var path = cursor is null
            ? $"/v1/sessions/{sessionId}/state"
            : $"/v1/sessions/{sessionId}/state?cursor={Uri.EscapeDataString(cursor)}";
        return await GetAsync(path, token);
    }

    public async Task<ApiResponse> UploadChunkAsync(string sessionId, string token, string fileId,
        int index, ReadOnlyMemory<byte> data, string sha256Hex)
    {
        return await PutChunkAsync(
            $"/v1/sessions/{sessionId}/files/{fileId}/chunks/{index}", data, sha256Hex, token);
    }

    public async Task<ApiResponse> CommitAsync(string sessionId, string token, string fileId,
        string fileSha256Hex, long size, string mtimeUtcNs, string? ctimeUtcNs = null)
    {
        return await PostJsonAsync($"/v1/sessions/{sessionId}/files/{fileId}/commit", new
        {
            fileSha256 = fileSha256Hex,
            size,
            mtimeUtcNs,
            ctimeUtcNs,
        }, token);
    }

    public async Task<ApiResponse> PauseAsync(string sid, string token) =>
        await PostJsonAsync($"/v1/sessions/{sid}/pause", new { }, token);

    public async Task<ApiResponse> ResumeAsync(string sid, string token) =>
        await PostJsonAsync($"/v1/sessions/{sid}/resume", new { }, token);

    public async Task<ApiResponse> CancelAsync(string sid, string token) =>
        await PostJsonAsync($"/v1/sessions/{sid}/cancel", new { }, token);

    public async Task<ApiResponse> CompleteAsync(string sid, string token) =>
        await PostJsonAsync($"/v1/sessions/{sid}/complete", new { }, token);

    public async Task<ApiResponse> ReportAsync(string sid, string token) =>
        await GetAsync($"/v1/sessions/{sid}/report", token);

    public void Dispose() => _http.Dispose();
}
