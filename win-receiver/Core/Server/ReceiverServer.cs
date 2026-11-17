using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Mac2WinReceiver.Core.Certs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// The receiver's HTTPS endpoint (protocol v1, ADR-007). Kestrel, local interfaces only,
/// TLS 1.3 preferred. Listening happens only when the host calls <see cref="StartAsync"/> —
/// the shipping UI gates that on the "Ready to receive" toggle (SPEC §4/§7).
/// </summary>
public sealed class ReceiverServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly ConcurrentDictionary<string, TransferSession> _sessions = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _challenges = new(); // nonce → expiry
    private readonly ConcurrentDictionary<string, DeviceRecord> _devices = new();      // sha256(pubkey) → record
    private readonly TokenVault _deviceTokens = new();
    private readonly TokenVault _sessionTokens = new();
    private readonly X509Certificate2 _certificate;

    public ReceiverOptions Options { get; }
    public PinVault Pins { get; }
    public string CertFingerprint { get; }
    public int Port { get; private set; }
    public int ActiveSessions => _sessions.Count;

    private sealed record DeviceRecord(string DeviceId, byte[] PublicKeyDer, string DeviceName, DateTimeOffset PairedAt);

    private ReceiverServer(WebApplication app, ReceiverOptions options, X509Certificate2 cert)
    {
        _app = app;
        Options = options;
        _certificate = cert;
        Port = options.Port;
        CertFingerprint = CertificateProvider.FingerprintSha256(cert);
        Pins = new PinVault(options.FixedTestPin);
    }

    public static async Task<ReceiverServer> StartAsync(ReceiverOptions options,
        CancellationToken ct = default)
    {
        if (!Directory.Exists(options.DestinationRoot))
            Directory.CreateDirectory(options.DestinationRoot);

        var cert = options.Certificate ?? CertificateProvider.CreateEphemeral();

        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.ConfigureHttpJsonOptions(o =>
        {
            // preserve dictionary keys exactly (manifest paths are case-sensitive on the wire)
            o.SerializerOptions.DictionaryKeyPolicy = null;
        });
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = ProtocolConstants.MaxChunkSize + 1024 * 1024;
            k.Listen(options.BindAddress, options.Port, lo => lo.UseHttps(cert));
        });

        var app = builder.Build();
        var server = new ReceiverServer(app, options, cert);
        server.MapEndpoints(app);

        await app.StartAsync(ct);

        var addresses = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        server.Port = addresses?.Addresses.FirstOrDefault() is { } addr
            ? int.Parse(addr.Split(':').Last())
            : options.Port;

        return server;
    }

    // ---------------------------------------------------------------- endpoints

    private void MapEndpoints(WebApplication app)
    {
        var v1 = app.MapGroup("/v1");

        // --- anonymous (TLS + fingerprints handle trust) -------------------
        v1.MapGet("/health", (HttpContext ctx) =>
        {
            var nonce = NewChallenge();
            return Results.Ok(new
            {
                service = "mac2win-receiver",
                protocolVersion = ProtocolConstants.ProtocolVersion,
                appVersion = typeof(ReceiverServer).Assembly.GetName().Version?.ToString(3) ?? "0.1.0",
                deviceName = Options.DeviceName,
                certFingerprintSha256 = CertFingerprint,
                serverNonce = nonce,
            });
        });

        v1.MapPost("/auth/challenge", () =>
        {
            var nonce = NewChallenge();
            return Results.Ok(new { serverNonce = nonce, expiresIn = 300 });
        });

        v1.MapPost("/pair", HandlePairAsync);
        v1.MapPost("/auth/hello", HandleHelloAsync);

        // --- device-scoped --------------------------------------------------
        v1.MapGet("/destination", (HttpContext ctx) =>
        {
            RequireDevice(ctx);
            var info = Options.CreateDestinationInfo().GetInfo();
            return Results.Ok(new
            {
                path = info.Path,
                freeBytes = info.FreeBytes,
                fileSystem = info.FileSystem,
                writable = info.Writable,
                longPathsEnabled = info.LongPathsEnabled,
            });
        });

        v1.MapPost("/sessions", HandleCreateSessionAsync);
        v1.MapGet("/sessions/{id}", HandleGetSessionAsync);

        // --- session-scoped -------------------------------------------------
        v1.MapPost("/sessions/{id}/manifest", HandleManifestAsync);
        v1.MapPost("/sessions/{id}/confirm", HandleConfirmAsync);
        v1.MapGet("/sessions/{id}/state", HandleStateAsync);
        v1.MapPut("/sessions/{id}/files/{fileId}/chunks/{index:int}", HandleChunkAsync);
        v1.MapPost("/sessions/{id}/files/{fileId}/commit", HandleCommitAsync);
        v1.MapPost("/sessions/{id}/pause", (HttpContext ctx, string id) =>
        {
            var session = RequireSession(ctx, id);
            session.Pause();
            return Results.Ok(new { status = WireStatus(session.Status) });
        });
        v1.MapPost("/sessions/{id}/resume", (HttpContext ctx, string id) =>
        {
            var session = RequireSession(ctx, id);
            session.Resume();
            return Results.Ok(new { status = WireStatus(session.Status) });
        });
        v1.MapPost("/sessions/{id}/cancel", (HttpContext ctx, string id) =>
        {
            var session = RequireSession(ctx, id);
            var report = session.Cancel();
            return Results.Ok(new { status = "CANCELLED", report });
        });
        v1.MapGet("/sessions/{id}/report", (HttpContext ctx, string id) =>
        {
            var session = RequireSession(ctx, id);
            if (session.Status is not (SessionStatus.Completed or SessionStatus.Cancelled or SessionStatus.Failed))
                throw new ProtocolException(ErrorCode.E_SESSION_STATE, "session not finished");
            return Results.Ok(session.BuildReport());
        });
        v1.MapPost("/sessions/{id}/complete", (HttpContext ctx, string id) =>
            Results.Ok(RequireSession(ctx, id).Complete()));

        // error shape for unmatched /v1 routes (protocol §5)
        app.Use(async (ctx, next) =>
        {
            try
            {
                await next();
            }
            catch (ProtocolException pex)
            {
                await WriteErrorAsync(ctx, pex);
            }
            catch (JsonException jex)
            {
                await WriteErrorAsync(ctx, new ProtocolException(ErrorCode.E_BAD_REQUEST, "malformed JSON: " + jex.Message));
            }
            catch (OperationCanceledException) when (ctx.RequestAborted.IsCancellationRequested)
            {
                // client went away: no response possible, no log of content
            }
            catch (Exception ex)
            {
                // never leak internals or file contents to the client
                ctx.RequestServices.GetService<ILogger<ReceiverServer>>()
                    ?.LogError(ex, "internal error handling {Path}", ctx.Request.Path);
                await WriteErrorAsync(ctx, new ProtocolException(ErrorCode.E_INTERNAL, "internal error"));
            }
        });
    }

    // The exception middleware is registered via app.Use after route mapping; WebApplication
    // inserts endpoint routing around user middleware, so it wraps every endpoint's execution.

    private static async Task WriteErrorAsync(HttpContext ctx, ProtocolException pex)
    {
        if (ctx.Response.HasStarted) return;
        var (status, _) = ProtocolErrors.Table[pex.Code];
        ctx.Response.StatusCode = (int)status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        var body = JsonSerializer.Serialize(
            new { error = new { code = pex.Code.ToString(), message = pex.Message, retryable = ProtocolErrors.Table[pex.Code].Retryable } },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        // Kestrel disallows synchronous response IO: must await WriteAsync (not Body.Write)
        await ctx.Response.WriteAsync(body, Encoding.UTF8);
    }

    // ----------------------------------------------------------- auth handlers

    private string NewChallenge()
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _challenges[nonce] = DateTimeOffset.UtcNow.AddMinutes(5);
        foreach (var kv in _challenges.Where(kv => kv.Value < DateTimeOffset.UtcNow))
            _challenges.TryRemove(kv.Key, out _);
        return nonce;
    }

    private string ConsumeChallenge(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce) || !_challenges.TryRemove(nonce, out var expiry))
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "missing or unknown serverNonce");
        if (expiry < DateTimeOffset.UtcNow)
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "serverNonce expired");
        return nonce;
    }

    private async Task<IResult> HandlePairAsync(HttpContext ctx, CancellationToken ct)
    {
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var version = root.GetProperty("protocolVersion").GetInt32();
        if (version != ProtocolConstants.ProtocolVersion)
            throw new ProtocolException(ErrorCode.E_UNSUPPORTED_VERSION,
                $"protocol version {version} not supported");

        var deviceName = root.GetProperty("deviceName").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "deviceName missing");
        var pubkeyB64 = root.GetProperty("devicePublicKey").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "devicePublicKey missing");
        var clientNonce = root.GetProperty("clientNonce").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "clientNonce missing");
        var serverNonce = root.GetProperty("serverNonce").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "serverNonce missing");
        var pinProofB64 = root.GetProperty("pinProof").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "pinProof missing");

        ConsumeChallenge(serverNonce);
        byte[] pubkeyDer;
        byte[] proof;
        try
        {
            pubkeyDer = Convert.FromBase64String(pubkeyB64);
            proof = Convert.FromBase64String(pinProofB64);
            _ = Convert.FromBase64String(clientNonce);
        }
        catch (FormatException)
        {
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "invalid base64 field");
        }
        // validate the public key parses (EC P-256 SPKI) before doing PIN work
        try
        {
            using var probe = ECDsa.Create();
            probe.ImportSubjectPublicKeyInfo(pubkeyDer, out _);
        }
        catch (CryptographicException)
        {
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "devicePublicKey is not a valid EC key");
        }

        var outcome = Pins.Attempt(pin => PairingProof.Verify(
            pin, CertFingerprint, clientNonce, serverNonce, pubkeyB64, proof));
        if (!outcome.Ok)
        {
            throw outcome.Reason switch
            {
                PinVault.PinFailure.Locked => new ProtocolException(ErrorCode.E_PIN_LOCKED,
                    $"too many attempts; retry in {Math.Ceiling(outcome.RetryAfter.TotalSeconds):0}s"),
                PinVault.PinFailure.Expired => new ProtocolException(ErrorCode.E_PIN_EXPIRED,
                    "PIN expired; a new PIN is displayed on the receiver"),
                _ => new ProtocolException(ErrorCode.E_PIN_INVALID, "PIN proof does not match"),
            };
        }

        var keyId = Convert.ToHexString(SHA256.HashData(pubkeyDer)).ToLowerInvariant();
        var deviceId = _devices.TryGetValue(keyId, out var existing)
            ? existing.DeviceId
            : Guid.NewGuid().ToString();
        _devices[keyId] = new DeviceRecord(deviceId, pubkeyDer, deviceName, DateTimeOffset.UtcNow);

        return Results.Ok(new
        {
            deviceId,
            issuedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(),
        });
    }

    private async Task<IResult> HandleHelloAsync(HttpContext ctx, CancellationToken ct)
    {
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var deviceId = root.GetProperty("deviceId").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "deviceId missing");
        var clientNonce = root.GetProperty("clientNonce").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "clientNonce missing");
        var serverNonce = root.GetProperty("serverNonce").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "serverNonce missing");
        var signatureB64 = root.GetProperty("signature").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "signature missing");

        ConsumeChallenge(serverNonce);

        var device = _devices.Values.FirstOrDefault(d => d.DeviceId == deviceId)
            ?? throw new ProtocolException(ErrorCode.E_NOT_PAIRED, "device is not paired");

        byte[] signature;
        try { signature = Convert.FromBase64String(signatureB64); }
        catch (FormatException) { throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "invalid signature encoding"); }

        var message = Encoding.UTF8.GetBytes($"{clientNonce}|{serverNonce}");

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(device.PublicKeyDer, out _);
        if (!ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256))
            throw new ProtocolException(ErrorCode.E_UNAUTHORIZED, "device signature invalid");

        var token = _deviceTokens.Issue("device", deviceId, TimeSpan.FromHours(1));
        return Results.Ok(new { deviceToken = token, expiresIn = 3600 });
    }

    // -------------------------------------------------------- session handlers

    private async Task<IResult> HandleCreateSessionAsync(HttpContext ctx, CancellationToken ct)
    {
        var deviceId = RequireDevice(ctx);
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var summaryEl = root.GetProperty("summary");
        var sourceName = root.GetProperty("sourceDevice").GetProperty("name").GetString() ?? "unknown";

        var summaryProbe = new SessionSummary(
            "pending", sourceName,
            summaryEl.TryGetProperty("fileCount", out var fc) ? fc.GetInt64() : 0,
            summaryEl.TryGetProperty("dirCount", out var dc) ? dc.GetInt64() : 0,
            summaryEl.TryGetProperty("symlinkCount", out var sc) ? sc.GetInt64() : 0,
            summaryEl.TryGetProperty("totalBytes", out var tb) ? tb.GetInt64() : 0,
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");

        var info = Options.CreateDestinationInfo().GetInfo();
        if (!info.Writable)
            throw new ProtocolException(ErrorCode.E_DESTINATION_ERROR, "destination is not writable");

        var session = new TransferSession(Options, Options.CreateDestinationInfo(),
            summaryProbe with { SessionId = Guid.NewGuid().ToString() });
        session.OwnerDeviceId = deviceId;
        _sessions[session.Id] = session;

        var handler = Options.ApprovalHandler;
        if (handler is null)
        {
            session.MarkDenied(); // no handler wired ⇒ never accept (SPEC §7)
        }
        else
        {
            _ = Task.Run(async () =>
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                try
                {
                    var decision = await handler(session.Summary, timeout.Token);
                    if (decision.Approved)
                        session.MarkApproved(_sessionTokens.Issue("session", session.Id, Options.SessionTtl));
                    else
                        session.MarkDenied();
                }
                catch
                {
                    session.MarkDenied();
                }
            }, CancellationToken.None);
        }

        return Results.Accepted($"/v1/sessions/{session.Id}",
            new { sessionId = session.Id, status = "AWAITING_APPROVAL" });
    }

    private IResult HandleGetSessionAsync(HttpContext ctx, string id)
    {
        var deviceId = RequireDevice(ctx);
        var session = GetSession(id);
        // owner check: only the device that created the session may poll it
        if (!string.Equals(session.OwnerDeviceId, deviceId, StringComparison.Ordinal))
            throw new ProtocolException(ErrorCode.E_SESSION_NOT_FOUND, "unknown session");
        var status = WireStatus(session.Status);
        return Results.Ok(new
        {
            sessionId = id,
            status,
            sessionToken = session.SessionToken,
            approvedAt = session.ApprovedAt?.ToUnixTimeMilliseconds().ToString(),
            chunkSizeMax = ProtocolConstants.MaxChunkSize,
            chunkSizeDefault = ProtocolConstants.DefaultChunkSize,
        });
    }

    private async Task<IResult> HandleManifestAsync(HttpContext ctx, string id, CancellationToken ct)
    {
        var session = GetSessionScoped(ctx, id);
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var batchIndex = root.GetProperty("batchIndex").GetInt32();
        var final = root.GetProperty("final").GetBoolean();
        var digest = root.TryGetProperty("manifestDigest", out var d) ? d.GetString() : null;
        if (!root.TryGetProperty("entries", out var entriesEl) || entriesEl.ValueKind != JsonValueKind.Array)
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "entries missing");

        var entries = entriesEl.EnumerateArray().Select(e => e.Clone()).ToList();
        var resp = session.ReceiveBatch(entries, batchIndex, final, digest, ct);
        if (resp.Preflight is null)
            return Results.Ok(new { status = resp.Status, planned = resp.Planned, batchAccepted = true });

        var p = resp.Preflight;
        return Results.Ok(new
        {
            status = resp.Status,
            planned = resp.Planned,
            batchAccepted = true,
            manifestDigest = p.ManifestDigest,
            totals = p.Totals,
            conflicts = p.Conflicts,
            renames = p.Renames,
            excluded = p.Excluded,
            rejected = p.Rejected,
            destination = p.Destination,
            predictedProblems = p.PredictedProblems,
        });
    }

    private async Task<IResult> HandleConfirmAsync(HttpContext ctx, string id, CancellationToken ct)
    {
        var session = GetSessionScoped(ctx, id);
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var resolutions = new Dictionary<string, string>(StringComparer.Ordinal);
        if (root.TryGetProperty("conflictResolutions", out var resEl) && resEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in resEl.EnumerateObject())
                resolutions[prop.Name] = prop.Value.GetString()
                    ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "resolution value missing");
        }
        var applyToAll = root.TryGetProperty("applyToAllDefault", out var at) ? at.GetString() : null;

        session.Confirm(resolutions, applyToAll);
        return Results.Ok(new { status = "TRANSFERRING", chunkSize = session.ChunkSize });
    }

    private IResult HandleStateAsync(HttpContext ctx, string id)
    {
        var session = GetSessionScoped(ctx, id);
        var cursor = ctx.Request.Query["cursor"].FirstOrDefault();
        return Results.Ok(session.GetState(cursor));
    }

    private async Task<IResult> HandleChunkAsync(HttpContext ctx, string id, string fileId, int index,
        CancellationToken ct)
    {
        var session = GetSessionScoped(ctx, id);
        var declared = ctx.Request.Headers["X-Chunk-Sha256"].FirstOrDefault();
        if (string.IsNullOrEmpty(declared))
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "X-Chunk-Sha256 header missing");
        var result = await session.PutChunkAsync(fileId, index, ctx.Request.Body, declared, ct);
        return Results.Ok(result);
    }

    private async Task<IResult> HandleCommitAsync(HttpContext ctx, string id, string fileId, CancellationToken ct)
    {
        var session = GetSessionScoped(ctx, id);
        using var doc = await ReadJson(ctx, ct);
        var root = doc.RootElement;
        var sha = root.GetProperty("fileSha256").GetString()
            ?? throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "fileSha256 missing");
        var size = root.GetProperty("size").GetInt64();
        var mtime = root.TryGetProperty("mtimeUtcNs", out var m) ? m.GetString() : null;
        var ctime = root.TryGetProperty("ctimeUtcNs", out var c) ? c.GetString() : null;
        var result = session.CommitFile(fileId, sha, size, mtime, ctime, ct);
        return Results.Ok(result);
    }

    // ------------------------------------------------------------- auth utils

    private static async Task<JsonDocument> ReadJson(HttpContext ctx, CancellationToken ct)
    {
        try
        {
            return await JsonDocument.ParseAsync(ctx.Request.Body, cancellationToken: ct);
        }
        catch (JsonException ex)
        {
            throw new ProtocolException(ErrorCode.E_BAD_REQUEST, "malformed JSON: " + ex.Message);
        }
    }

    private static string? Bearer(HttpContext ctx)
    {
        var header = ctx.Request.Headers.Authorization.FirstOrDefault();
        return header is not null && header.StartsWith("Bearer ", StringComparison.Ordinal)
            ? header["Bearer ".Length..]
            : null;
    }

    private string RequireDevice(HttpContext ctx)
    {
        var token = Bearer(ctx);
        return _deviceTokens.Validate(token, "device")
            ?? throw new ProtocolException(ErrorCode.E_UNAUTHORIZED, "valid deviceToken required");
    }

    private TransferSession GetSession(string id)
    {
        if (!_sessions.TryGetValue(id, out var session))
            throw new ProtocolException(ErrorCode.E_SESSION_NOT_FOUND, "unknown session");
        session.ExpireIfDue();
        return session;
    }

    /// <summary>Session endpoints: bearer must be a sessionToken scoped to this session.</summary>
    private TransferSession GetSessionScoped(HttpContext ctx, string id)
    {
        var session = GetSession(id);
        var token = Bearer(ctx);
        if (_sessionTokens.Validate(token, "session") != id)
            throw new ProtocolException(ErrorCode.E_UNAUTHORIZED, "valid sessionToken required");
        return session;
    }

    private TransferSession RequireSession(HttpContext ctx, string id) => GetSessionScoped(ctx, id);

    /// <summary>Session status in wire form: AwaitingApproval → AWAITING_APPROVAL.</summary>
    public static string WireStatus(SessionStatus status) =>
        Regex.Replace(status.ToString(), "([a-z0-9])([A-Z])", "$1_$2").ToUpperInvariant();

    public async ValueTask DisposeAsync()
    {
        foreach (var s in _sessions.Values)
        {
            try { s.Dispose(); } catch { /* best effort */ }
        }
        _certificate.Dispose();
        await _app.DisposeAsync();
    }
}
