using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Mac2WinReceiver.Core.Tests.Integration;

namespace Mac2WinReceiver.PerfTests;

/// <summary>Measurement harness for M5 performance tests.</summary>
/// <remarks>
/// Wraps <see cref="TestEnv"/> (real Kestrel + real TLS + real sockets on loopback). Source
/// files live on disk and are streamed chunk-by-chunk during the transfer, so the test
/// process never holds all transfer data in RAM — measured memory growth is therefore
/// receiver-attributable (bounded by chunk buffer × concurrency) rather than test-data
/// size. Numbers are loopback upper bounds; real LAN/iperf3 figures are REAL-DEVICE.
/// </remarks>
public sealed class PerfEnv : IAsyncDisposable
{
    public TestEnv Env { get; }
    public ProtocolTestClient Client { get; }
    public string SourceDir => Env.SourceDir;
    public string DestinationDir => Env.DestinationDir;

    private readonly Task _sampler;
    private readonly CancellationTokenSource _sampleCts = new();
    private long _peakManagedBytes;
    private long _baselineWorkingSetBytes;
    private long _peakWorkingSetBytes;

    private PerfEnv(TestEnv env, ProtocolTestClient client)
    {
        Env = env;
        Client = client;
        _sampler = Task.Run(SampleLoop);
    }

    public static async Task<PerfEnv> StartAsync(int? chunkSize = null, long? freeSpaceMargin = null)
    {
        var env = await TestEnv.StartAsync(o =>
        {
            if (chunkSize is { } cs) o.ChunkSize = cs;
            if (freeSpaceMargin is { } fsm) o.FreeSpaceMarginBytes = fsm;
            return o;
        });
        var client = await env.AuthenticatedClientAsync();
        return new PerfEnv(env, client);
    }

    private void SampleLoop()
    {
        try
        {
            while (!_sampleCts.Token.IsCancellationRequested)
            {
                var mw = GC.GetTotalMemory(false);
                if (mw > _peakManagedBytes) _peakManagedBytes = mw;
                var ws = Process.GetCurrentProcess().WorkingSet64;
                if (ws > _peakWorkingSetBytes) _peakWorkingSetBytes = ws;
                Thread.Sleep(50);
            }
        }
        catch (OperationCanceledException) { }
        catch { /* sampler is best-effort */ }
    }

    /// <summary>Writes deterministic pseudo-random source files to disk keyed by manifest path.</summary>
    public void WriteSource(string relPath, byte[] data)
    {
        var disk = Path.Combine(SourceDir, relPath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(disk)!);
        File.WriteAllBytes(disk, data);
    }

    /// <summary>Runs a full transfer of the given on-disk files and returns measured results.</summary>
    public async Task<PerfResult> TransferAsync(IReadOnlyList<(string Path, string DiskPath)> files)
    {
        var totalBytes = files.Sum(f =>
        {
            try { return new FileInfo(f.DiskPath).Length; }
            catch { return 0L; }
        });
        var mtime = MtimeNs(DateTime.UtcNow);
        var entries = files.Select(f =>
            new Entry(f.Path, "file", totalBytes == 0 ? 0 : new FileInfo(f.DiskPath).Length, mtime, 420)).ToList();

        // capture receiver-attributable baseline right before the transfer
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        _baselineWorkingSetBytes = Process.GetCurrentProcess().WorkingSet64;
        _peakManagedBytes = GC.GetTotalMemory(false);
        _peakWorkingSetBytes = _baselineWorkingSetBytes;

        var allDigestEntries = entries.Select(e =>
            new ManifestDigest.Entry(e.Path, e.Type, e.Size, e.MtimeUtcNs, e.Mode)).ToList();
        var digest = ManifestDigest.ComputeHex(allDigestEntries);

        var sw = Stopwatch.StartNew();
        var sid = await Client.CreateSessionAsync(files.Count, 0, totalBytes);
        var token = await Client.AwaitApprovalAsync(sid);

        // manifests are capped at MaxEntriesPerBatch per batch; send multi-batch when needed
        var fileIds = new List<string>();
        var batchSize = ProtocolConstants.MaxEntriesPerBatch;
        for (var b = 0; b < entries.Count; b += batchSize)
        {
            var batch = entries.Skip(b).Take(batchSize).ToList();
            var isLast = b + batchSize >= entries.Count;
            var manifestResp = await Client.SendManifestAsync(sid, token, batch, final: isLast,
                digest: isLast ? digest : null, batchIndex: b / batchSize);
            if (!manifestResp.IsSuccess)
                throw new InvalidOperationException(
                    $"manifest batch {b / batchSize}: {manifestResp.Status} {manifestResp.ErrorCode} {manifestResp.ErrorMessage}");
            foreach (var p in manifestResp.Body.GetProperty("planned").EnumerateArray())
            {
                if (!p.TryGetProperty("fileId", out var fid) || fid.GetString() is not { } fidStr)
                    throw new InvalidOperationException("manifest planned entry missing fileId");
                fileIds.Add(fidStr);
            }
        }

        var confirm = await Client.ConfirmAsync(sid, token);
        if (!confirm.IsSuccess)
            throw new InvalidOperationException($"confirm: {confirm.Status} {confirm.ErrorCode} {confirm.ErrorMessage}");

        var chunkSize = Env.Server.Options.ChunkSize;
        foreach (var ((path, diskPath), fileId) in files.Zip(fileIds))
        {
            var size = new FileInfo(diskPath).Length;
            var chunkCount = size == 0 ? 0 : (int)((size + chunkSize - 1) / chunkSize);
            using var wholeHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var fs = File.OpenRead(diskPath);
            var buffer = new byte[chunkSize];
            for (var i = 0; i < chunkCount; i++)
            {
                var len = fs.Read(buffer, 0, (int)Math.Min(chunkSize, size - i * chunkSize));
                var chunkMem = buffer.AsMemory(0, len);
                wholeHash.AppendData(chunkMem.Span);
                var chunkResp = await Client.UploadChunkAsync(sid, token, fileId, i,
                    chunkMem, TestEnv.HashBytes(chunkMem.Span));
                if (!chunkResp.IsSuccess)
                    throw new InvalidOperationException($"chunk {i} of {path}: {chunkResp.Status} {chunkResp.ErrorCode} {chunkResp.ErrorMessage}");
            }
            var wholeFileHex = Convert.ToHexString(wholeHash.GetHashAndReset()).ToLowerInvariant();
            var commit = await Client.CommitAsync(sid, token, fileId,
                wholeFileHex, size, mtime);
            if (!commit.IsSuccess)
                throw new InvalidOperationException($"commit {path}: {commit.Status} {commit.ErrorCode} {commit.ErrorMessage}");
        }

        var complete = await Client.CompleteAsync(sid, token);
        if (!complete.IsSuccess)
            throw new InvalidOperationException($"complete: {complete.Status} {complete.ErrorCode} {complete.ErrorMessage}");
        sw.Stop();

        // invariants (SPEC §10)
        var reportResp = complete.Body.TryGetProperty("report", out var r) ? r : complete.Body;
        var report = reportResp.Deserialize<SessionReport>(new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        })!;
        var partials = Directory.Exists(DestinationDir)
            ? Directory.GetFiles(DestinationDir, "*.m2wpart", SearchOption.AllDirectories)
            : Array.Empty<string>();
        if (partials.Length > 0)
            throw new InvalidOperationException($"partial files at final path: {string.Join(",", partials)}");
        foreach (var item in report.Items)
        {
            if (item.Outcome is not ("VERIFIED" or "RENAMED" or "REPLACED")) continue;
            var dst = item.FinalPath ?? throw new InvalidOperationException($"no final path for {item.Path}");
            if (!File.Exists(dst)) throw new InvalidOperationException($"missing final file {dst}");
            var src = files.FirstOrDefault(f => f.Path == item.Path);
            if (src.DiskPath is { } disk &&
                !TestEnv.HashFile(disk).Equals(TestEnv.HashFile(dst), StringComparison.Ordinal))
                throw new InvalidOperationException($"hash mismatch for {dst}");
        }

        _sampleCts.Cancel();
        await _sampler;

        return new PerfResult(sid, report, sw.Elapsed, totalBytes,
            _peakWorkingSetBytes - _baselineWorkingSetBytes, _peakManagedBytes);
    }

    private static string MtimeNs(DateTime utc) =>
        ((utc - DateTime.UnixEpoch).Ticks * 100L).ToString();

    public async ValueTask DisposeAsync()
    {
        _sampleCts.Cancel();
        try { await _sampler; } catch { }
        await Env.DisposeAsync();
    }
}

public sealed record PerfResult(
    string SessionId, SessionReport Report, TimeSpan Elapsed, long TotalBytes,
    long WorkingSetDeltaBytes, long PeakManagedBytes)
{
    public double Mbps => TotalBytes / 1024.0 / 1024.0 / Elapsed.TotalSeconds;
    public double WorkingSetDeltaMb => WorkingSetDeltaBytes / 1024.0 / 1024.0;
    public double PeakManagedMb => PeakManagedBytes / 1024.0 / 1024.0;
    public double FilesPerSecond => Report.Items.Count / Elapsed.TotalSeconds;
    public long Items => Report.Totals.Items;
    public long Verified => Report.Totals.Verified;
}
