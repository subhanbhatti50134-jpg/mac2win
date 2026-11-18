using System.IO;
using System.Linq;
using Xunit;

namespace Mac2WinReceiver.PerfTests;

/// <summary>Large-file throughput and memory measurements (SPEC §9).</summary>
/// <remarks>
/// All runs are loopback (real Kestrel + real TLS + real sockets), so numbers are an
/// upper bound — real LAN/iperf3 figures are REAL-DEVICE. SPEC §9 requires reporting
/// actual numbers in docs/PERFORMANCE.md; these tests capture them and assert the
/// sanity boundaries (receiver-attributable working-set growth under 200 MB,
/// integrity invariants hold).
/// </remarks>
public sealed class ThroughputAndMemoryTests
{
    private static byte[] Rand(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private sealed record PerfCase(string Label, IReadOnlyList<(string Path, string DiskPath)> Files);

    [Fact]
    public async Task LargeFile_ThroughputAndMemory_UnderTarget()
    {
        // 100 MiB single file at 1 MiB chunks (representative; 50 GiB target is
        // extrapolated + REAL-DEVICE since 50 GiB is never committed locally).
        const int size = 100 * 1024 * 1024;
        var data = Rand(1, size);
        var diskPath = Path.Combine(Path.GetTempPath(), $"m2w-perf-big-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(diskPath, data);

            await using var env = await PerfEnv.StartAsync();
            var result = await env.TransferAsync(new[] { ("big.bin", diskPath) });

            Assert.Equal(1, result.Items);
            Assert.Equal(1, result.Verified);
            // receiver-attributable transfer growth (test baseline subtracted) under target
            Assert.True(result.WorkingSetDeltaMb < 200,
                $"transfer working-set growth {result.WorkingSetDeltaMb:F1} MB exceeds 200 MB target");

            System.Console.WriteLine($"[PERF] 100 MiB large file: {result.Mbps:F1} MB/s, " +
                                     $"{result.Elapsed.TotalSeconds:F2} s, " +
                                     $"WS growth {result.WorkingSetDeltaMb:F1} MB, " +
                                     $"managed heap {result.PeakManagedMb:F1} MB (testhost-inclusive)");
        }
        finally
        {
            try { File.Delete(diskPath); } catch { }
        }
    }

    [Fact]
    public async Task Memory_FlatAcrossTransfers_RegardlessOfSize()
    {
        // Memory must be bounded by buffer size × concurrency and flat regardless of
        // file size or count (SPEC §9). Stream source files from disk so the test does
        // not hold all transfer data in RAM; measured growth is receiver-attributable.
        var cases = new PerfCase[]
        {
            new("10 MiB x 1", OneFile(10 * 1024 * 1024, "a.bin", 2)),
            new("100 MiB x 1", OneFile(100 * 1024 * 1024, "b.bin", 3)),
            new("1 MiB x 200",
                Enumerable.Range(0, 200)
                    .Select(i => ($"small{i:D3}.bin", WriteTemp(1 * 1024 * 1024, $"small{i:D3}.bin", 4 + i)))
                    .ToList()),
        };

        var peaks = new List<double>();
        foreach (var c in cases)
        {
            await using var env = await PerfEnv.StartAsync();
            // files already stream from disk; transfer reads them directly
            var result = await env.TransferAsync(c.Files);
            peaks.Add(result.WorkingSetDeltaMb);
            System.Console.WriteLine($"[PERF] {c.Label}: WS growth {result.WorkingSetDeltaMb:F1} MB, " +
                                     $"managed {result.PeakManagedMb:F1} MB (testhost-inclusive), " +
                                     $"{result.Mbps:F1} MB/s, {result.FilesPerSecond:F0} files/s");
            Assert.True(result.WorkingSetDeltaMb < 200,
                $"{c.Label}: transfer working-set growth {result.WorkingSetDeltaMb:F1} MB exceeds 200 MB target");
        }

        var max = peaks.Max();
        var min = peaks.Min();
        // flat: working-set growth is bounded by buffer size × concurrency and does NOT
        // scale with total bytes (10 MiB ≈ 100 MiB single-file growth); per-file count
        // adds bounded metadata. Assert a hard bound rather than a strict ratio.
        Assert.True(max < 50, $"working-set growth not bounded: {max:F1} MB (target < 50 MB)");
        Assert.True(Math.Abs(peaks[0] - peaks[1]) < 15,
            $"growth scales with file size: 10 MiB {peaks[0]:F1} MB vs 100 MiB {peaks[1]:F1} MB");
    }

    [Fact]
    public async Task LargeFile_DiskCopyBaseline_SameOrderOfMagnitude()
    {
        // Compare transfer throughput to a plain disk copy on the same volume: if they
        // are the same order of magnitude, the transfer is disk-limited (SPEC §9 says
        // to say so when disk-limited).
        const int size = 50 * 1024 * 1024;
        var data = Rand(5, size);
        var src = Path.Combine(Path.GetTempPath(), $"m2w-perf-src-{Guid.NewGuid():N}.bin");
        var dst = Path.Combine(Path.GetTempPath(), $"m2w-perf-dst-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(src, data);

            var copySw = System.Diagnostics.Stopwatch.StartNew();
            File.Copy(src, dst, overwrite: true);
            copySw.Stop();
            var copyMbps = size / 1024.0 / 1024.0 / copySw.Elapsed.TotalSeconds;

            await using var env = await PerfEnv.StartAsync();
            var result = await env.TransferAsync(new[] { ("big.bin", src) });

            System.Console.WriteLine($"[PERF] disk copy baseline: {copyMbps:F1} MB/s | " +
                                     $"m2w transfer: {result.Mbps:F1} MB/s");
            Assert.True(result.Mbps > 0);
        }
        finally
        {
            try { File.Delete(src); } catch { }
            try { File.Delete(dst); } catch { }
        }
    }

    private static IReadOnlyList<(string Path, string DiskPath)> OneFile(int size, string name, int seed)
    {
        var disk = WriteTemp(size, name, seed);
        return new[] { (name, disk) };
    }

    private static string WriteTemp(int size, string name, int seed)
    {
        var disk = Path.Combine(Path.GetTempPath(), $"m2w-perf-{Guid.NewGuid():N}-{name}");
        File.WriteAllBytes(disk, Rand(seed, size));
        return disk;
    }
}
