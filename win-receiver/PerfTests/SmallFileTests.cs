using System.IO;
using System.Linq;
using Xunit;

namespace Mac2WinReceiver.PerfTests;

/// <summary>Small-file rate measurements (SPEC §9: ≥500 files/s for 4–64 KB files).</summary>
/// <remarks>
/// Loopback upper bound; real gigabit-LAN figures are REAL-DEVICE. Our protocol already
/// performs the naive one-request-per-file baseline (one PUT + one commit per file), so
/// this measures that path end to end. Per SPEC §9 "validate or revise with data":
/// actual rates are reported below and compared to the 500 files/s target; the test
/// asserts sanity (> 0) rather than hard-failing, since loopback request overhead differs
/// from a gigabit LAN and the target is a LAN figure.
/// </remarks>
public sealed class SmallFileTests
{
    [Theory]
    [InlineData(4 * 1024, 2000, "4 KB")]
    [InlineData(16 * 1024, 2000, "16 KB")]
    [InlineData(64 * 1024, 2000, "64 KB")]
    public async Task SmallFileRate_ReportVsTarget(int fileSize, int fileCount, string label)
    {
        await using var env = await PerfEnv.StartAsync();
        var files = new List<(string Path, string DiskPath)>();
        var rng = new Random(42);
        for (var i = 0; i < fileCount; i++)
        {
            var bytes = new byte[fileSize];
            rng.NextBytes(bytes);
            var disk = Path.Combine(env.SourceDir, $"file{i:D5}.bin");
            File.WriteAllBytes(disk, bytes);
            files.Add(($"file{i:D5}.bin", disk));
        }

        var result = await env.TransferAsync(files);

        Assert.Equal(fileCount, result.Items);
        Assert.Equal(fileCount, result.Verified);
        System.Console.WriteLine($"[PERF] {label} x {fileCount}: " +
                                 $"{result.FilesPerSecond:F0} files/s, " +
                                 $"{result.Mbps:F1} MB/s, {result.Elapsed.TotalSeconds:F2} s " +
                                 $"(target ≥500 files/s)");

        Assert.True(result.FilesPerSecond > 0);
    }
}
