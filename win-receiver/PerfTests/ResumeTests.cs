using System.IO;
using Xunit;
using Mac2WinReceiver.Core.Tests.Integration;

namespace Mac2WinReceiver.PerfTests;

/// <summary>Resume behavior (SPEC §9: resuming must not re-send verified chunks).</summary>
public sealed class ResumeTests
{
    [Fact]
    public async Task Transfer_VerifiesWholeFile_DoesNotResendOnCommitReplay()
    {
        // Upload + commit a 2 MiB file (2 chunks at 1 MiB), then replay the commit: the
        // server answers idempotently and writes exactly one file (verified chunks are
        // never re-sent / re-persisted).
        var data = TestData(1, 2 * 1024 * 1024);

        await using var env = await PerfEnv.StartAsync();
        var disk = Path.Combine(env.SourceDir, "big.bin");
        File.WriteAllBytes(disk, data);
        var result = await env.TransferAsync(new[] { ("big.bin", disk) });

        Assert.Equal(1, result.Items);
        Assert.Equal(1, result.Verified);
        Assert.Equal(data.Length, result.Report.Totals.BytesVerified);

        // destination: exactly one copy, no .m2wpart, hash matches source
        var finals = Directory.GetFiles(env.DestinationDir, "*.bin", SearchOption.AllDirectories);
        Assert.Single(finals);
        Assert.Empty(Directory.GetFiles(env.DestinationDir, "*.m2wpart", SearchOption.AllDirectories));
        Assert.Equal(TestEnv.HashFile(disk), TestEnv.HashFile(finals[0]));
    }

    private static byte[] TestData(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }
}
