using System.Text;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// M3 crash-consistency unit tests for <see cref="TransferSession.Recover"/>: the on-disk
/// states a hard kill can leave behind — a commit intent whose rename never ran, unjournaled
/// tail bytes, stale chunk records after a file restart, a corrupted boundary chunk — must
/// recover to exactly one safe answer (SPEC §5 resume, §10 hard-kill fault injection).
/// </summary>
public sealed class RecoveryCrashWindowsTests
{
    private const int Chunk = 1024 * 1024;

    private sealed class Env : IDisposable
    {
        public string Root { get; }
        public string Dest { get; }
        public string StagingRoot { get; }
        public ReceiverOptions Options { get; }

        public Env()
        {
            Root = Path.Combine(Path.GetTempPath(), "m2w-rec-" + Guid.NewGuid().ToString("N"));
            Dest = Path.Combine(Root, "dst");
            StagingRoot = Path.Combine(Dest, ".mac2win-staging");
            Directory.CreateDirectory(Dest);
            Directory.CreateDirectory(StagingRoot);
            Options = new ReceiverOptions
            {
                DestinationRoot = Dest,
                ChunkSize = Chunk,
                FreeSpaceMarginBytes = 0,
            };
        }

        public SessionSnapshot Snapshot() => new()
        {
            SessionId = Guid.NewGuid().ToString(),
            OwnerDeviceId = "dev-1",
            Status = "Transferring",
            ChunkSize = Chunk,
            CreatedAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            LastActivityMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            BatchesReceived = 1,
            LastBatchItemStart = 0,
            LastBatchFinal = true,
        };

        public static ItemSnapshot FileItem(string fileId, string path, long size) => new()
        {
            Path = path,
            Type = "file",
            Size = size,
            MtimeUtcNs = "0",
            FileId = fileId,
            Action = "CREATE",
            FinalRelativePath = path,
            Outcome = "PENDING",
        };

        public string SessionDir(string id) => Path.Combine(StagingRoot, id);

        public void Dispose()
        {
            try { Directory.Delete(Root, recursive: true); }
            catch (IOException) { /* temp cleanup best effort */ }
            catch (UnauthorizedAccessException) { /* temp cleanup best effort */ }
        }
    }

    private static byte[] Data(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string ChunkLine(string fileId, int index, byte[] bytes) =>
        $"CHUNK {fileId} {index} {TestEnv.HashBytes(bytes)}\n";

    private static string FileLine(string fileId, byte[] bytes, string finalRel) =>
        $"FILE {fileId} {TestEnv.HashBytes(bytes)} " +
        $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(finalRel))}\n";

    // ------------------------------------------------------------ crash windows

    [Fact]
    public void Recovery_CompletesRenameFromJournalIntent()
    {
        using var env = new Env();
        var id = Guid.NewGuid().ToString();
        var dir = env.SessionDir(id);
        Directory.CreateDirectory(dir);

        var data = Data(1, 5000);
        var sha = TestEnv.HashBytes(data);

        // bytes flushed and journaled, but the kill landed before File.Move ran
        File.WriteAllBytes(Path.Combine(dir, "f-0000.m2wpart"), data);
        File.WriteAllText(Path.Combine(dir, "journal.log"),
            ChunkLine("f-0000", 0, data) + FileLine("f-0000", data, "target.dat"));

        var snap = env.Snapshot();
        snap.SessionId = id;
        snap.Items.Add(Env.FileItem("f-0000", "target.dat", data.Length));

        using var session = TransferSession.Recover(
            env.Options, new FakeDestinationInfo(env.Dest), snap);

        var item = Assert.Single(session.Items);
        Assert.True(item.Committed);
        Assert.Equal("VERIFIED", item.Outcome);
        var finalPath = Path.Combine(env.Dest, "target.dat");
        Assert.True(File.Exists(finalPath));
        Assert.Equal(sha, TestEnv.HashFile(finalPath));
        Assert.False(File.Exists(Path.Combine(dir, "f-0000.m2wpart"))); // moved, not copied

        // a replayed commit after recovery is idempotent (no second move, same outcome)
        var replay = session.CommitFile("f-0000", sha, data.Length, null, null,
            CancellationToken.None);
        Assert.Equal("VERIFIED", replay.Outcome);
        Assert.Equal(finalPath, replay.FinalPath);
    }

    [Fact]
    public void Recovery_CommitIntentWhoseDataIsGone_FailsTerminally()
    {
        using var env = new Env();
        var id = Guid.NewGuid().ToString();
        var dir = env.SessionDir(id);
        Directory.CreateDirectory(dir);

        var data = Data(2, 5000);
        // FILE intent journaled, but neither the staged file nor the final file exists
        File.WriteAllText(Path.Combine(dir, "journal.log"),
            ChunkLine("f-0000", 0, data) + FileLine("f-0000", data, "lost.dat"));

        var snap = env.Snapshot();
        snap.SessionId = id;
        snap.Items.Add(Env.FileItem("f-0000", "lost.dat", data.Length));

        using var session = TransferSession.Recover(
            env.Options, new FakeDestinationInfo(env.Dest), snap);

        var item = Assert.Single(session.Items);
        Assert.False(item.Committed);
        Assert.Equal("FAILED", item.Outcome);
        Assert.NotNull(item.OutcomeReason);
        Assert.False(File.Exists(Path.Combine(env.Dest, "lost.dat")));
    }

    [Fact]
    public void Recovery_DistrustsUnjournaledTailBytes()
    {
        using var env = new Env();
        var id = Guid.NewGuid().ToString();
        var dir = env.SessionDir(id);
        Directory.CreateDirectory(dir);

        var chunk0 = Data(3, Chunk);
        var size = 2L * Chunk;

        // staged file: verified chunk 0, then 1000 bytes of a chunk-1 write that was
        // never journaled (the kill landed between the data flush and the journal append)
        using (var fs = File.Create(Path.Combine(dir, "f-0000.m2wpart")))
        {
            fs.Write(chunk0);
            fs.Write(Data(4, 1000));
        }
        File.WriteAllText(Path.Combine(dir, "journal.log"), ChunkLine("f-0000", 0, chunk0));

        var snap = env.Snapshot();
        snap.SessionId = id;
        snap.Items.Add(Env.FileItem("f-0000", "tail.bin", size));

        using var session = TransferSession.Recover(
            env.Options, new FakeDestinationInfo(env.Dest), snap);

        var state = session.GetState(null);
        var partial = Assert.Single(state.Partial);
        Assert.Equal("tail.bin", partial.Path);
        Assert.Equal(new[] { 0 }, partial.VerifiedChunks);
        Assert.Equal(1, partial.NextChunk); // the unjournaled tail is never trusted
        Assert.Equal(Chunk, Assert.Single(session.Items).BytesReceived);
    }

    [Fact]
    public void Recovery_DistrustsStaleChunksAfterFileRestart()
    {
        using var env = new Env();
        var id = Guid.NewGuid().ToString();
        var dir = env.SessionDir(id);
        Directory.CreateDirectory(dir);

        var oldChunk0 = Data(5, Chunk);
        var newChunk0 = Data(6, Chunk);
        var size = 2L * Chunk;

        // after a source change the file restarted: RESET invalidated the old records and
        // chunk 0 was re-sent with new bytes; the kill happened before chunk 1 was re-sent
        File.WriteAllBytes(Path.Combine(dir, "f-0000.m2wpart"), newChunk0);
        File.WriteAllText(Path.Combine(dir, "journal.log"),
            ChunkLine("f-0000", 0, oldChunk0) +
            ChunkLine("f-0000", 1, Data(7, Chunk)) +
            "RESET f-0000\n" +
            ChunkLine("f-0000", 0, newChunk0));

        var snap = env.Snapshot();
        snap.SessionId = id;
        snap.Items.Add(Env.FileItem("f-0000", "restarted.bin", size));

        using var session = TransferSession.Recover(
            env.Options, new FakeDestinationInfo(env.Dest), snap);

        var item = Assert.Single(session.Items);
        // chunk 0 recovered with the NEW hash (pre-RESET records are gone); chunk 1 was
        // never re-sent, so it must not be trusted even though a stale record exists
        Assert.Equal(new[] { 0 }, item.VerifiedChunks);
        Assert.Equal(TestEnv.HashBytes(newChunk0), item.ChunkHashes[0]);
        var state = session.GetState(null);
        Assert.Equal(1, Assert.Single(state.Partial).NextChunk);
    }

    [Fact]
    public void Recovery_BoundaryHashMismatch_DropsBoundaryAndAbove()
    {
        using var env = new Env();
        var id = Guid.NewGuid().ToString();
        var dir = env.SessionDir(id);
        Directory.CreateDirectory(dir);

        var chunk0 = Data(8, Chunk);
        var chunk1 = Data(9, Chunk);
        var chunk2 = Data(10, Chunk);
        var size = 3L * Chunk;

        // all three chunks journaled and present, but the boundary chunk's on-disk bytes
        // were corrupted after the flush (bit rot / partial overwrite)
        using (var fs = File.Create(Path.Combine(dir, "f-0000.m2wpart")))
        {
            fs.Write(chunk0);
            fs.Write(chunk1);
            fs.Write(Data(11, Chunk)); // wrong bytes where chunk 2 should be
        }
        File.WriteAllText(Path.Combine(dir, "journal.log"),
            ChunkLine("f-0000", 0, chunk0) +
            ChunkLine("f-0000", 1, chunk1) +
            ChunkLine("f-0000", 2, chunk2));

        var snap = env.Snapshot();
        snap.SessionId = id;
        snap.Items.Add(Env.FileItem("f-0000", "rotten.bin", size));

        using var session = TransferSession.Recover(
            env.Options, new FakeDestinationInfo(env.Dest), snap);

        var state = session.GetState(null);
        var partial = Assert.Single(state.Partial);
        // the boundary (chunk 2) failed its re-hash: it and everything above are distrusted,
        // chunks 0-1 stay — the sender resumes by re-sending chunk 2 (SPEC §5)
        Assert.Equal(new[] { 0, 1 }, partial.VerifiedChunks);
        Assert.Equal(2, partial.NextChunk);
    }
}
