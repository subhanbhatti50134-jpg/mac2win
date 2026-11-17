using System.Text;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Durable write-ahead journal for one session (SPEC §5 Resume).
/// Ordering: chunk bytes are flushed to the staged file FIRST, then the journal line is
/// appended and fsynced — so a journaled chunk always exists on disk (write-ahead means
/// the intent record trails the data it describes; recovery never trusts unjournaled bytes).
///
/// Line format (ASCII, one record per line):
///   CHUNK &lt;fileId&gt; &lt;chunkIndex&gt; &lt;sha256hex&gt;
///   FILE  &lt;fileId&gt; &lt;sha256hex&gt; &lt;base64(destination-relative final path)&gt;
/// </summary>
public sealed class Journal : IDisposable
{
    private readonly object _gate = new();
    private readonly FileStream _stream;

    public string Path { get; }

    public Journal(string path)
    {
        Path = path;
        var dir = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read,
            bufferSize: 4096, FileOptions.None);
    }

    public void RecordChunk(string fileId, int chunkIndex, string sha256Hex)
    {
        lock (_gate)
        {
            var line = $"CHUNK {fileId} {chunkIndex} {sha256Hex}\n";
            _stream.Write(Encoding.ASCII.GetBytes(line));
            _stream.Flush(flushToDisk: true);
        }
    }

    public void RecordFileCommitted(string fileId, string sha256Hex, string destinationRelativePath)
    {
        lock (_gate)
        {
            var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(destinationRelativePath));
            var line = $"FILE {fileId} {sha256Hex} {b64}\n";
            _stream.Write(Encoding.ASCII.GetBytes(line));
            _stream.Flush(flushToDisk: true);
        }
    }

    /// <summary>Plays the journal back (M3 crash-recovery tests). Returns plain records.</summary>
    public static JournalSnapshot Replay(string path)
    {
        var snap = new JournalSnapshot();
        if (!File.Exists(path)) return snap;
        foreach (var raw in File.ReadLines(path))
        {
            var parts = raw.Split(' ', 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;
            switch (parts[0])
            {
                case "CHUNK" when parts.Length == 4:
                    if (int.TryParse(parts[2], out var idx))
                        snap.Chunks.Add((parts[1], idx, parts[3]));
                    break;
                case "FILE" when parts.Length == 4:
                    try
                    {
                        var rel = Encoding.UTF8.GetString(Convert.FromBase64String(parts[3]));
                        snap.Files.Add((parts[1], parts[2], rel));
                    }
                    catch (FormatException) { /* corrupt line: ignore, chunk-level data still trusted */ }
                    break;
            }
        }
        return snap;
    }

    public void Dispose()
    {
        lock (_gate) _stream.Dispose();
    }
}

public sealed class JournalSnapshot
{
    public List<(string FileId, int ChunkIndex, string Sha256Hex)> Chunks { get; } = new();
    public List<(string FileId, string Sha256Hex, string RelativePath)> Files { get; } = new();
}
