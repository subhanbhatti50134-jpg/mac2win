using System.Text.Json;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Durable session metadata (SPEC §5: "sessions survive app restarts"). Written atomically
/// (temp file + rename) next to the session's staging directory on every state transition;
/// per-chunk progress lives in the write-ahead <see cref="Journal"/> instead, so a crash
/// between transitions never corrupts the last good snapshot (M3 crash consistency).
/// </summary>
public sealed class SessionSnapshot
{
    public int Version { get; set; } = 1;
    public string SessionId { get; set; } = "";
    public string OwnerDeviceId { get; set; } = "";
    public string Status { get; set; } = "";
    public string? SessionToken { get; set; }
    public long CreatedAtMs { get; set; }
    public long? ApprovedAtMs { get; set; }
    public long LastActivityMs { get; set; }
    public int ChunkSize { get; set; }

    // summary shown in the approval dialog
    public string SourceDeviceName { get; set; } = "";
    public long FileCount { get; set; }
    public long DirCount { get; set; }
    public long SymlinkCount { get; set; }
    public long TotalBytes { get; set; }
    public string RemoteIp { get; set; } = "";

    // manifest progress (chunk progress is NOT here — the journal owns it)
    public int BatchesReceived { get; set; }
    public string? ManifestDigest { get; set; }
    public long PlannedFileBytes { get; set; }
    /// <summary>Index into <see cref="Items"/> where the last accepted batch started (idempotent replay).</summary>
    public int LastBatchItemStart { get; set; } = -1;
    public bool LastBatchFinal { get; set; }
    public Dictionary<string, string> ConflictResolutions { get; set; } = new();

    public List<ItemSnapshot> Items { get; set; } = new();

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.General);

    /// <summary>Metadata path for a session: sits NEXT TO (not inside) the staging directory.</summary>
    public static string MetadataPath(string stagingRoot, string sessionId) =>
        Path.Combine(stagingRoot, sessionId + ".session.json");

    /// <summary>Paired-device records shared by every session (re-pairing must survive restarts).</summary>
    public static string DevicesPath(string stagingRoot) =>
        Path.Combine(stagingRoot, "devices.json");

    /// <summary>Loads a snapshot; null when missing or corrupt (a corrupt file never blocks startup).</summary>
    public static SessionSnapshot? Load(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            return JsonSerializer.Deserialize<SessionSnapshot>(File.ReadAllText(path), Json);
        }
        catch (JsonException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>Atomic write: readers never observe a half-written snapshot.</summary>
    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>One manifest item's durable ledger/plan state (transfer progress excluded).</summary>
public sealed class ItemSnapshot
{
    public string Path { get; set; } = "";
    public string Type { get; set; } = "";
    public long Size { get; set; }
    public string MtimeUtcNs { get; set; } = "0";
    public string? CtimeUtcNs { get; set; }
    public long Mode { get; set; }
    public string? SymlinkTarget { get; set; }
    public string? SenderState { get; set; }
    public string? FileId { get; set; }
    public string Action { get; set; } = "CREATE";
    public string? FinalRelativePath { get; set; }
    public string? PlanReason { get; set; }
    public bool OverwriteAllowed { get; set; }
    public bool Committed { get; set; }
    public string? FileSha256 { get; set; }
    public string Outcome { get; set; } = "PENDING";
    public string? OutcomeReason { get; set; }
    public string? OutcomeErrorCode { get; set; }
}

/// <summary>
/// Paired-device records on disk (SPEC §4 trusted devices): a device that paired before a
/// receiver restart stays trusted — re-pairing would need a fresh PIN the user may not have.
/// Tokens are NOT persisted; the device obtains a fresh one via /v1/auth/hello (signed challenge).
/// </summary>
public sealed class DeviceStore
{
    public List<StoredDevice> Devices { get; set; } = new();

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.General);

    public static DeviceStore Load(string path)
    {
        if (!File.Exists(path)) return new DeviceStore();
        try
        {
            return JsonSerializer.Deserialize<DeviceStore>(File.ReadAllText(path), Json)
                   ?? new DeviceStore();
        }
        catch (JsonException) { return new DeviceStore(); }
        catch (IOException) { return new DeviceStore(); }
        catch (UnauthorizedAccessException) { return new DeviceStore(); }
    }

    /// <summary>Best effort: a failed device-store write degrades restart behavior, never live pairing.</summary>
    public void Save(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
            File.Move(tmp, path, overwrite: true);
        }
        catch (IOException) { /* best effort — see summary */ }
        catch (UnauthorizedAccessException) { /* best effort — see summary */ }
    }
}

public sealed class StoredDevice
{
    public string KeyId { get; set; } = "";          // sha256(devicePublicKey) hex
    public string DeviceId { get; set; } = "";
    public string PublicKeyDerBase64 { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public long PairedAtMs { get; set; }
}
