namespace Mac2WinReceiver.App.ViewModels;

/// <summary>One row in the receiver's progress/history list (SPEC §8).</summary>
public sealed class SessionRow
{
    public string SessionId { get; init; } = string.Empty;
    public string DeviceName { get; init; } = string.Empty;
    public string RemoteIp { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public long TotalBytes { get; init; }
    public long BytesReceived { get; init; }
    public int FilesCompleted { get; init; }
    public int FilesTotal { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public double Percent => FilesTotal > 0 ? (double)FilesCompleted / FilesTotal * 100 : 0;
}
