using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Mac2WinReceiver.Core.Server;

/// <summary>Decision returned by the receiver's approval handler (SPEC §4: explicit user approval).</summary>
public sealed record ApprovalDecision(bool Approved, string? Reason = null)
{
    public static readonly ApprovalDecision Approve = new(true);
    public static readonly ApprovalDecision Deny = new(false, "denied by receiver");
}

/// <summary>
/// Configuration of the headless receiver server. The UI (M4) constructs this from user
/// settings; the test harness constructs it directly. There is no hidden default: a server
/// without an <see cref="ApprovalHandler"/> denies every request (SPEC §7 — no silent acceptance).
/// </summary>
public sealed class ReceiverOptions
{
    /// <summary>Device name shown to the Mac (approval dialog, mDNS).</summary>
    public string DeviceName { get; set; } = Environment.MachineName;

    /// <summary>TCP port; 0 = ephemeral (tests). Production default is ProtocolConstants.DefaultPort.</summary>
    public int Port { get; set; } = ProtocolConstants.DefaultPort;

    /// <summary>Bind address — local interfaces only (SPEC §4). Loopback for tests.</summary>
    public IPAddress BindAddress { get; set; } = IPAddress.Loopback;

    /// <summary>Root directory that receives transferred files. Must exist and be writable.</summary>
    public required string DestinationRoot { get; set; }

    /// <summary>Staging root; defaults to &lt;DestinationRoot&gt;/.mac2win-staging (same volume ⇒ atomic rename).</summary>
    public string? StagingRoot { get; set; }

    /// <summary>Chunk size for this receiver (protocol §2.8 response may lower the sender's request).</summary>
    public int ChunkSize { get; set; } = ProtocolConstants.DefaultChunkSize;

    /// <summary>TLS certificate. Null ⇒ generate an ephemeral self-signed certificate at startup.</summary>
    public X509Certificate2? Certificate { get; set; }

    /// <summary>
    /// Explicit approval handler (UI dialog in M4). Null ⇒ all session requests are DENIED —
    /// this is the safe default; production wiring must set it (SPEC §7).
    /// </summary>
    public Func<SessionSummary, CancellationToken, Task<ApprovalDecision>>? ApprovalHandler { get; set; }

    /// <summary>
    /// Fixed PIN for test/dev harnesses (ReceiverHost --pin). When null, a CSPRNG PIN is
    /// generated at startup and rotated after every successful pairing (SPEC §4).
    /// The shipping UI never sets this.
    /// </summary>
    public string? FixedTestPin { get; set; }

    /// <summary>Re-read and hash staged bytes before rename (SPEC §5, default ON).</summary>
    public bool VerifyAfterWrite { get; set; } = true;

    /// <summary>Session TTL (SPEC §5: default 7 days).</summary>
    public TimeSpan SessionTtl { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Free-space safety margin required at confirm time (bytes).</summary>
    public long FreeSpaceMarginBytes { get; set; } = 64 * 1024 * 1024;

    /// <summary>Idle timeout for in-session requests (protocol E_IDLE_TIMEOUT).</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Injection point for destination volume facts (tests substitute fake FAT32/low-disk
    /// volumes without needing real hardware). Null ⇒ real <see cref="DriveDestinationInfo"/>.
    /// </summary>
    public Func<string, IDestinationInfo>? DestinationInfoFactory { get; set; }

    public IDestinationInfo CreateDestinationInfo() =>
        DestinationInfoFactory?.Invoke(DestinationRoot) ?? new DriveDestinationInfo(DestinationRoot);
}
