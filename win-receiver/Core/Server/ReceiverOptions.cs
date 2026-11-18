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

    /// <summary>
    /// Idle timeout for approved, non-terminal sessions: no protocol activity within this
    /// window expires the session (E_SESSION_EXPIRED) and purges its staging (SPEC §5
    /// resume-after-sleep ⇒ default is generous; SPEC §7 requires the limit to exist).
    /// Pre-approval sessions are bounded by <see cref="SessionTtl"/> and the 5-minute
    /// approval-dialog timeout instead. Set to <see cref="TimeSpan.Zero"/> to disable.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Auth-challenge lifetime (protocol §2.2 serverNonce TTL; default 5 min).</summary>
    public TimeSpan ChallengeTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Override for the PIN lifetime (protocol §4: 5 minutes). Null keeps the protocol
    /// default. Test harnesses only (fault-injection suite) — the shipping UI never sets this.
    /// </summary>
    public TimeSpan? PinMaxAge { get; set; }

    /// <summary>
    /// Pending auth nonces held before oldest-first eviction (SPEC §7: anonymous health/
    /// challenge floods must not grow memory without bound).
    /// </summary>
    public int MaxPendingChallenges { get; set; } = ProtocolConstants.MaxPendingChallenges;

    /// <summary>
    /// Sliding-window cap on unauthenticated auth requests per client IP
    /// (challenge/pair/hello). 0 or negative disables the limiter (SPEC §7 connection
    /// and rate limits).
    /// </summary>
    public int AuthRateLimit { get; set; } = 60;

    /// <summary>Sliding window for <see cref="AuthRateLimit"/>.</summary>
    public TimeSpan AuthRateWindow { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>No-progress timeout for reading a request body: a client that stalls mid-body is
    /// answered with E_IDLE_TIMEOUT instead of holding a connection forever (SPEC §7
    /// "endless streams"). Zero disables.
    /// </summary>
    public TimeSpan BodyStallTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Directories the destination must never be (inside) — Windows, Program Files,
    /// Program Data (SPEC §6.2). Null ⇒ <see cref="DestinationGuard.SystemRoots"/>.
    /// Tests inject synthetic roots.
    /// </summary>
    public IReadOnlyList<string>? ProtectedDestinationRoots { get; set; }

    /// <summary>
    /// Injection point for destination volume facts (tests substitute fake FAT32/low-disk
    /// volumes without needing real hardware). Null ⇒ real <see cref="DriveDestinationInfo"/>.
    /// </summary>
    public Func<string, IDestinationInfo>? DestinationInfoFactory { get; set; }

    public IDestinationInfo CreateDestinationInfo() =>
        DestinationInfoFactory?.Invoke(DestinationRoot) ?? new DriveDestinationInfo(DestinationRoot);
}
