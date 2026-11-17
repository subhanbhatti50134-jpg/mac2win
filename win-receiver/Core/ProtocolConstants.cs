namespace Mac2WinReceiver.Core;

/// <summary>Protocol-wide constants (protocol/PROTOCOL.md, protocol/VERSION).</summary>
public static class ProtocolConstants
{
    /// <summary>Wire protocol version. Bump only with a breaking change (new /vN prefix).</summary>
    public const int ProtocolVersion = 1;

    /// <summary>Default TCP port; configurable in receiver settings, advertised via mDNS.</summary>
    public const int DefaultPort = 48600;

    /// <summary>Bonjour/mDNS service type (SPEC §4).</summary>
    public const string ServiceType = "_mac2win._tcp";

    /// <summary>HTTP prefix for all endpoints.</summary>
    public const string PathPrefix = "/v1";

    /// <summary>Manifest batch caps (protocol §2.7).</summary>
    public const int MaxEntriesPerBatch = 1000;
    public const int MaxBatchJsonBytes = 1024 * 1024;

    /// <summary>Chunk size bounds (SPEC §5): 1 MiB .. 64 MiB, default 4 MiB.</summary>
    public const int MinChunkSize = 1 * 1024 * 1024;
    public const int MaxChunkSize = 64 * 1024 * 1024;
    public const int DefaultChunkSize = 4 * 1024 * 1024;

    /// <summary>PIN rules (SPEC §4).</summary>
    public const int PinMinDigits = 6;
    public const int PinMaxAgeSeconds = 300;
    public const int PinMaxFailedAttempts = 5;
}
