using System.Security.Cryptography.X509Certificates;
using Mac2WinReceiver.Core.Certs;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// One running receiver on loopback with real TLS, plus temp source/destination trees.
/// AUTOMATED level: real sockets, real Kestrel, pinned test certificate (SPEC §7).
/// </summary>
public sealed class TestEnv : IAsyncDisposable
{
    /// <summary>Fixed test PIN (harness only — production PINs are CSPRNG, single-use).</summary>
    public const string TestPin = "483920";

    public ReceiverServer Server { get; private set; }
    public string Root { get; }
    public string SourceDir { get; }
    public string DestinationDir { get; }
    public Uri BaseUri => new($"https://127.0.0.1:{Server.Port}");
    public IDestinationInfo DestinationInfo { get; private set; } = null!;

    private readonly ReceiverOptions _options;

    private TestEnv(ReceiverServer server, ReceiverOptions options, string root, string source,
        string destination)
    {
        Server = server;
        _options = options;
        Root = root;
        SourceDir = source;
        DestinationDir = destination;
    }

    public static async Task<TestEnv> StartAsync(
        Func<ReceiverOptions, ReceiverOptions>? configure = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "m2w-it-" + Guid.NewGuid().ToString("N"));
        var source = Path.Combine(root, "src");
        var destination = Path.Combine(root, "dst");
        Directory.CreateDirectory(source);
        Directory.CreateDirectory(destination);

        var options = new ReceiverOptions
        {
            DestinationRoot = destination,
            Port = 0, // ephemeral
            BindAddress = System.Net.IPAddress.Loopback,
            DeviceName = "TEST-PC",
            FixedTestPin = TestPin,
            // approve-all harness handler (SPEC §4 requires the real UI dialog in production;
            // this is the test stand-in for that dialog)
            ApprovalHandler = (_, _) => Task.FromResult(ApprovalDecision.Approve),
            ChunkSize = 1024 * 1024, // 1 MiB keeps boundary tests small and fast
            FreeSpaceMarginBytes = 0,
        };
        options = configure?.Invoke(options) ?? options;
        // one certificate for the whole env: a restart must keep the pinned fingerprint
        options.Certificate ??= CertificateProvider.CreateEphemeral();

        var server = await ReceiverServer.StartAsync(options);
        var env = new TestEnv(server, options, root, source, destination);
        env.DestinationInfo = options.CreateDestinationInfo();
        return env;
    }

    /// <summary>
    /// Simulates a hard kill of the receiver followed by a fresh start (M3 crash
    /// consistency): every persist happens synchronously inside the operation path, so
    /// tearing the server down without any extra flush leaves exactly the on-disk state a
    /// kill -9 would. The new server binds a new ephemeral port over the same
    /// destination/staging tree with the same certificate.
    /// </summary>
    public async Task RestartServerAsync()
    {
        await Server.DisposeAsync();
        Server = await ReceiverServer.StartAsync(_options);
        DestinationInfo = _options.CreateDestinationInfo();
    }

    /// <summary>Creates a client with the pinned server fingerprint (no accept-all path).</summary>
    public ProtocolTestClient CreateClient() => new(BaseUri, Server.CertFingerprint);

    public async Task<ProtocolTestClient> AuthenticatedClientAsync()
    {
        var client = CreateClient();
        await client.AuthenticateAsync(TestPin);
        return client;
    }

    /// <summary>Computes SHA-256 of a file, lowercase hex.</summary>
    public static string HashFile(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs))
            .ToLowerInvariant();
    }

    public static string HashBytes(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync();
        _options.Certificate?.Dispose(); // env owns the cert (server never disposes it)
        try
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
        catch (IOException) { /* temp cleanup best effort */ }
        catch (UnauthorizedAccessException) { /* temp cleanup best effort */ }
    }
}

/// <summary>Sync-over-async helpers kept small so tests read linearly.</summary>
public static class TestSync
{
    public static T Run<T>(Func<Task<T>> f) => f().GetAwaiter().GetResult();
}
