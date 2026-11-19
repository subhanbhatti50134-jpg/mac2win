using System.Security.Cryptography.X509Certificates;
using Mac2WinReceiver.Core.Certs;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Unit;

/// <summary>
/// Certificate subject handling (SPEC §4, ADR-007). The receiver app passes the device
/// name (settings DeviceName, default Environment.MachineName) to CreateEphemeral — a
/// bare hostname is not an X.500 DN, and CertificateRequest rejects it with
/// CryptographicException, which crashed the app at startup with no UI (Event Viewer,
/// 2026-11-19). A plain device name must therefore be escaped and wrapped in CN=.
/// </summary>
public sealed class CertificateProviderTests
{
    /// <summary>The exact value that crashed the shipped 0.1.0 installer build.</summary>
    private const string BareMachineName = "DESKTOP-IHAMU4O";

    [Fact]
    public void CreateEphemeral_BareMachineName_IssuedCert()
    {
        using var cert = CertificateProvider.CreateEphemeral(BareMachineName);
        Assert.Contains("CN=DESKTOP-IHAMU4O", cert.Subject, StringComparison.Ordinal);
        Assert.False(string.IsNullOrEmpty(CertificateProvider.FingerprintSha256(cert)));
    }

    [Fact]
    public void CreateEphemeral_ExistingDistinguishedName_UsedVerbatim()
    {
        using var cert = CertificateProvider.CreateEphemeral("CN=TEST-DEVICE");
        Assert.Equal("CN=TEST-DEVICE", cert.Subject);
    }

    [Fact]
    public void CreateEphemeral_DeviceNameWithRfc4514Metacharacters_IssuedCert()
    {
        // ',', '+', '"', '<', '>', ';' and '\' must be escaped inside a CN value.
        using var cert = CertificateProvider.CreateEphemeral(@"Lab-PC 1, A+B ""x"" <2>;c\d");
        Assert.StartsWith("CN=", cert.Subject, StringComparison.Ordinal);
        Assert.Contains("Lab-PC 1", cert.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateEphemeral_Null_DefaultsToMac2winReceiverName()
    {
        using var cert = CertificateProvider.CreateEphemeral();
        Assert.StartsWith("CN=mac2win-receiver-", cert.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void FingerprintSha256_Is64LowercaseHex_AndStableForSameCert()
    {
        using var cert = CertificateProvider.CreateEphemeral(BareMachineName);
        var fp = CertificateProvider.FingerprintSha256(cert);
        Assert.Matches("^[0-9a-f]{64}$", fp);
        Assert.Equal(fp, CertificateProvider.FingerprintSha256(cert));
        // 32 bytes → 32 * 2 hex chars + 31 separators = 95
        Assert.Equal(95, CertificateProvider.FingerprintColonSeparated(cert).Length);
    }

    [Fact]
    public void CreateEphemeral_ServesTls_ServerAuthEku()
    {
        using var cert = CertificateProvider.CreateEphemeral(BareMachineName);
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        var oids = eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>()
            .Select(o => o.Value).ToList();
        Assert.Contains("1.3.6.1.5.5.7.3.1", oids);
    }
}
