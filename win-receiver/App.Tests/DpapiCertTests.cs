using System.IO;
using System.Security.Cryptography.X509Certificates;
using Mac2WinReceiver.App.Services;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>DPAPI certificate persistence: load/reuse/corrupt-regenerate (ADR-014).</summary>
public sealed class DpapiCertTests
{
    [Fact]
    public void LoadOrCreate_CreatesAndReusesCert()
    {
        var path = Path.Combine(Path.GetTempPath(), $"m2w-cert-test-{Guid.NewGuid()}.dat");
        try
        {
            var persistence = new CertificatePersistence(path);

            var cert1 = persistence.LoadOrCreate("CN=TEST-DEVICE");
            Assert.NotNull(cert1);
            Assert.False(string.IsNullOrEmpty(cert1.Thumbprint));

            // reload → same cert (thumbprint matches)
            var cert2 = persistence.LoadOrCreate("CN=TEST-DEVICE");
            Assert.Equal(cert1.Thumbprint, cert2.Thumbprint);

            cert1.Dispose();
            cert2.Dispose();
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void CorruptFile_RegeneratesCert()
    {
        var path = Path.Combine(Path.GetTempPath(), $"m2w-cert-corrupt-{Guid.NewGuid()}.dat");
        try
        {
            File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 }); // garbage
            var persistence = new CertificatePersistence(path);

            var cert = persistence.LoadOrCreate("CN=TEST-DEVICE");
            Assert.NotNull(cert);
            Assert.False(string.IsNullOrEmpty(cert.Thumbprint));
            cert.Dispose();
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
