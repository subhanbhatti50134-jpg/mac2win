using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mac2WinReceiver.Core.Certs;

namespace Mac2WinReceiver.App.Services;

/// <summary>Per-install certificate persisted with DPAPI (ADR-014: ephemeral PFX round-trip +
/// PersistKeySet\|UserKeySet). Lives in the App project because DPAPI is Windows-only.</summary>
public sealed class CertificatePersistence
{
    private readonly string _path;

    public CertificatePersistence(string path) => _path = path;

    /// <summary>Load an existing cert or create a new per-install one and persist it.</summary>
    public X509Certificate2 LoadOrCreate(string subjectName)
    {
        if (File.Exists(_path))
        {
            try
            {
                var protectedBytes = File.ReadAllBytes(_path);
                var pfx = ProtectedData.Unprotect(protectedBytes, null,
                    DataProtectionScope.CurrentUser);
#pragma warning disable SYSLIB0057 // X509Certificate2 constructor obsolete on net10; DPAPI flow needs it
                return new X509Certificate2(pfx, (string?)null,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
#pragma warning restore SYSLIB0057
            }
            catch
            {
                // corrupt file → regenerate
            }
        }
        return CreateAndPersist(subjectName);
    }

    public X509Certificate2 CreateAndPersist(string subjectName)
    {
        using var cert = CertificateProvider.CreateEphemeral(subjectName);
        var pfx = cert.Export(X509ContentType.Pfx);
        var protectedBytes = ProtectedData.Protect(pfx, null, DataProtectionScope.CurrentUser);
        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, _path, overwrite: true);
#pragma warning disable SYSLIB0057 // X509Certificate2 constructor obsolete on net10; DPAPI flow needs it
        return new X509Certificate2(pfx, (string?)null,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
#pragma warning restore SYSLIB0057
    }
}
