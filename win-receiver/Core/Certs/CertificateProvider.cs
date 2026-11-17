using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mac2WinReceiver.Core.Certs;

/// <summary>
/// Per-install self-signed certificate for the receiver's TLS endpoint (SPEC §4, ADR-007).
/// M1: ephemeral generation per process (tests pin the resulting fingerprint out-of-band).
/// M2 adds persistence with DPAPI-protected private key storage on Windows.
/// </summary>
public static class CertificateProvider
{
    /// <summary>Creates an ephemeral self-signed EC P-256 certificate (TLS 1.3 capable).</summary>
    public static X509Certificate2 CreateEphemeral(string? subjectName = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            subjectName ?? $"CN=mac2win-receiver-{Environment.MachineName}",
            ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false)); // serverAuth
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using var fresh = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        // Windows schannel refuses to serve CreateSelfSigned's in-memory key
        // ("platform does not support ephemeral keys"), so round-trip through a PFX:
        // this yields a real key container that is deleted when the cert is disposed
        // (no PersistKeySet), keeping M1's per-process ephemerality.
        var pfx = fresh.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(pfx, (string?)null,
            X509KeyStorageFlags.Exportable);
    }

    /// <summary>SHA-256 over the certificate DER, lowercase hex (the pinned fingerprint, protocol §1.1).</summary>
    public static string FingerprintSha256(X509Certificate2 cert) =>
        Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();

    /// <summary>Colon-separated form for UI display (QR/connection code shows the plain hex).</summary>
    public static string FingerprintColonSeparated(X509Certificate2 cert)
    {
        var hex = FingerprintSha256(cert);
        return string.Join(':', Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));
    }
}
