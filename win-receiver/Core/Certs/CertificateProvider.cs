using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Mac2WinReceiver.Core.Certs;

/// <summary>
/// Per-install self-signed certificate for the receiver's TLS endpoint (SPEC §4, ADR-007).
/// M1: ephemeral generation per process (tests pin the resulting fingerprint out-of-band).
/// M2 adds persistence with DPAPI-protected private key storage on Windows.
/// </summary>
public static class CertificateProvider
{
    /// <summary>
    /// Creates an ephemeral self-signed EC P-256 certificate (TLS 1.3 capable).
    /// <paramref name="subjectName"/> accepts either a full X.500 DN ("CN=FOO") or a bare
    /// device name such as <c>Environment.MachineName</c> — the receiver app passes its
    /// settings DeviceName straight through. CertificateRequest rejects a bare name outright
    /// (CryptographicException at startup, found in Event Viewer 2026-11-19), so every input
    /// is normalized through <see cref="ToDistinguishedName"/> before the request is built.
    /// </summary>
    public static X509Certificate2 CreateEphemeral(string? subjectName = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            ToDistinguishedName(subjectName),
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

    /// <summary>
    /// Normalizes a certificate subject to an X.500 DN. A value that already parses as a DN
    /// ("CN=FOO") is used as-is; anything else — a bare device name such as
    /// <c>Environment.MachineName</c>, or a settings DeviceName with RFC 4514 metacharacters —
    /// is emitted as a single CN RDN through <see cref="X500DistinguishedNameBuilder"/>, which
    /// encodes the value directly instead of round-tripping it through .NET's DN string parser
    /// (that parser rejects bare names outright — CryptographicException at startup, and it also
    /// rejects most backslash escapes, so hand-escaping the string does not work).
    /// Null/blank input falls back to the default mac2win-receiver subject.
    /// </summary>
    public static X500DistinguishedName ToDistinguishedName(string? nameOrDn)
    {
        var trimmed = nameOrDn?.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return BuildCn($"mac2win-receiver-{Environment.MachineName}");

        // Only strings that look like DNs are taken literally; a device name is never
        // interpreted as one. UseNewLines covers DN strings whose values contain escaped
        // commas, which the default flag set rejects.
        if (trimmed.Contains('=', StringComparison.Ordinal)
            && TryParseDistinguishedName(trimmed, out var dn))
        {
            return dn!;
        }

        var value = new StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (!char.IsControl(ch)) value.Append(ch); // control chars cannot appear in a DN
        }
        return value.Length == 0
            ? BuildCn($"mac2win-receiver-{Environment.MachineName}")
            : BuildCn(value.ToString());
    }

    private static X500DistinguishedName BuildCn(string cnValue)
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.Add("2.5.4.3", cnValue); // commonName
        return builder.Build();
    }

    private static bool TryParseDistinguishedName(string value, out X500DistinguishedName? dn)
    {
        try
        {
            dn = new X500DistinguishedName(value);
            return true;
        }
        catch (CryptographicException)
        {
            // fall through to the UseNewLines flag set
        }
        try
        {
            dn = new X500DistinguishedName(value, X500DistinguishedNameFlags.UseNewLines);
            return true;
        }
        catch (CryptographicException)
        {
            dn = null;
            return false;
        }
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
