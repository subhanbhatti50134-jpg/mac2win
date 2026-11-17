using System.Security.Cryptography;
using System.Text;

namespace Mac2WinReceiver.Core;

/// <summary>
/// PIN-bound pairing proof (protocol/PROTOCOL.md §2.3, ADR-003).
/// Construction: HKDF-SHA256(PIN, salt=certFingerprintHex, info="mac2win-pair-v1")
/// then HMAC-SHA256 over clientNonce|serverNonce|devicePublicKey (base64, '|'-joined).
/// Standard primitives only — no custom cryptography.
/// </summary>
public static class PairingProof
{
    public const string HkdfInfo = "mac2win-pair-v1";

    public static byte[] DerivePinKey(string pin, string certFingerprintSha256Hex)
    {
        ArgumentException.ThrowIfNullOrEmpty(pin);
        ArgumentException.ThrowIfNullOrEmpty(certFingerprintSha256Hex);
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.ASCII.GetBytes(pin),
            32,
            salt: Encoding.ASCII.GetBytes(certFingerprintSha256Hex.ToLowerInvariant()),
            info: Encoding.ASCII.GetBytes(HkdfInfo));
    }

    /// <summary>Message bytes: UTF8(clientNonceB64) || '|' || UTF8(serverNonceB64) || '|' || UTF8(devicePublicKeyB64).</summary>
    public static byte[] BuildMessage(string clientNonceB64, string serverNonceB64, string devicePublicKeyB64) =>
        Encoding.UTF8.GetBytes($"{clientNonceB64}|{serverNonceB64}|{devicePublicKeyB64}");

    public static byte[] ComputeProof(string pin, string certFingerprintSha256Hex,
        string clientNonceB64, string serverNonceB64, string devicePublicKeyB64)
    {
        var key = DerivePinKey(pin, certFingerprintSha256Hex);
        return HMACSHA256.HashData(key, BuildMessage(clientNonceB64, serverNonceB64, devicePublicKeyB64));
    }

    /// <summary>Constant-time verification of a presented proof.</summary>
    public static bool Verify(string pin, string certFingerprintSha256Hex,
        string clientNonceB64, string serverNonceB64, string devicePublicKeyB64,
        ReadOnlySpan<byte> presentedProof)
    {
        var expected = ComputeProof(pin, certFingerprintSha256Hex, clientNonceB64, serverNonceB64, devicePublicKeyB64);
        return CryptographicOperations.FixedTimeEquals(expected, presentedProof);
    }
}
