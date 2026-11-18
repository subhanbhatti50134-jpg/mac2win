namespace Mac2WinReceiver.Core;

/// <summary>Connection-code payload (protocol §1.1) parsed by the sender / entered manually.</summary>
public sealed record ConnectionCodeInfo(string Host, int Port, string FingerprintSha256Hex, string Pin);

/// <summary>
/// The manual connection code (human-typable and encoded in the receiver's QR code):
///   m2w://&lt;host&gt;:&lt;port&gt;?fp=&lt;64 hex chars&gt;&amp;pin=&lt;6+ digits&gt;
///
/// The receiver builds it for display; the Mac sender parses it (or scans the QR that
/// carries the identical string). `fp` is the full certificate fingerprint the sender must
/// pin, `pin` is the single-use pairing PIN (protocol §1.1/§4). Pure string logic — lives in
/// the cross-platform core so both the WPF app and headless harnesses share one validator.
/// </summary>
public static class ConnectionCode
{
    public const string Scheme = "m2w";
    public const int MinPinDigits = 6;
    public const int MaxPinDigits = 16;

    /// <summary>Builds a connection code. Throws when the inputs would not round-trip.</summary>
    public static string Build(string host, int port, string certFingerprintSha256Hex, string pin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "port must be 1-65535");
        var fp = NormalizeFingerprint(certFingerprintSha256Hex);
        ValidatePin(pin);

        // bracket IPv6 literals so Parse can read host and port back unambiguously
        var hostPart = host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;
        return $"{Scheme}://{hostPart}:{port}?fp={fp}&pin={pin}";
    }

    /// <summary>Parses a connection code. Throws <see cref="FormatException"/> on any deviation.</summary>
    public static ConnectionCodeInfo Parse(string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new FormatException("connection code is empty");

        Uri uri;
        try
        {
            uri = new Uri(code.Trim(), UriKind.Absolute);
        }
        catch (UriFormatException ex)
        {
            throw new FormatException("connection code is not a valid URI", ex);
        }

        if (!string.Equals(uri.Scheme, Scheme, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"unexpected scheme '{uri.Scheme}', expected '{Scheme}'");
        if (string.IsNullOrEmpty(uri.Host))
            throw new FormatException("connection code has no host");
        // Uri.Port is -1 when the input carried no explicit port (m2w has no known default)
        if (uri.Port is < 1 or > 65535)
            throw new FormatException("connection code has no usable port");

        string? fp = null, pin = null;
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            var key = Uri.UnescapeDataString(pair[..eq]);
            var value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            if (string.Equals(key, "fp", StringComparison.Ordinal)) fp = value;
            else if (string.Equals(key, "pin", StringComparison.Ordinal)) pin = value;
            // unknown query keys are ignored (protocol §1: clients ignore unknown fields)
        }

        fp = NormalizeFingerprint(fp ?? throw new FormatException("connection code has no fp"));
        ValidatePin(pin ?? throw new FormatException("connection code has no pin"));

        // Uri.Host returns bracketed IPv6 ([fe80::1]); strip the brackets for the info
        var host = uri.Host;
        if (host.StartsWith('[') && host.EndsWith(']'))
            host = host[1..^1];
        return new ConnectionCodeInfo(host, uri.Port, fp, pin!);
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        var fp = fingerprint.Trim().ToLowerInvariant();
        if (fp.Length != 64 || fp.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new FormatException("fingerprint must be exactly 64 hex characters (case-insensitive)");
        return fp;
    }

    private static void ValidatePin(string pin)
    {
        if (pin.Length < MinPinDigits || pin.Length > MaxPinDigits || pin.Any(c => c is < '0' or > '9'))
            throw new FormatException($"PIN must be {MinPinDigits}-{MaxPinDigits} digits");
    }
}
