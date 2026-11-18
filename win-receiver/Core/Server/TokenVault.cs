using System.Security.Cryptography;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Random bearer tokens for device and session scope (protocol §2.4/§2.6).
/// 32 bytes from a CSPRNG, constant-time lookup, TTL enforcement.
/// </summary>
public sealed class TokenVault
{
    private sealed record Entry(string Value, DateTimeOffset ExpiresAt, string Scope, string OwnerId);

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _tokens = new(StringComparer.Ordinal);

    public string Issue(string scope, string ownerId, TimeSpan ttl)
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var value = Convert.ToBase64String(bytes);
        lock (_gate)
        {
            PruneLocked();
            _tokens[value] = new Entry(value, DateTimeOffset.UtcNow + ttl, scope, ownerId);
        }
        return value;
    }

    /// <summary>Validates a bearer token for the given scope; returns owner id or null.</summary>
    public string? Validate(string? token, string scope)
    {
        if (string.IsNullOrEmpty(token)) return null;
        lock (_gate)
        {
            PruneLocked();
            foreach (var e in _tokens.Values)
            {
                var tokenOk = CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(e.Value),
                    System.Text.Encoding.ASCII.GetBytes(token));
                if (tokenOk && e.Scope == scope)
                    return e.OwnerId;
            }
            return null;
        }
    }

    /// <summary>
    /// Re-registers a previously issued token after a receiver restart (M3 crash recovery),
    /// so a sender that stored the token can resume its session without re-pairing.
    /// </summary>
    public void Restore(string value, string scope, string ownerId, TimeSpan ttl)
    {
        lock (_gate)
        {
            _tokens[value] = new Entry(value, DateTimeOffset.UtcNow + ttl, scope, ownerId);
        }
    }

    public void RevokeOwner(string ownerId)
    {
        lock (_gate)
        {
            foreach (var key in _tokens.Where(kv => kv.Value.OwnerId == ownerId).Select(kv => kv.Key).ToList())
                _tokens.Remove(key);
        }
    }

    private void PruneLocked()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var key in _tokens.Where(kv => kv.Value.ExpiresAt < now).Select(kv => kv.Key).ToList())
            _tokens.Remove(key);
    }
}
