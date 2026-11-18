using System.Collections.Concurrent;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Per-client-IP sliding-window rate limiter for the unauthenticated auth endpoints
/// (challenge/pair/hello). SPEC §7 connection and rate limits; over-limit requests fail
/// with E_RATE_LIMITED (429). One bucket per observed source address — TCP peers cannot
/// spoof their address through the handshake, and the receiver is local-network only.
/// </summary>
public sealed class AuthRateLimiter
{
    private sealed class Bucket
    {
        public readonly Queue<DateTimeOffset> Hits = new();
    }

    private readonly int _limit;
    private readonly TimeSpan _window;
    private readonly ConcurrentDictionary<string, Bucket> _buckets = new(StringComparer.Ordinal);

    public AuthRateLimiter(int limit, TimeSpan window)
    {
        _limit = limit;
        _window = window;
    }

    /// <summary>True if this call is within the budget (and was counted).</summary>
    public bool TryAcquire(string clientKey)
    {
        if (_limit <= 0) return true; // limiter disabled (ReceiverOptions.AuthRateLimit)

        var now = DateTimeOffset.UtcNow;
        var bucket = _buckets.GetOrAdd(clientKey, _ => new Bucket());
        lock (bucket)
        {
            while (bucket.Hits.Count > 0 && now - bucket.Hits.Peek() >= _window)
                bucket.Hits.Dequeue();

            if (bucket.Hits.Count >= _limit)
                return false;

            bucket.Hits.Enqueue(now);
            return true;
        }
    }

    /// <summary>Drop stale buckets (memory hygiene under address churn); used by tests.</summary>
    public void PruneStaleBuckets()
    {
        var cutoff = DateTimeOffset.UtcNow - _window;
        foreach (var kv in _buckets)
        {
            if (kv.Value.Hits.Count == 0 || kv.Value.Hits.Peek() <= cutoff)
                _buckets.TryRemove(kv.Key, out _);
        }
    }

    /// <summary>Number of tracked client buckets (diagnostics/tests).</summary>
    public int BucketCount => _buckets.Count;
}
