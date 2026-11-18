using System.Security.Cryptography;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Single-use PIN state machine (SPEC §4): ≥6 CSPRNG digits, 5-minute expiry, single-use,
/// lockout after 5 failed attempts with escalating backoff (1s, 2s, 4s, 8s, 16s).
/// The PIN is never logged and never serialized over HTTP — it is exposed only through
/// <see cref="CurrentPin"/> for direct UI binding (and test harnesses).
/// </summary>
public sealed class PinVault
{
    private readonly object _gate = new();
    private readonly bool _fixedMode; // dev/test harness (--pin): no rotation, documented as test-only
    private readonly TimeSpan _maxAge; // null ⇒ protocol default (5 min); tests shorten it
    private string _pin;
    private DateTimeOffset _issuedAt;
    private int _failures;
    private int _lockLevel;
    private DateTimeOffset _lockedUntil;

    public PinVault(string? fixedPin = null, TimeSpan? maxAge = null)
    {
        _fixedMode = fixedPin is not null;
        _pin = fixedPin ?? Generate();
        _issuedAt = DateTimeOffset.UtcNow;
        _maxAge = maxAge ?? TimeSpan.FromSeconds(ProtocolConstants.PinMaxAgeSeconds);
    }

    public static string Generate()
    {
        Span<byte> bytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(bytes);
        var value = BitConverter.ToUInt32(bytes) % 100_000_000;
        return value.ToString("D8");
    }

    /// <summary>Current display PIN (UI/tests). Never written to logs.</summary>
    public string CurrentPin
    {
        get { lock (_gate) return _pin; }
    }

    public enum PinFailure { None, Locked, Expired, Wrong }

    public readonly record struct VerifyOutcome(bool Ok, PinFailure Reason, TimeSpan RetryAfter)
    {
        public bool Failed => !Ok;
    }

    /// <summary>
    /// One pairing attempt. The raw PIN never leaves this object: the caller supplies a
    /// predicate that tests the current PIN (e.g. recompute an HMAC proof and compare).
    /// Handles expiry, lockout backoff, single-use consumption and rotation.
    /// </summary>
    public VerifyOutcome Attempt(Func<string, bool> pinCheck)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (_lockedUntil > now)
                return new VerifyOutcome(false, PinFailure.Locked, _lockedUntil - now);

            var expired = now - _issuedAt > _maxAge;
            if (expired)
            {
                Rotate();
                return new VerifyOutcome(false, PinFailure.Expired, TimeSpan.Zero);
            }

            bool match;
            try { match = pinCheck(_pin); }
            catch { match = false; } // never let a predicate exception bypass lockout accounting

            if (match)
            {
                Rotate(); // single-use: consume + issue the next PIN (fixed mode keeps the same PIN)
                return new VerifyOutcome(true, PinFailure.None, TimeSpan.Zero);
            }

            _failures++;
            if (_failures >= ProtocolConstants.PinMaxFailedAttempts)
            {
                // escalating backoff: 1s, 2s, 4s, 8s, 16s
                var backoff = TimeSpan.FromSeconds(Math.Pow(2, Math.Min(_lockLevel, 4)));
                _lockLevel++;
                _lockedUntil = now + backoff;
                _failures = 0;
                return new VerifyOutcome(false, PinFailure.Locked, backoff);
            }
            return new VerifyOutcome(false, PinFailure.Wrong, TimeSpan.Zero);
        }
    }

    private void Rotate()
    {
        if (!_fixedMode)
            _pin = Generate();
        _issuedAt = DateTimeOffset.UtcNow;
        _failures = 0;
        _lockLevel = 0;
        _lockedUntil = default;
    }
}
