using Mac2WinReceiver.Core;

namespace Mac2WinReceiver.Core.Server;

/// <summary>
/// Wraps a request body so a client that stops sending mid-body (SPEC §7 "endless
/// streams") cannot pin a connection: if no bytes arrive within the stall timeout the
/// read fails with <see cref="ErrorCode.E_IDLE_TIMEOUT"/> (408, retryable) — a protocol
/// error the client can act on — instead of hanging forever. The timer resets on every
/// successful read, so slow-but-progressing transfers are unaffected; a zero or negative
/// timeout disables the wrapper entirely.
/// </summary>
internal sealed class StallTimeoutStream : Stream
{
    private readonly Stream _inner;
    private readonly TimeSpan _timeout;
    private readonly CancellationToken _requestAborted;
    private readonly CancellationTokenSource _stall = new();
    private readonly CancellationTokenSource _linked;

    public StallTimeoutStream(Stream inner, TimeSpan timeout, CancellationToken requestAborted)
    {
        _inner = inner;
        _timeout = timeout;
        _requestAborted = requestAborted;
        _linked = CancellationTokenSource.CreateLinkedTokenSource(requestAborted, _stall.Token);
    }

    /// <summary>Wraps <paramref name="inner"/> unless the timeout is disabled.</summary>
    public static Stream Wrap(Stream inner, TimeSpan timeout, CancellationToken requestAborted) =>
        timeout <= TimeSpan.Zero ? inner : new StallTimeoutStream(inner, timeout, requestAborted);

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        _stall.CancelAfter(_timeout); // schedule (and re-arm on every read) the no-progress timer
        try
        {
            return await _inner.ReadAsync(buffer, _linked.Token);
        }
        catch (OperationCanceledException) when (_stall.IsCancellationRequested && !_requestAborted.IsCancellationRequested)
        {
            throw new ProtocolException(ErrorCode.E_IDLE_TIMEOUT,
                $"request body stalled for {_timeout.TotalSeconds:0.#}s");
        }
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        await ReadAsync(buffer.AsMemory(offset, count), ct);

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    // ---- pass-through members (a request body is only ever read sequentially) ----

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _linked.Dispose();
            _stall.Dispose();
        }
        base.Dispose(disposing);
    }
}
