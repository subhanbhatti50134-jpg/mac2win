using System.Net;
using System.Net.Sockets;

namespace Mac2WinReceiver.Core.Tests.Integration;

/// <summary>
/// In-process TCP fault-injection proxy (SPEC §10 "in-process chaos proxy"): sits between
/// the sender and the receiver on loopback and can sever, delay, or throttle connections to
/// simulate LAN loss and congestion. It is a byte-level tunnel — TLS passes through
/// untouched, so certificate pinning keeps working exactly as on a real network.
/// </summary>
public sealed class ChaosProxy : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly int _targetPort;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _relays = new();

    private ChaosProxy(int port, int targetPort)
    {
        Port = port;
        _targetPort = targetPort;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    /// <summary>Proxy's own loopback port (point clients here instead of the receiver).</summary>
    public int Port { get; private set; }

    /// <summary>
    /// Sever any connection once it has carried this many client→server bytes
    /// (mid-chunk / mid-manifest drops). Null disables. Applies per connection; re-arming
    /// while a connection is already open does not affect it.
    /// </summary>
    public int? SeverAfterClientBytes { get; set; }

    /// <summary>Artificial one-way delay applied to every forwarded buffer (both directions).</summary>
    public TimeSpan Latency { get; set; } = TimeSpan.Zero;

    /// <summary>Client→server bytes-per-second cap (throttling). Null disables.</summary>
    public int? ThrottleClientBytesPerSecond { get; set; }

    public static ChaosProxy Start(int targetPort)
    {
        var proxy = new ChaosProxy(0, targetPort);
        proxy._listener.Start();
        proxy.Port = ((IPEndPoint)proxy._listener.LocalEndpoint).Port;
        _ = proxy.AcceptLoopAsync();
        return proxy;
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (OperationCanceledException) { return; }
            catch (SocketException) { return; } // listener stopped
            catch (ObjectDisposedException) { return; }
            lock (_relays) _relays.Add(RelayAsync(client));
        }
    }

    private async Task RelayAsync(TcpClient client)
    {
        TcpClient? server = null;
        try
        {
            using (client)
            {
                server = new TcpClient();
                await server.ConnectAsync(IPAddress.Loopback, _targetPort, _cts.Token);

                var up = PumpAsync(client.GetStream(), server.GetStream(),
                    SeverAfterClientBytes, Latency, ThrottleClientBytesPerSecond, _cts.Token);
                var down = PumpAsync(server.GetStream(), client.GetStream(),
                    null, Latency, null, _cts.Token);
                var first = await Task.WhenAny(up, down);
                _ = first.ContinueWith(t => _ = t.Exception,
                    TaskContinuationOptions.OnlyOnFaulted);
                // whichever direction finished or faulted: sever the other one too
                _ = (first == up ? down : up).ContinueWith(t => _ = t.Exception,
                    TaskContinuationOptions.OnlyOnFaulted);
            }
        }
        catch (Exception)
        {
            /* fault injection or teardown: connection simply dies */
        }
        finally
        {
            try { client.Client.Dispose(); } catch { /* already disposed */ }
            try { server?.Client.Dispose(); } catch { /* already disposed */ }
            try { server?.Dispose(); } catch { /* already disposed */ }
        }
    }

    private static async Task PumpAsync(Stream from, Stream to, int? byteBudget,
        TimeSpan latency, int? throttleBytesPerSecond, CancellationToken ct)
    {
        var buf = new byte[32 * 1024];
        long sent = 0;
        while (true)
        {
            var n = await from.ReadAsync(buf, ct);
            if (n == 0) return; // orderly shutdown of this direction

            if (byteBudget is { } budget)
            {
                if (sent + n > budget)
                {
                    var keep = (int)Math.Max(0, budget - sent);
                    if (keep > 0) await to.WriteAsync(buf.AsMemory(0, keep), ct);
                    throw new IOException("chaos proxy severing connection (fault injection)");
                }
                sent += n;
            }

            if (latency > TimeSpan.Zero) await Task.Delay(latency, ct);
            await to.WriteAsync(buf.AsMemory(0, n), ct);

            if (throttleBytesPerSecond is { } rate && rate > 0)
            {
                var delayMs = (int)(n * 1000L / rate);
                if (delayMs > 0) await Task.Delay(delayMs, ct);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* already stopped */ }
        Task[] relays;
        lock (_relays) relays = _relays.ToArray();
        try { await Task.WhenAll(relays).WaitAsync(TimeSpan.FromSeconds(5)); }
        catch { /* faulted relays are expected */ }
        _cts.Dispose();
    }
}
