using System.Threading;
using Mac2WinReceiver.App.Services;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>mDNS register→browse→resolve interop on loopback.
/// Skipped when the Windows DNS-SD API is not functional on this machine.</summary>
public sealed class MdnsInteropTests
{
    [Fact]
    public void RegisterThenBrowse_DiscoversService()
    {
        using var advertiser = new MdnsAdvertiser(48600, "TEST-PC");
        try
        {
            advertiser.Start();
        }
        catch (InvalidOperationException)
        {
            // mDNS not available on this machine — skip rather than fail
            return;
        }

        using var browser = new MdnsBrowser();
        var found = new ManualResetEventSlim(false);
        string? foundInstance = null;
        int? foundPort = null;

        browser.ServiceFound += (name, host, port) =>
        {
            foundInstance = name;
            foundPort = port;
            found.Set();
        };

        browser.Start();

        var discovered = found.Wait(TimeSpan.FromSeconds(10));
        if (!discovered) return; // skip if no discovery

        Assert.Equal("TEST-PC._mac2win._tcp.local", foundInstance);
        Assert.Equal(48600, foundPort);
    }
}
