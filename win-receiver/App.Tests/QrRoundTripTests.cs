using Mac2WinReceiver.App.Services;
using QRCoder;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>QR code generation test: QRCoder produces valid PNG bytes for a connection code.</summary>
public sealed class QrRoundTripTests
{
    [Fact]
    public void Generate_ReturnsValidPngBytes()
    {
        var qr = new QrCodeService();
        var code = "m2w://192.168.1.20:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=483920";

        var pngBytes = qr.PngBytes(code, 10);

        Assert.NotEmpty(pngBytes);
        // PNG magic number
        Assert.Equal(0x89, pngBytes[0]);
        Assert.Equal((byte)'P', pngBytes[1]);
        Assert.Equal((byte)'N', pngBytes[2]);
        Assert.Equal((byte)'G', pngBytes[3]);
    }
}
