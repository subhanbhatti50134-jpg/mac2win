using QRCoder;

namespace Mac2WinReceiver.App.Services;

/// <summary>QR code generation for the connection code (protocol §1.1 / SPEC §8).</summary>
public sealed class QrCodeService
{
    /// <summary>PNG bytes for the QR code encoding the given connection code string.</summary>
    public byte[] PngBytes(string connectionCode, int pixelsPerModule = 10)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(connectionCode, QRCodeGenerator.ECCLevel.Q);
        using var image = new PngByteQRCode(data);
        return image.GetGraphic(pixelsPerModule);
    }
}
