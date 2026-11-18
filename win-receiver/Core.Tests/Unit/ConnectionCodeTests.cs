using Mac2WinReceiver.Core;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Unit;

/// <summary>
/// Connection-code tests (protocol §1.1): the receiver displays this string and its QR,
/// the sender parses it — one validator in core keeps both ends honest. Hostile inputs
/// (the QR/manual path is user- and attacker-supplied) must fail with FormatException,
/// never parse into a usable-but-wrong endpoint.
/// </summary>
public sealed class ConnectionCodeTests
{
    /// <summary>64 lowercase hex chars — a valid fingerprint.</summary>
    private const string Fp =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string FpUpper =
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    [Fact]
    public void BuildThenParse_RoundTrips()
    {
        var code = ConnectionCode.Build("192.168.1.20", 48600, Fp, "483920");
        var info = ConnectionCode.Parse(code);
        Assert.Equal("192.168.1.20", info.Host);
        Assert.Equal(48600, info.Port);
        Assert.Equal(Fp, info.FingerprintSha256Hex);
        Assert.Equal("483920", info.Pin);
    }

    [Fact]
    public void Build_UppercaseFingerprint_NormalizesToLowercase()
    {
        var code = ConnectionCode.Build("10.0.0.4", 48600, FpUpper, "123456");
        Assert.Contains($"fp={Fp}", code, StringComparison.Ordinal);
        Assert.Equal(Fp, ConnectionCode.Parse(code).FingerprintSha256Hex);
    }

    [Fact]
    public void Build_IPv6Host_BracketsAndRoundTrips()
    {
        var code = ConnectionCode.Build("fe80::1", 48600, Fp, "555123");
        var info = ConnectionCode.Parse(code);
        Assert.Equal("fe80::1", info.Host);
        Assert.Equal(48600, info.Port);
    }

    [Theory]
    [InlineData("m2w://host:48600?fp=tooshort&pin=123456")] // fp not 64 hex
    [InlineData("m2w://host:48600?fp=&pin=123456")] // fp empty
    [InlineData("m2w://host:48600?pin=123456")] // fp absent
    [InlineData("m2w://host:48600?fp=g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0&pin=123456")] // non-hex
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde&pin=123456")] // 63 chars
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0&pin=123456")] // 65 chars
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=12345")] // pin < 6
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=12345678901234567")] // pin > 16
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=12ab56")] // non-digit pin
    [InlineData("m2w://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")] // pin absent
    [InlineData("http://host:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=123456")] // wrong scheme
    [InlineData("m2w://host?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=123456")] // no port
    [InlineData("m2w://:48600?fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&pin=123456")] // no host
    [InlineData("not a code at all")]
    [InlineData("")]
    public void Parse_HostileOrMalformedCode_ThrowsFormatException(string code)
    {
        Assert.Throws<FormatException>(() => ConnectionCode.Parse(code));
    }

    [Fact]
    public void Build_InvalidInputs_Throw()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionCode.Build("host", 0, Fp, "123456"));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConnectionCode.Build("host", 70000, Fp, "123456"));
        Assert.Throws<FormatException>(() =>
            ConnectionCode.Build("host", 48600, Fp, "12"));
        Assert.Throws<FormatException>(() =>
            ConnectionCode.Build("host", 48600, "zz", "123456"));
        Assert.Throws<ArgumentException>(() =>
            ConnectionCode.Build(" ", 48600, Fp, "123456"));
    }

    [Fact]
    public void Parse_UnknownQueryKeys_AreIgnored()
    {
        // protocol §1: clients ignore unknown fields
        var code = $"m2w://192.168.1.9:48600?fp={Fp}&pin=483920&extra=1&x=y";
        var info = ConnectionCode.Parse(code);
        Assert.Equal("483920", info.Pin);
        Assert.Equal(Fp, info.FingerprintSha256Hex);
    }

    [Fact]
    public void Parse_TrimmedWhitespace_RoundTrips()
    {
        var code = $"  m2w://192.168.1.9:48600?fp={Fp}&pin=483920\n";
        Assert.Equal("483920", ConnectionCode.Parse(code).Pin);
    }
}
