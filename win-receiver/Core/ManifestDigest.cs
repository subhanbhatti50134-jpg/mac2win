using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mac2WinReceiver.Core;

/// <summary>
/// Canonical manifest digest (protocol/PROTOCOL.md §2.7.1):
/// for each entry in batch order: UTF8(path) || 0x00 || ASCII(type) || 0x00 ||
/// ASCII(size) || 0x00 || ASCII(mtimeUtcNs) || 0x00 || ASCII(mode) || 0x0A,
/// then SHA-256, lowercase hex. Paths on the wire are NFC.
/// </summary>
public static class ManifestDigest
{
    public sealed record Entry(string Path, string Type, long Size, string MtimeUtcNs, long Mode);

    public static byte[] CanonicalBytes(IEnumerable<Entry> entries)
    {
        using var ms = new MemoryStream();
        foreach (var e in entries)
        {
            static void Write0(MemoryStream s, string v)
            {
                var b = Encoding.UTF8.GetBytes(v);
                s.Write(b);
                s.WriteByte(0);
            }
            Write0(ms, e.Path);
            var type = Encoding.ASCII.GetBytes(e.Type);
            ms.Write(type);
            ms.WriteByte(0);
            var size = Encoding.ASCII.GetBytes(e.Size.ToString(System.Globalization.CultureInfo.InvariantCulture));
            ms.Write(size);
            ms.WriteByte(0);
            var mtime = Encoding.ASCII.GetBytes(e.MtimeUtcNs);
            ms.Write(mtime);
            ms.WriteByte(0);
            var mode = Encoding.ASCII.GetBytes(e.Mode.ToString(System.Globalization.CultureInfo.InvariantCulture));
            ms.Write(mode);
            ms.WriteByte((byte)'\n');
        }
        return ms.ToArray();
    }

    public static string ComputeHex(IEnumerable<Entry> entries) =>
        Convert.ToHexString(SHA256.HashData(CanonicalBytes(entries))).ToLowerInvariant();

    /// <summary>Parses the exact JSON shape of a manifest batch entry (golden vectors).</summary>
    public static Entry ParseEntry(JsonElement el) => new(
        el.GetProperty("path").GetString() ?? throw new JsonException("path"),
        el.GetProperty("type").GetString() ?? throw new JsonException("type"),
        el.GetProperty("size").GetInt64(),
        el.GetProperty("mtimeUtcNs").GetString() ?? throw new JsonException("mtimeUtcNs"),
        el.GetProperty("mode").GetInt64());
}
