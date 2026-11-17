using System.IO;
using System.Runtime.InteropServices;

namespace Mac2WinReceiver.Core.Server;

/// <summary>Destination volume facts used by preflight (SPEC §5, §6.2).</summary>
public sealed record DestinationSnapshot(
    string Path,
    long FreeBytes,
    string FileSystem,
    bool Writable,
    bool LongPathsEnabled,
    long MaxFileSize);

/// <summary>
/// Abstraction over the destination volume so preflight logic is testable without a
/// real FAT32 disk (tests substitute a fake; production uses <see cref="DriveDestinationInfo"/>).
/// </summary>
public interface IDestinationInfo
{
    DestinationSnapshot GetInfo();
}

/// <summary>Real filesystem facts via <see cref="DriveInfo"/> (cross-platform).</summary>
public sealed class DriveDestinationInfo : IDestinationInfo
{
    private readonly string _root;

    public DriveDestinationInfo(string destinationRoot)
    {
        _root = Path.GetFullPath(destinationRoot);
    }

    public DestinationSnapshot GetInfo()
    {
        var root = Path.GetPathRoot(_root);
        DriveInfo? drive = null;
        try
        {
            if (!string.IsNullOrEmpty(root))
                drive = new DriveInfo(root);
        }
        catch (ArgumentException) { /* UNC/unusual roots */ }

        var format = drive?.DriveFormat ?? "unknown";
        var free = drive?.AvailableFreeSpace ?? DirFreeBytesFallback();
        // FAT32 per-file limit (SPEC §6.2): fail preflight with a clear message
        var maxFileSize = format.Contains("FAT32", StringComparison.OrdinalIgnoreCase)
            ? 4L * 1024 * 1024 * 1024 - 1
            : long.MaxValue;

        var writable = true;
        try
        {
            var probe = Path.Combine(_root, ".mac2win-write-probe");
            File.WriteAllBytes(probe, Array.Empty<byte>());
            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            writable = false;
        }

        return new DestinationSnapshot(
            _root, free, format, writable, IsLongPathsEnabled(), maxFileSize);
    }

    private long DirFreeBytesFallback()
    {
        try
        {
            var di = new DriveInfo(Path.GetPathRoot(_root) ?? _root);
            return di.AvailableFreeSpace;
        }
        catch
        {
            return 0;
        }
    }

    private static bool IsLongPathsEnabled()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return true;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\FileSystem");
            return key?.GetValue("LongPathsEnabled") is int v && v == 1;
        }
        catch
        {
            return false;
        }
    }
}
