using System.IO;

namespace Mac2WinReceiver.App.Services;

/// <summary>Central, single-instance paths for the receiver app.</summary>
public sealed class AppPaths
{
    public string AppDataRoot { get; }
    public string ConfigDir { get; }
    public string HistoryFile { get; }
    public string CertFile { get; }
    public string DevicesFile { get; }

    public AppPaths(string? appDataRoot = null)
    {
        AppDataRoot = appDataRoot
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Mac2WinReceiver");
        ConfigDir = Path.Combine(AppDataRoot, "config");
        Directory.CreateDirectory(ConfigDir);
        HistoryFile = Path.Combine(ConfigDir, "history.json");
        CertFile = Path.Combine(ConfigDir, "cert.dat");
        DevicesFile = Path.Combine(ConfigDir, "devices.json");
    }
}
