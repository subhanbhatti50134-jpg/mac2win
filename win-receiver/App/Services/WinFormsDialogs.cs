using System;
using System.IO;
using System.Windows.Forms;

namespace Mac2WinReceiver.App.Services;

/// <summary>Production folder picker: WinForms FolderBrowserDialog.</summary>
public sealed class WinFormsFolderPicker : IFolderPicker
{
    public string? PickFolder(string initialDirectory, string title)
    {
        using var dlg = new FolderBrowserDialog
        {
            InitialDirectory = Directory.Exists(initialDirectory) ? initialDirectory : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Description = title,
        };
        return dlg.ShowDialog() == DialogResult.OK ? dlg.SelectedPath : null;
    }
}

/// <summary>Production file saver: WinForms SaveFileDialog.</summary>
public sealed class WinFormsFileSaver : IFileSaver
{
    public string? SaveFile(string initialDirectory, string fileName, string filter, out string selectedFilter)
    {
        selectedFilter = string.Empty;
        using var dlg = new SaveFileDialog
        {
            InitialDirectory = Directory.Exists(initialDirectory) ? initialDirectory : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            FileName = fileName,
            Filter = filter,
        };
        if (dlg.ShowDialog() != DialogResult.OK) return null;
        selectedFilter = dlg.FilterIndex.ToString();
        return dlg.FileName;
    }
}

/// <summary>Production shell launcher: opens explorer.</summary>
public sealed class WinFormsShellLauncher : IShellLauncher
{
    public void OpenFolder(string path)
    {
        try { System.Diagnostics.Process.Start("explorer.exe", path); }
        catch { /* best effort */ }
    }
}
