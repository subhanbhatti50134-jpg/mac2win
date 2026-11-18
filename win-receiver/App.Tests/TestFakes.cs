using System.Collections.Generic;
using Mac2WinReceiver.App.Services;
using Mac2WinReceiver.App.ViewModels;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>Test fake for IApprovalUi — records dialogs and lets the test approve/deny.</summary>
public sealed class FakeApprovalUi : IApprovalUi
{
    public class RecordedDialog
    {
        public string DeviceName { get; set; } = string.Empty;
        public string RemoteIp { get; set; } = string.Empty;
        public int ItemCount { get; set; }
        public long TotalBytes { get; set; }
        public TaskCompletionSource<bool> Tcs { get; } = new();
    }

    public List<RecordedDialog> Dialogs { get; } = new();
    public int OpenDialogs => Dialogs.Count(d => !d.Tcs.Task.IsCompleted);

    public Task<bool> ShowApprovalDialogAsync(string deviceName, string remoteIp, int itemCount, long totalBytes)
    {
        var rec = new RecordedDialog
        {
            DeviceName = deviceName,
            RemoteIp = remoteIp,
            ItemCount = itemCount,
            TotalBytes = totalBytes,
        };
        Dialogs.Add(rec);
        return rec.Tcs.Task;
    }

    public void ApproveLast() => ApproveDialog(Dialogs[^1].Tcs, true);
    public void DenyLast() => ApproveDialog(Dialogs[^1].Tcs, false);

    private static void ApproveDialog(TaskCompletionSource<bool> tcs, bool approved) =>
        tcs.TrySetResult(approved);
}

/// <summary>Test fake for IFolderPicker — returns a preset folder.</summary>
public sealed class FakeFolderPicker : IFolderPicker
{
    public string? ReturnPath { get; set; }
    public string? LastInitialDirectory { get; private set; }
    public string? LastTitle { get; private set; }

    public string? PickFolder(string initialDirectory, string title)
    {
        LastInitialDirectory = initialDirectory;
        LastTitle = title;
        return ReturnPath;
    }
}

/// <summary>Test fake for IFileSaver — returns a preset path and records calls.</summary>
public sealed class FakeFileSaver : IFileSaver
{
    public string? ReturnPath { get; set; }
    public string? LastInitialDirectory { get; private set; }
    public string? LastFileName { get; private set; }
    public string? LastFilter { get; private set; }
    public string? LastSelectedFilter { get; private set; }

    public string? SaveFile(string initialDirectory, string fileName, string filter, out string selectedFilter)
    {
        LastInitialDirectory = initialDirectory;
        LastFileName = fileName;
        LastFilter = filter;
        selectedFilter = LastSelectedFilter = string.Empty;
        return ReturnPath;
    }
}

/// <summary>Test fake for IShellLauncher — records open-folder calls.</summary>
public sealed class FakeShellLauncher : IShellLauncher
{
    public List<string> OpenedFolders { get; } = new();
    public void OpenFolder(string path) => OpenedFolders.Add(path);
}
