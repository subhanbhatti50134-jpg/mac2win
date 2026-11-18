using System.Windows;
using System.Windows.Threading;
using Mac2WinReceiver.App.ViewModels;
using Mac2WinReceiver.App.Views;

namespace Mac2WinReceiver.App.Services;

/// <summary>Production approval UI: shows a non-modal ApprovalDialog on the UI thread
/// (SPEC §4: every transfer needs explicit approval). Exposes OpenDialogs for tests.</summary>
public sealed class WpfApprovalUi : IApprovalUi
{
    private readonly Window _owner;
    private int _openDialogs;

    public int OpenDialogs => _openDialogs;

    public WpfApprovalUi(Window owner) => _owner = owner;

    public Task<bool> ShowApprovalDialogAsync(string deviceName, string remoteIp, int itemCount, long totalBytes)
    {
        var tcs = new TaskCompletionSource<bool>();

        // marshal to the UI thread
        _owner.Dispatcher.Invoke(() =>
        {
            _openDialogs++;
            var dlg = new ApprovalDialog(deviceName, remoteIp, itemCount, totalBytes)
            {
                Owner = _owner,
            };
            dlg.Closed += (_, _) =>
            {
                _openDialogs--;
                // Closed without clicking Approve = Deny (X/close ⇒ Deny per SPEC §4)
                tcs.TrySetResult(dlg.DialogResult == true);
            };
            dlg.Show();
        });

        return tcs.Task;
    }
}
