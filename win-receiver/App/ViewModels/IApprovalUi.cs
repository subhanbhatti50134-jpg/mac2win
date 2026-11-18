namespace Mac2WinReceiver.App.ViewModels;

/// <summary>Approval dialog abstraction — production uses a WPF dialog; tests inject a fake
/// that records dialogs and lets the test approve/deny programmatically.</summary>
public interface IApprovalUi
{
    /// <summary>Shows the approval dialog for an incoming session. Returns the user's decision.</summary>
    Task<bool> ShowApprovalDialogAsync(string deviceName, string remoteIp, int itemCount, long totalBytes);

    /// <summary>Number of dialogs currently open (test fakes use this to know when to respond).</summary>
    int OpenDialogs { get; }
}
