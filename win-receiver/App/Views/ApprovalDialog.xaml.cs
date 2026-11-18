using System.Windows;

namespace Mac2WinReceiver.App.Views;

/// <summary>Incoming-request approval dialog (SPEC §4). Shows Mac name, IP, item count,
/// total size. X/close ⇒ Deny; Approve button ⇒ DialogResult = true.</summary>
public sealed partial class ApprovalDialog : Window
{
    public string DeviceName { get; }
    public string RemoteIp { get; }
    public int ItemCount { get; }
    public string TotalSize { get; }

    public ApprovalDialog(string deviceName, string remoteIp, int itemCount, long totalBytes)
    {
        DeviceName = deviceName;
        RemoteIp = remoteIp;
        ItemCount = itemCount;
        TotalSize = FormatBytes(totalBytes);
        DataContext = this;
        InitializeComponent();
    }

    private void OnApprove(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void OnDeny(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private static string FormatBytes(long bytes)
    {
        var suffixes = new[] { "B", "KB", "MB", "GB", "TB" };
        var mag = Math.Max(0, (int)Math.Floor(Math.Log(Math.Max(1, bytes), 1024)));
        var adjusted = bytes / Math.Pow(1024, mag);
        return $"{adjusted:0.##} {suffixes[mag]}";
    }
}
