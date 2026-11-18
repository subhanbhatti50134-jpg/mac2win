using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Mac2WinReceiver.App.Services;

namespace Mac2WinReceiver.App.ViewModels;

/// <summary>Main window view model. All UI updates are throttled via a DispatcherTimer
/// (~10–20 Hz per SPEC §14); no work blocks the UI thread.</summary>
public sealed class ReceiverViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly ReceiverServer _server;
    private readonly IApprovalUi _approvalUi;
    private readonly QrCodeService _qr;
    private readonly HistoryStore _history;
    private readonly ReportExporter _reports;
    private readonly IFolderPicker _folderPicker;
    private readonly IFileSaver _fileSaver;
    private readonly IShellLauncher _shellLauncher;
    private readonly DispatcherTimer _pollTimer;

    private bool _isReady;
    private string _pin = string.Empty;
    private string _connectionCode = string.Empty;
    private string _qrImageBase64 = string.Empty;
    private string _statusText = "Not receiving";
    private string _destinationRoot = string.Empty;
    private string _conflictPolicy = "ASK";
    private string? _errorMessage;

    public bool IsReady
    {
        get => _isReady;
        set
        {
            if (_isReady == value) return;
            _isReady = value;
            OnPropertyChanged();
            if (value) _ = StartListeningAsync(); else StopListening();
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(CanStop));
        }
    }

    public string Pin
    {
        get => _pin;
        private set { _pin = value; OnPropertyChanged(); }
    }

    public string ConnectionCode
    {
        get => _connectionCode;
        private set { _connectionCode = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasConnectionCode)); }
    }

    public bool HasConnectionCode => !string.IsNullOrEmpty(ConnectionCode);

    public string QrImageBase64
    {
        get => _qrImageBase64;
        private set { _qrImageBase64 = value; OnPropertyChanged(); }
    }

    public string StatusText
    {
        get => _statusText;
        private set { _statusText = value; OnPropertyChanged(); }
    }

    public string DestinationRoot
    {
        get => _destinationRoot;
        set { _destinationRoot = value; OnPropertyChanged(); }
    }

    public string ConflictPolicy
    {
        get => _conflictPolicy;
        set { _conflictPolicy = value; OnPropertyChanged(); }
    }

    public string? ErrorMessage
    {
        get => _errorMessage;
        set { _errorMessage = value; OnPropertyChanged(); }
    }

    public bool CanStart => !_isReady;
    public bool CanStop => _isReady;

    public ObservableCollection<SessionRow> Sessions { get; } = new();
    public ObservableCollection<HistoryRowDto> History { get; } = new();

    public IReadOnlyList<string> ConflictPolicies { get; } =
        new[] { "ASK", "SKIP", "REPLACE", "RENAME", "KEEP_BOTH" };

    public ICommand CopyCodeCommand { get; }
    public ICommand PickDestinationCommand { get; }
    public ICommand OpenDestinationCommand { get; }
    public ICommand ClearHistoryCommand { get; }
    public ICommand ExportJsonCommand { get; }
    public ICommand ExportCsvCommand { get; }
    public ICommand ExportHtmlCommand { get; }
    public ICommand RevokeDeviceCommand { get; }

    public ReceiverViewModel(ReceiverServer server, IApprovalUi approvalUi, QrCodeService qr,
        HistoryStore history, ReportExporter reports, IFolderPicker folderPicker,
        IFileSaver fileSaver, IShellLauncher shellLauncher)
    {
        _server = server;
        _approvalUi = approvalUi;
        _qr = qr;
        _history = history;
        _reports = reports;
        _folderPicker = folderPicker;
        _fileSaver = fileSaver;
        _shellLauncher = shellLauncher;

        foreach (var row in _history.Rows) History.Add(new HistoryRowDto(row));

        CopyCodeCommand = new RelayCommand(_ => { CopyCode(); return Task.CompletedTask; });
        PickDestinationCommand = new RelayCommand(_ => { PickDestination(); return Task.CompletedTask; });
        OpenDestinationCommand = new RelayCommand(_ => { OpenDestination(); return Task.CompletedTask; });
        ClearHistoryCommand = new RelayCommand(_ => { ClearHistory(); return Task.CompletedTask; });
        ExportJsonCommand = new RelayCommand(_ => { ExportReport("json"); return Task.CompletedTask; });
        ExportCsvCommand = new RelayCommand(_ => { ExportReport("csv"); return Task.CompletedTask; });
        ExportHtmlCommand = new RelayCommand(_ => { ExportReport("html"); return Task.CompletedTask; });
        RevokeDeviceCommand = new RelayCommand(_ => { RevokeDevice(); return Task.CompletedTask; });

        // Poll progress at ~15 Hz (SPEC §14: throttle UI updates 10–20 Hz, never block UI thread)
        _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(67) };
        _pollTimer.Tick += (_, _) => RefreshSessions();
        _pollTimer.Start();
    }

    public void SetDispatcher(Dispatcher dispatcher) => _dispatcher = dispatcher;

    private Dispatcher? _dispatcher;

    private async Task StartListeningAsync()
    {
        ErrorMessage = null;
        try
        {
            // Use server's fixed test PIN if configured, otherwise generate a random one
            Pin = _server.Options.FixedTestPin ?? GeneratePin();

            var fp = _server.CertFingerprint;
            var code = Mac2WinReceiver.Core.ConnectionCode.Build(
                GetLocalIp(), _server.Port, fp, Pin);
            ConnectionCode = code;
            QrImageBase64 = Convert.ToBase64String(_qr.PngBytes(code));

            StatusText = "Ready to receive";
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(CanStop));
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to start: {ex.Message}";
            IsReady = false;
        }
    }

    private void StopListening()
    {
        StatusText = "Not receiving";
        Pin = string.Empty;
        ConnectionCode = string.Empty;
        QrImageBase64 = string.Empty;
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanStop));
    }

    private void RefreshSessions()
    {
        if (_dispatcher is null) return;
        if (!_dispatcher.CheckAccess())
        {
            _dispatcher.Invoke(RefreshSessions);
            return;
        }

        try
        {
            var infos = _server.GetSessionInfos();
            var currentIds = new HashSet<string>(Sessions.Select(s => s.SessionId));
            var updated = false;

            foreach (var info in infos)
            {
                var row = new SessionRow
                {
                    SessionId = info.Id,
                    DeviceName = info.Summary.SourceDeviceName,
                    RemoteIp = info.Summary.RemoteIp,
                    Status = info.Status,
                    TotalBytes = info.Summary.TotalBytes,
                    BytesReceived = info.BytesReceived,
                    FilesCompleted = info.FilesCompleted,
                    FilesTotal = info.FilesTotal,
                    CreatedAt = info.CreatedAt,
                };
                var existing = Sessions.FirstOrDefault(s => s.SessionId == info.Id);
                if (existing is null)
                {
                    Sessions.Add(row);
                    updated = true;

                    // terminal session → add to history
                    if (info.Status is "COMPLETED" or "FAILED" or "CANCELLED" or "DENIED")
                    {
                        var report = _server.GetSessionReport(info.Id);
                        if (report is not null) _history.Add(report, info.Summary.SourceDeviceName);
                        History.Add(new HistoryRowDto(new Services.HistoryRow
                        {
                            Date = info.CreatedAt,
                            DeviceName = info.Summary.SourceDeviceName,
                            TotalBytes = report?.Totals.BytesVerified ?? info.Summary.TotalBytes,
                            Status = info.Status,
                            SessionId = info.Id,
                        }));
                    }
                }
                else
                {
                    var idx = Sessions.IndexOf(existing);
                    Sessions[idx] = row;
                    updated = true;
                }
                currentIds.Remove(info.Id);
            }

            foreach (var id in currentIds)
            {
                var r = Sessions.First(s => s.SessionId == id);
                Sessions.Remove(r);
                updated = true;
            }

            if (updated) OnPropertyChanged(nameof(Sessions));
        }
        catch { /* server may be stopped */ }
    }

    private void CopyCode()
    {
        try { System.Windows.Clipboard.SetText(ConnectionCode); }
        catch { /* clipboard unavailable */ }
    }

    private void PickDestination()
    {
        var chosen = _folderPicker.PickFolder(
            string.IsNullOrEmpty(DestinationRoot) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : DestinationRoot,
            "Choose Mac2Win destination folder");
        if (chosen is not null)
        {
            DestinationRoot = chosen;
            _server.Options.DestinationRoot = chosen;
        }
    }

    private void OpenDestination()
    {
        var path = string.IsNullOrEmpty(DestinationRoot)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : DestinationRoot;
        _shellLauncher.OpenFolder(path);
    }

    private void ClearHistory()
    {
        _history.Clear();
        History.Clear();
    }

    private void ExportReport(string format)
    {
        SessionReport? report = null;
        foreach (var info in _server.GetSessionInfos())
        {
            var r = _server.GetSessionReport(info.Id);
            if (r is not null && (r.Status == "COMPLETED" || r.Status == "FAILED" || r.Status == "CANCELLED" || r.Status == "DENIED"))
            {
                report = r;
                break;
            }
        }
        if (report is null)
        {
            ErrorMessage = "No completed transfer to export.";
            return;
        }

        string content;
        string filter;
        string fileName;
        switch (format)
        {
            case "json":
                content = _reports.ExportJson(report);
                filter = "JSON files (*.json)|*.json";
                fileName = $"m2w-report-{report.SessionId}.json";
                break;
            case "csv":
                content = _reports.ExportCsv(report);
                filter = "CSV files (*.csv)|*.csv";
                fileName = $"m2w-report-{report.SessionId}.csv";
                break;
            default:
                content = _reports.ExportHtml(report);
                filter = "HTML files (*.html)|*.html";
                fileName = $"m2w-report-{report.SessionId}.html";
                break;
        }

        var saved = _fileSaver.SaveFile(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            fileName, filter, out _);
        if (saved is not null)
        {
            try { File.WriteAllText(saved, content); }
            catch (Exception ex) { ErrorMessage = $"Export failed: {ex.Message}"; }
        }
    }

    private void RevokeDevice()
    {
        ErrorMessage = "Device revocation requires selecting a device from the trusted-devices list (settings).";
    }

    private static string GeneratePin()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        var value = Math.Abs(BitConverter.ToInt32(bytes, 0)) % 900000 + 100000;
        return value.ToString("D6");
    }

    private static string GetLocalIp()
    {
        foreach (var addr in System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName()))
        {
            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                !IPAddressIsLoopback(addr))
                return addr.ToString();
        }
        return "127.0.0.1";
    }

    private static bool IPAddressIsLoopback(System.Net.IPAddress addr) =>
        addr.ToString() is "127.0.0.1" or "::1";

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void Dispose()
    {
        _pollTimer.Stop();
        StopListening();
    }
}

/// <summary>DTO for history rows bound to the UI.</summary>
public sealed class HistoryRowDto
{
    public string Date { get; }
    public string DeviceName { get; }
    public string TotalBytes { get; }
    public string Status { get; }

    public HistoryRowDto(Services.HistoryRow row)
    {
        Date = row.Date.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        DeviceName = row.DeviceName;
        TotalBytes = FormatBytes(row.TotalBytes);
        Status = row.Status;
    }

    private static string FormatBytes(long bytes)
    {
        var suffixes = new[] { "B", "KB", "MB", "GB", "TB" };
        var mag = Math.Max(0, (int)Math.Floor(Math.Log(Math.Max(1, bytes), 1024)));
        var adjusted = bytes / Math.Pow(1024, mag);
        return $"{adjusted:0.##} {suffixes[mag]}";
    }
}
