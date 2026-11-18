using System.Net;
using System.Windows;
using Mac2WinReceiver.App.Services;
using Mac2WinReceiver.App.ViewModels;
using Mac2WinReceiver.App.Views;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;

namespace Mac2WinReceiver.App;

/// <summary>WPF application entry point. Wires the Core ReceiverServer to the UI.</summary>
public sealed partial class App : System.Windows.Application
{
    public ReceiverServer Server { get; private set; } = null!;
    public ReceiverViewModel ViewModel { get; private set; } = null!;
    public IApprovalUi ApprovalUi { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var paths = new AppPaths();
        var settings = new SettingsStore(System.IO.Path.Combine(paths.ConfigDir, "settings.json"));
        var history = new HistoryStore(paths.HistoryFile);
        var qr = new QrCodeService();
        var reports = new ReportExporter();
        var certPersistence = new CertificatePersistence(paths.CertFile);

        // per-install certificate, DPAPI-protected (ADR-014)
        var cert = certPersistence.LoadOrCreate(settings.Current.DeviceName);

        var server = ReceiverServer.StartAsync(new ReceiverOptions
        {
            DeviceName = settings.Current.DeviceName,
            Port = settings.Current.Port,
            BindAddress = System.Net.IPAddress.Any, // LAN (SPEC §5)
            DestinationRoot = settings.Current.DestinationRoot,
            Certificate = cert,
            DefaultConflictPolicy = settings.Current.DefaultConflictPolicy,
            VerifyAfterWrite = settings.Current.VerifyAfterWrite,
            ChunkSize = settings.Current.ChunkSize,
            FreeSpaceMarginBytes = 0,
        }).GetAwaiter().GetResult();

        var main = new MainWindow();
        var approvalUi = new WpfApprovalUi(main);
        var vm = new ReceiverViewModel(server, approvalUi, qr, history, reports,
            new WinFormsFolderPicker(), new WinFormsFileSaver(), new WinFormsShellLauncher());
        vm.SetDispatcher(System.Windows.Threading.Dispatcher.CurrentDispatcher);

        // wire approval: server calls back on a server thread; marshal to UI thread
        server.Options.ApprovalHandler = async (summary, ct) =>
        {
            var approved = await approvalUi.ShowApprovalDialogAsync(
                summary.SourceDeviceName, summary.RemoteIp,
                (int)summary.FileCount, summary.TotalBytes);
            return approved
                ? ApprovalDecision.Approve
                : ApprovalDecision.Deny;
        };

        Server = server;
        ApprovalUi = approvalUi;
        ViewModel = vm;

        main.DataContext = vm;
        MainWindow = main;
        main.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        ViewModel?.Dispose();
        Server?.DisposeAsync().GetAwaiter().GetResult();
        base.OnExit(e);
    }
}
