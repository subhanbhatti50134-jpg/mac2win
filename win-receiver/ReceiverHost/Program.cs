// Mac2Win Transfer — headless receiver host.
// Runs the receiver's HTTPS endpoint without a UI. Used by:
//   * cross-implementation tests (real Swift sender ↔ real .NET receiver, macOS CI)
//   * manual/local testing on any OS with the .NET runtime
// The shipping Windows app (M4) hosts the same ReceiverServer behind a WPF UI with an
// explicit "Ready to receive" toggle and approval dialogs; this host never auto-approves
// unless --auto-approve is passed (test harnesses only).

using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;

static string? Arg(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

var destination = Arg(args, "--destination")
    ?? throw new ArgumentException("--destination <path> is required");
var port = int.TryParse(Arg(args, "--port"), out var p) ? p : ProtocolConstants.DefaultPort;
var pin = Arg(args, "--pin");                       // test/dev only: fixed PIN (documented)
var deviceName = Arg(args, "--device-name") ?? Environment.MachineName;
var autoApprove = args.Contains("--auto-approve");  // test harnesses only
var verifyAfterWrite = Arg(args, "--verify-after-write") is not ("false" or "0");

var options = new ReceiverOptions
{
    DestinationRoot = Path.GetFullPath(destination),
    Port = port,
    DeviceName = deviceName,
    FixedTestPin = pin,
    VerifyAfterWrite = verifyAfterWrite,
};

if (autoApprove)
{
    Console.Error.WriteLine("WARNING: --auto-approve is for test harnesses only; " +
                            "production builds must show the approval dialog (SPEC §4).");
    options.ApprovalHandler = (_, _) => Task.FromResult(ApprovalDecision.Approve);
}
else
{
    // no handler ⇒ every session request is denied until a UI wires one (SPEC §7)
    options.ApprovalHandler = null;
    Console.Error.WriteLine("NOTE: no approval handler in headless mode without --auto-approve; " +
                            "incoming sessions will be DENIED.");
}

var server = await ReceiverServer.StartAsync(options);

Console.WriteLine($"mac2win-receiver ready");
Console.WriteLine($"listen:   https://127.0.0.1:{server.Port} (port {port})");
Console.WriteLine($"device:   {deviceName}");
Console.WriteLine($"dest:     {options.DestinationRoot}");
Console.WriteLine($"cert:     sha256:{server.CertFingerprint}");
// The PIN below is the headless equivalent of the on-screen display (SPEC §4: shown only
// on the receiver, never written to logs by the application itself).
Console.WriteLine($"pin:      {server.Pins.CurrentPin}");

var done = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.TrySetResult(); };
await done.Task;
await server.DisposeAsync();
