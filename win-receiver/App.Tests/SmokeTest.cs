using System;
using System.IO;
using System.Threading.Tasks;
using Mac2WinReceiver.App.Services;
using Mac2WinReceiver.App.ViewModels;
using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Mac2WinReceiver.Core.Tests.Integration;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>Full UI-driven smoke test (SPEC §13 M4 exit): Ready toggle → pair → approve →
/// transfer → progress → history → export → stop. Runs on STA thread.</summary>
public sealed class SmokeTest
{
    private static byte[] Data(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string MtimeNs(DateTime utc) =>
        ((utc - DateTime.UnixEpoch).Ticks * 100L).ToString();

    [Fact]
    public async Task UiDrivenTransfer_EndToEnd()
    {
        await using var env = await TestEnv.StartAsync(o =>
        {
            o.ApprovalHandler = (_, _) => Task.FromResult(ApprovalDecision.Approve);
            return o;
        });
        var client = await env.AuthenticatedClientAsync();

        var server = env.Server;
        var approvalUi = new FakeApprovalUi();
        // Wire approval through the fake UI so the smoke test exercises the dialog flow
        server.Options.ApprovalHandler = async (summary, ct) =>
        {
            var approved = await approvalUi.ShowApprovalDialogAsync(
                summary.SourceDeviceName, summary.RemoteIp,
                (int)summary.FileCount, summary.TotalBytes);
            return approved
                ? ApprovalDecision.Approve
                : ApprovalDecision.Deny;
        };
        var vm = new ReceiverViewModel(server, approvalUi, new QrCodeService(),
            new HistoryStore(Path.Combine(Path.GetTempPath(), $"m2w-smoke-hist-{Guid.NewGuid()}.json")),
            new ReportExporter(), new FakeFolderPicker(), new FakeFileSaver(), new FakeShellLauncher());

        try
        {
            // 1. Toggle Ready → PIN, connection code, QR populated
            vm.IsReady = true;
            Assert.False(string.IsNullOrEmpty(vm.Pin));
            Assert.False(string.IsNullOrEmpty(vm.ConnectionCode));
            Assert.False(string.IsNullOrEmpty(vm.QrImageBase64));
            Assert.Equal("Ready to receive", vm.StatusText);

            // 2. Mac sender pairs with the VM's PIN (ProtocolTestClient uses same wire protocol)
            var token = await client.AuthenticateAsync(vm.Pin);

            // 3. Create session, manifest, confirm (simulating Mac sender)
            var bytes = Data(91, 2 * 1024 * 1024); // 2 MiB
            File.WriteAllBytes(Path.Combine(env.SourceDir, "smoke.bin"), bytes);

            var sid = await client.CreateSessionAsync(1, 0, bytes.Length);

            // Wait for the approval dialog to appear, then approve through the fake UI
            var dialogAppeared = false;
            for (var i = 0; i < 100 && !dialogAppeared; i++)
            {
                if (approvalUi.Dialogs.Count > 0) { dialogAppeared = true; break; }
                await Task.Delay(50);
            }
            Assert.True(dialogAppeared, "approval dialog never appeared");
            approvalUi.ApproveLast();

            var sessionToken = await client.AwaitApprovalAsync(sid);

            // Approval dialog should have appeared (shown via fake UI, then approved)
            Assert.Single(approvalUi.Dialogs);

            var mtime = MtimeNs(DateTime.UtcNow);
            var manifestDigest = ManifestDigest.ComputeHex(new[]
            {
                new ManifestDigest.Entry("smoke.bin", "file", bytes.Length, mtime, 420)
            });

            var manifest = await client.SendManifestAsync(sid, sessionToken, new Entry[]
            {
                new Entry("smoke.bin", "file", bytes.Length, mtime, 420)
            }, final: true, digest: manifestDigest);

            if (!manifest.IsSuccess)
            {
                var errMsg = manifest.Body.TryGetProperty("error", out var errEl)
                    ? errEl.GetProperty("code").GetString()
                    : "unknown";
                throw new InvalidOperationException($"manifest failed: {manifest.Status} {manifest.ErrorCode} {manifest.ErrorMessage} body={manifest.Body}");
            }
            Assert.True(manifest.IsSuccess);
            var fileId = manifest.Body.GetProperty("planned")[0].GetProperty("fileId").GetString()!;

            var confirm = await client.ConfirmAsync(sid, sessionToken);
            Assert.True(confirm.IsSuccess);

            // 4. Upload chunk → commit → complete
            var chunkSize = 1024 * 1024;
            for (var i = 0; i < 2; i++)
            {
                var offset = i * chunkSize;
                var len = Math.Min(chunkSize, bytes.Length - offset);
                var chunk = await client.UploadChunkAsync(sid, sessionToken, fileId, i,
                    bytes.AsMemory(offset, len), TestEnv.HashBytes(bytes.AsMemory(offset, len).Span));
                Assert.True(chunk.IsSuccess);
            }

            var commit = await client.CommitAsync(sid, sessionToken, fileId,
                TestEnv.HashBytes(bytes), bytes.Length, MtimeNs(DateTime.UtcNow));
            Assert.Equal("VERIFIED", commit.Body.GetProperty("outcome").GetString());

            var complete = await client.CompleteAsync(sid, sessionToken);
            Assert.True(complete.IsSuccess);

            // 5. Progress row shows completed
            var info = Assert.Single(server.GetSessionInfos());
            Assert.Equal("COMPLETED", info.Status);
            Assert.Equal(bytes.Length, info.BytesReceived);
            Assert.Equal(1, info.FilesCompleted);

            // 6. History entry exists
            var report = server.GetSessionReport(sid);
            Assert.NotNull(report);
            Assert.Equal(1, report!.Totals.Verified);

            // 7. Export report (JSON/CSV/HTML)
            var json = new ReportExporter().ExportJson(report);
            Assert.Contains(sid, json);
            Assert.Contains("VERIFIED", json);

            var csv = new ReportExporter().ExportCsv(report);
            Assert.Contains(sid, csv);

            var html = new ReportExporter().ExportHtml(report);
            Assert.Contains(sid, html);
            Assert.Contains("<!DOCTYPE html>", html);

            // 8. On-disk SHA-256 == source
            var dst = Path.Combine(env.DestinationDir, "smoke.bin");
            Assert.True(File.Exists(dst));
            Assert.Equal(TestEnv.HashBytes(bytes), TestEnv.HashFile(dst));

            // 9. Stop Ready
            vm.IsReady = false;
            Assert.Equal("Not receiving", vm.StatusText);
            Assert.False(vm.IsReady);

            vm.Dispose();
        }
        catch
        {
            vm.Dispose();
            throw;
        }
    }
}
