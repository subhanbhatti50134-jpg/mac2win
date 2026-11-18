import SwiftUI

struct TransferView: View {
    @ObservedObject var viewModel: SenderViewModel
    let progress: SenderViewModel.SessionProgress

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "arrow.up.triangle.fill")
                .font(.system(size: 56)).foregroundStyle(.green)
            Text("Transferring").font(.title2).fontWeight(.semibold)
            Text(progress.path)
                .font(.body).foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)

            ProgressView(value: progress.percent, total: 100)
                .frame(width: 280)
            Text("\(progress.percent, specifier: "%.0f")%  •  \(progress.bytesDone) / \(progress.bytesTotal) bytes")
                .font(.caption).foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button("Pause") { /* pause wired via core client in a later build */ }
                    .buttonStyle(.bordered).disabled(true)
                Button("Cancel") {
                    Task { await viewModel.cancel() }
                }
                .buttonStyle(.bordered).foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

struct CompletionView: View {
    let report: Mac2WinSenderCore.SessionReport
    @ObservedObject var viewModel: SenderViewModel

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72)).foregroundStyle(.green)
            Text("Transfer Complete").font(.title2).fontWeight(.semibold)
            VStack(alignment: .leading, spacing: 6) {
                HStack { Text("Items").foregroundStyle(.secondary); Spacer(); Text("\(report.totals.items)") }
                HStack { Text("Verified").foregroundStyle(.secondary); Spacer(); Text("\(report.totals.verified)") }
                HStack { Text("Failed").foregroundStyle(.secondary); Spacer(); Text("\(report.totals.failed)") }
                HStack { Text("Bytes verified").foregroundStyle(.secondary);
                    Spacer(); Text(ByteCountFormatter.string(fromByteCount: report.totals.bytesVerified, countStyle: .file)) }
            }
            .padding()
            .background(RoundedRectangle(cornerRadius: 8).fill(Color(.controlBackgroundColor)))
            Button("Send More Files") {
                viewModel.phase = .paired
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
