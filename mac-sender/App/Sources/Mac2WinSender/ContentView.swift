import SwiftUI

struct ContentView: View {
    @ObservedObject var viewModel: SenderViewModel

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
        }
    }

    private var sidebar: some View {
        List {
            Section("Connection") {
                Button {
                    // manual connect sheet handled by detail
                } label: {
                    Label("Connect to Receiver…", systemImage: "plug")
                }
                if viewModel.isConnected {
                    Button("Disconnect") {
                        Task { await viewModel.disconnect() }
                    }
                    .foregroundStyle(.red)
                }
            }
            Section("Status") {
                HStack {
                    Text(viewModel.receiverName.isEmpty ? "Receiver" : viewModel.receiverName)
                    Spacer()
                    Text(viewModel.receiverAddress)
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                Text(viewModel.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private var detail: some View {
        switch viewModel.phase {
        case .disconnected, .connecting:
            WelcomeView(viewModel: viewModel)
        case .paired:
            DiscoveryView(viewModel: viewModel)
        case .awaitingApproval:
            VStack {
                Image(systemName: "hand.raised.fill")
                    .font(.system(size: 56)).foregroundStyle(.orange)
                Text("Waiting for receiver approval…")
                    .font(.headline)
                Text("Approve the incoming transfer on the receiver.")
                    .font(.subheadline).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .transferring(let progress):
            TransferView(viewModel: viewModel, progress: progress)
        case .completed(let report):
            CompletionView(report: report, viewModel: viewModel)
        case .error(let message):
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 56)).foregroundStyle(.red)
                Text("Error").font(.headline)
                Text(message).font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Try Again") { viewModel.phase = .disconnected }
                    .buttonStyle(.borderedProminent)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}
