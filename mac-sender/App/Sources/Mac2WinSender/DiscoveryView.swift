import SwiftUI

struct DiscoveryView: View {
    @ObservedObject var viewModel: SenderViewModel
    @State private var code = ""
    @State private var scanned = false

    var body: some View {
        VStack(spacing: 20) {
            Text("Choose a Receiver").font(.title2).fontWeight(.semibold)
            Text("Scan the receiver's QR code and paste the connection code below, or enter it manually.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)

            VStack(spacing: 12) {
                HStack {
                    Image(systemName: "qrcode.viewfinder")
                        .foregroundStyle(.blue)
                    TextField("m2w://host:port?fp=…&pin=…", text: $code)
                        .textFieldStyle(.roundedBorder)
                }
                Button("Connect") {
                    Task { await viewModel.connect(code: code) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(code.isEmpty)
            }
            .padding(.top)

            Divider()
            VStack(spacing: 8) {
                Text("Network discovery (Bonjour _mac2win._tcp) comes in the next build.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Scan Local Network") {
                    scanned = true
                }
                .disabled(true)
                .buttonStyle(.bordered)
            }

            if scanned {
                Text("No receivers found on this network yet.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
