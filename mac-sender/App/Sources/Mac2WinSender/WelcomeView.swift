import SwiftUI

struct WelcomeView: View {
    @ObservedObject var viewModel: SenderViewModel
    @State private var code = ""
    @State private var showingConnect = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "arrow.right.doc.fill")
                .font(.system(size: 72)).foregroundStyle(.blue)
            Text("Mac2Win Transfer").font(.largeTitle).fontWeight(.semibold)
            Text("Send files from this Mac to a Windows PC over your local network.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)

            VStack(spacing: 12) {
                TextField("Connection code (m2w://…)", text: $code)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 340)
                Button("Connect") {
                    Task { await viewModel.connect(code: code) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(code.isEmpty)
            }
            .padding(.top)

            Divider()
            Text("Or scan the receiver's QR code and paste the connection code.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
