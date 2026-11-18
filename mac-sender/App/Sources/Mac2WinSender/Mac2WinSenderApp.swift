import SwiftUI
import Mac2WinSenderCore

@main
struct Mac2WinSenderApp: App {
    @StateObject private var viewModel = SenderViewModel()

    var body: some Scene {
        WindowGroup("Mac2Win Transfer") {
            ContentView(viewModel: viewModel)
                .frame(minWidth: 700, minHeight: 520)
        }
        .commands {
            CommandMenu("Mac2Win") {
                Button("Disconnect") {
                    Task { await viewModel.disconnect() }
                }
                .keyboardShortcut("k", modifiers: [.command, .shift])
            }
        }
    }
}
