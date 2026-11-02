import SwiftUI

@main
struct NetCrackApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var app = AppModel()

    var body: some Scene {
        Window("NetCrack", id: "main") {
            RootView()
                .environmentObject(app)
                .task { await app.startup() }
        }
        .defaultSize(width: 1_220, height: 820)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandGroup(replacing: .appSettings) {
                Button("Setup…") {
                    app.showSetup = true
                }
                .keyboardShortcut(",", modifiers: .command)
            }
            CommandMenu("NetCrack") {
                Button("Scan now") {
                    Task { await app.scanNow() }
                }
                .keyboardShortcut("r", modifiers: .command)

                Button("Check tools") {
                    Task { await app.checkTools() }
                }

                Divider()

                Button("Start capture") {
                    Task { await app.startCapture() }
                }
                .keyboardShortcut("k", modifiers: [.command, .shift])

                Button("Stop capture") {
                    Task { await app.stopCapture() }
                }
                .keyboardShortcut(".", modifiers: [.command, .shift])

                Button("Deauth client") {
                    Task { await app.sendDeauth() }
                }

                Divider()

                Button("Run attack") {
                    Task { await app.crack.run() }
                }
                .keyboardShortcut(.return, modifiers: [.command, .shift])

                Button("Queue mode…") {
                    app.showQueue = true
                }
                .keyboardShortcut("q", modifiers: [.command, .shift])
            }
        }
    }
}
