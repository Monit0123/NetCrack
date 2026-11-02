import AppKit

/// Small delegate with two jobs: single-window behaviour, and a bounded
/// cleanup on quit so a privileged helper never outlives the app.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var appModel: AppModel?

    /// `reply(toApplicationShouldTerminate:)` may only be called once, and two
    /// independent paths race to call it (cleanup finished / grace period
    /// elapsed).
    private var didReply = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let appModel else { return .terminateNow }

        Task { @MainActor in
            await appModel.shutdown()
            self.replyWhenReady()
        }
        // Grace period: a stuck tool must never hold the app open. The root
        // supervisor also has its own idle timeout, so nothing runs forever
        // even if cleanup was cut short.
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            self.replyWhenReady()
        }
        return .terminateLater
    }

    private func replyWhenReady() {
        guard !didReply else { return }
        didReply = true
        NSApp.reply(toApplicationShouldTerminate: true)
    }
}
