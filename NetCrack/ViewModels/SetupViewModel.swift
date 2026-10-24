import Foundation

/// Setup sheet: what is installed, and the one-click installer.
@MainActor
final class SetupViewModel: ObservableObject {
    @Published var report: ToolchainReport = .pending
    @Published private(set) var logs: [LogLine] = []
    @Published private(set) var isInstalling = false
    @Published private(set) var phase: String = ""
    @Published private(set) var lastFinished: ToolchainReport?
    @Published var includeOptional = true
    @Published var buildFromSource = true
    @Published var error: UserFacingError?

    private let settings: SettingsStore
    private var task: Task<Void, Never>?
    private let maximumLogLines = 2_000

    init(settings: SettingsStore) {
        self.settings = settings
    }

    var missingRequired: [ExternalTool] { report.missing }

    var missingOptional: [ExternalTool] { report.optionalMissing }

    var installable: [ExternalTool] {
        var tools = report.missing
        if includeOptional {
            tools.append(contentsOf: report.optionalMissing.filter { $0 != .brew })
        }
        return tools
    }

    var canInstall: Bool {
        !isInstalling && report.hasBrew && !installable.isEmpty
    }

    var summary: String { report.summary }

    func refresh() async {
        report.isChecking = true
        let snapshot = await ToolLocator.shared.report(refresh: true)
        report = snapshot
        lastFinished = snapshot
    }

    func install() async {
        guard !isInstalling else { return }
        guard report.hasBrew else {
            self.error = UserFacingError(
                message: "Homebrew is not installed.",
                detail: "Use “Install Homebrew” below, or run the install command from the README in Terminal."
            )
            return
        }
        let tools = installable
        guard !tools.isEmpty else { return }

        isInstalling = true
        error = nil
        logs.removeAll()
        phase = "Starting Homebrew…"
        append(LogLine("Installing: \(tools.map(\.executable).joined(separator: ", "))", kind: .system))
        append(LogLine(
            "aircrack-ng has no Apple Silicon bottle. Building it from source takes 5–15 minutes; everything else is a fast download.",
            kind: .warning
        ))

        let manager = SetupManager.shared
        task = Task { [weak self] in
            guard let self else { return }
            for await event in manager.install(
                missing: tools,
                includeOptional: self.includeOptional,
                buildAircrackFromSource: self.buildFromSource
            ) {
                self.handle(event)
            }
            self.isInstalling = false
            self.phase = ""
        }
    }

    func installHomebrew() async {
        guard !isInstalling else { return }
        isInstalling = true
        error = nil
        phase = "Installing Homebrew (asks for your password once)…"
        append(LogLine("Starting the Homebrew installer as administrator.", kind: .system))
        task = Task { [weak self] in
            guard let self else { return }
            for await event in SetupManager.shared.installHomebrew() {
                self.handle(event)
            }
            self.isInstalling = false
            self.phase = ""
        }
    }

    func cancel() async {
        await SetupManager.shared.cancelInstall()
        task?.cancel()
        task = nil
        isInstalling = false
        phase = ""
        append(LogLine("Install cancelled.", kind: .system))
    }

    func clearLogs() {
        logs.removeAll()
    }

    var brewInstallCommands: String {
        """
        # Once Homebrew is available:
        brew install hashcat
        brew install hcxtools
        brew install tcpdump            # optional: macOS already ships /usr/bin/tcpdump
        brew install --build-from-source aircrack-ng
        brew install reaver             # optional, WPS PIN brute force
        """
    }

    private func handle(_ event: SetupManager.Event) {
        switch event {
        case let .log(line):
            append(line)
        case let .started(description):
            phase = description
            append(LogLine("▶︎ \(description)", kind: .system))
        case let .finished(snapshot):
            lastFinished = snapshot
            report = snapshot
            isInstalling = false
            phase = ""
            append(LogLine("Toolchain now: \(snapshot.summary)", kind: snapshot.hasRequiredTools ? .success : .warning))
            Task { await ToolLocator.shared.invalidate() }
        case let .failed(error):
            self.error = error
            isInstalling = false
            phase = ""
            append(LogLine(error.message, kind: .error))
        }
    }

    private func append(_ line: LogLine) {
        logs.append(line)
        if logs.count > maximumLogLines {
            logs.removeFirst(logs.count - maximumLogLines)
        }
    }
}
