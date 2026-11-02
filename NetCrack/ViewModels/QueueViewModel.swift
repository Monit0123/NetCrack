import Foundation
import AppKit
import UniformTypeIdentifiers

/// Queue sheet: run the whole pipeline against several networks unattended and
/// print a results table at the end.
@MainActor
final class QueueViewModel: ObservableObject {
    @Published var selectedIDs: Set<String> = []
    @Published private(set) var results: [PipelineResult] = []
    @Published private(set) var logs: [LogLine] = []
    @Published private(set) var isRunning = false
    @Published private(set) var progress: PipelineEngine.PipelineProgress?
    @Published var error: UserFacingError?

    @Published var captureSeconds: Double = 45
    @Published var runMask = true
    @Published var runIncremental = false
    @Published var runWPS = false
    @Published var runWEP = true
    @Published var tryKeychain = true
    @Published var deauthFirst = false

    var targetsProvider: (() -> [AccessPoint])?

    private let settings: SettingsStore
    private let pipeline = PipelineEngine()
    private var task: Task<Void, Never>?
    private let maximumLogLines = 2_000

    init(settings: SettingsStore) {
        self.settings = settings
    }

    var networks: [AccessPoint] {
        targetsProvider?() ?? []
    }

    var selectedNetworks: [AccessPoint] {
        networks.filter { selectedIDs.contains($0.id) }
    }

    var canRun: Bool {
        !isRunning && !selectedNetworks.isEmpty
    }

    var progressFraction: Double {
        guard let progress, progress.total > 0 else { return 0 }
        return Double(progress.completed) / Double(progress.total)
    }

    var progressText: String {
        guard let progress else { return "Idle" }
        return "\(progress.completed)/\(progress.total) · \(progress.currentSSID) · \(progress.phase)"
    }

    var recoveredCount: Int {
        results.filter { $0.status == .recovered || $0.status == .keychain }.count
    }

    func toggle(_ accessPoint: AccessPoint) {
        if selectedIDs.contains(accessPoint.id) {
            selectedIDs.remove(accessPoint.id)
        } else {
            selectedIDs.insert(accessPoint.id)
        }
    }

    func isSelected(_ accessPoint: AccessPoint) -> Bool {
        selectedIDs.contains(accessPoint.id)
    }

    func selectAllCrackable() {
        selectedIDs = Set(networks.filter { $0.security.isCrackable }.map(\.id))
    }

    func clearSelection() {
        selectedIDs.removeAll()
    }

    func run(
        interfaceName: String,
        captureMode: CaptureMode,
        channel: Int,
        wordlist: URL?
    ) async {
        guard !isRunning else { return }
        let targets = selectedNetworks
        guard !targets.isEmpty else {
            error = UserFacingError(message: "Select at least one network.")
            return
        }
        if captureMode == .external && interfaceName.isEmpty {
            error = UserFacingError(message: "Choose the external adapter's interface name first.")
            return
        }
        if runWPS && captureMode == .builtin {
            error = UserFacingError(
                message: "WPS needs an external adapter.",
                detail: "The built-in radio cannot transmit. Disable WPS in the queue options, or switch the capture mode to an external adapter."
            )
            return
        }

        results.removeAll()
        logs.removeAll()
        progress = nil
        isRunning = true

        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("NetCrack", isDirectory: true)
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("NetCrack", isDirectory: true)

        var options = PipelineEngine.Options.standard()
        options.mode = captureMode
        options.interfaceName = interfaceName
        options.channel = channel > 0 ? channel : nil
        options.wordlist = wordlist
        options.ruleFile = settings.ruleFilePath
        options.mask = settings.mask
        options.crackEngine = settings.crackEngine == .aircrack ? .aircrack : .hashcat
        options.potfile = support.appendingPathComponent("netcrack.potfile")
        options.workDirectory = settings.captureDirectory.appendingPathComponent("queue", isDirectory: true)
        options.captureSeconds = captureSeconds
        options.deauthFirst = deauthFirst && captureMode == .external
        options.runMask = runMask
        options.runIncremental = runIncremental
        options.runWPS = runWPS && captureMode == .external
        options.runWEP = runWEP
        options.tryKeychain = tryKeychain
        options.forceHashcat = false

        let pipeline = self.pipeline
        task = Task { [weak self] in
            for await event in pipeline.run(targets: targets, options: options) {
                guard let self else { return }
                self.handle(event)
            }
            self?.isRunning = false
            self?.progress = nil
        }
    }

    func cancel() async {
        guard isRunning else { return }
        append(LogLine("Cancelling the queue…", kind: .system))
        await pipeline.cancel()
    }

    func copyKey(for result: PipelineResult) {
        guard let key = result.key else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
    }

    func exportCSV() {
        guard !results.isEmpty else { return }
        let panel = NSSavePanel()
        panel.title = "Export results"
        panel.nameFieldStringValue = "netcrack-results-\(Formatters.timestamp()).csv"
        panel.allowedContentTypes = [.commaSeparatedText]
        guard panel.runModal() == .OK, let url = panel.url else { return }

        var lines = ["ssid,bssid,status,key,detail,seconds,hashes"]
        for result in results {
            let fields = [
                result.ssid,
                result.bssid,
                result.status.rawValue,
                result.key ?? "",
                result.detail,
                String(format: "%.1f", result.duration),
                "\(result.hashesFound)"
            ].map { field -> String in
                let escaped = field.replacingOccurrences(of: "\"", with: "\"\"")
                return "\"\(escaped)\""
            }
            lines.append(fields.joined(separator: ","))
        }
        do {
            try lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
            append(LogLine("Exported \(results.count) rows to \(url.lastPathComponent).", kind: .success))
        } catch {
            self.error = UserFacingError(error)
        }
    }

    private func handle(_ event: PipelineEngine.Event) {
        switch event {
        case let .log(line):
            append(line)
        case let .progress(update):
            progress = update
        case let .result(result):
            results.append(result)
        case let .finished(all):
            results = all
            let recovered = all.filter { $0.status == .recovered || $0.status == .keychain }
            append(LogLine(
                "Queue finished: \(recovered.count) of \(all.count) recovered.",
                kind: recovered.isEmpty ? .warning : .success
            ))
        case let .failed(error):
            self.error = error
            append(LogLine(error.message, kind: .error))
        }
    }

    private func append(_ line: LogLine) {
        logs.append(line)
        if logs.count > maximumLogLines {
            logs.removeFirst(logs.count - maximumLogLines)
        }
    }

    func clearResults() {
        results.removeAll()
        logs.removeAll()
    }
}
