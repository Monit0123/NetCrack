import Foundation
import AppKit

/// Capture stage: owns the engine, the live counters and the console.
@MainActor
final class CaptureViewModel: ObservableObject {
    @Published private(set) var status: CaptureStatus = .idle
    @Published private(set) var stats: CaptureStats = .empty
    @Published private(set) var hashes: [CaptureHash] = []
    @Published private(set) var logs: [LogLine] = []
    @Published private(set) var elapsed: TimeInterval = 0
    @Published private(set) var pcapPath: String = ""
    @Published private(set) var diagnostics: MonitorDiagnostics = .idle
    @Published private(set) var isRunning = false
    @Published private(set) var lastSummary: CaptureEngine.Summary?
    @Published private(set) var isStarting = false
    @Published private(set) var wpsRunning = false
    @Published private(set) var wpsKey: String?
    @Published private(set) var wpsMessage: String?

    @Published var mode: CaptureMode {
        didSet { settings.captureMode = mode }
    }
    @Published var externalInterface: String {
        didSet { settings.externalInterface = externalInterface }
    }
    @Published var desiredChannel: Int {
        didSet { settings.captureChannel = desiredChannel }
    }
    @Published var lockChannel: Bool = false
    @Published var keepAwake: Bool {
        didSet { settings.keepDisplayAwake = keepAwake }
    }
    @Published var deauthClient: String {
        didSet { settings.deauthClientMac = deauthClient }
    }

    var onSummary: ((CaptureEngine.Summary) -> Void)?
    var onStats: ((CaptureStats) -> Void)?

    private let engine = CaptureEngine()
    private let settings: SettingsStore
    private var consumeTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var startedAt: Date?
    private let maximumLogLines = 1_500

    init(settings: SettingsStore) {
        self.settings = settings
        self.mode = settings.captureMode
        self.externalInterface = settings.externalInterface
        self.desiredChannel = settings.captureChannel
        self.keepAwake = settings.keepDisplayAwake
        self.deauthClient = settings.deauthClientMac
    }

    // MARK: - Derived UI state

    var canDeauth: Bool {
        mode == .external && isRunning
    }

    var deauthExplanation: String {
        if mode == .builtin {
            return "Disabled: the built-in Mac radio cannot transmit in monitor mode, so it cannot deauthenticate a client. Attach an external adapter to force a handshake."
        }
        if !isRunning {
            return "Start a capture first; aireplay-ng needs the target BSSID and a running monitor interface."
        }
        return "Send 8 deauth frames to force the client to reconnect, which produces a fresh EAPOL handshake."
    }

    var wpsExplanation: String {
        if mode == .builtin {
            return "WPS needs an external adapter: wash and reaver have to transmit, and the built-in radio cannot."
        }
        return "Scan for WPS and try the PixieWPS offline PIN attack on the Target pane."
    }

    var canAttemptWPS: Bool {
        mode == .external
    }

    var statusDetail: String {
        switch status {
        case .idle:
            return isRunning ? "Finishing…" : "Ready when you are."
        case .starting:
            return isStarting ? "Requesting administrator rights and starting tcpdump…" : "Starting…"
        case .capturing:
            return stats.frames == 0 ? "Monitor mode is up; waiting for the first frame." : "Recording 802.11 frames."
        case .handshakeFound:
            return "An EAPOL handshake is in the pcap. Move to Crack."
        case .pmkidFound:
            return "A PMKID is in the pcap. This usually cracks fastest."
        case .noSignal:
            return "Monitor mode accepted the request but no frames arrived."
        case let .failed(message):
            return message
        }
    }

    var effectiveInterfaceName: String {
        mode == .builtin ? "" : externalInterface
    }

    func effectiveInterface(defaultName: String) -> String {
        if mode == .builtin { return defaultName }
        return externalInterface.isEmpty ? defaultName : externalInterface
    }

    var pcapURL: URL? {
        guard !pcapPath.isEmpty else { return nil }
        return URL(fileURLWithPath: pcapPath)
    }

    var eapolTotal: Int { stats.eapolHashes }
    var pmkidTotal: Int { stats.pmkidHashes }

    var hasUsableHash: Bool { eapolTotal > 0 || pmkidTotal > 0 }

    // MARK: - Control

    func start(target: AccessPoint?, interfaceName: String) async {
        guard !isRunning else { return }
        do {
            try settings.ensureCaptureDirectory()
        } catch {
            self.append(LogLine("Could not create the capture folder: \(error.localizedDescription)", kind: .error))
            return
        }

        logs.removeAll()
        hashes = []
        stats = .empty
        diagnostics = .idle
        lastSummary = nil
        elapsed = 0
        status = .starting
        isStarting = true
        isRunning = true
        startedAt = Date()

        let interface = effectiveInterface(defaultName: interfaceName)
        let pcap = makePcapURL(target: target)
        pcapPath = pcap.path

        let configuration = CaptureEngine.Configuration(
            mode: mode,
            interfaceName: interface,
            desiredChannel: desiredChannel > 0 ? desiredChannel : target?.channel,
            target: target,
            pcapURL: pcap,
            keepDisplayAwake: keepAwake,
            deauthAfterStart: false,
            deauthClient: deauthClient,
            lockChannel: lockChannel
        )

        startTimer()
        let engine = self.engine
        consumeTask = Task { [weak self] in
            for await event in engine.start(configuration) {
                guard let self else { return }
                self.handle(event)
            }
            self?.isRunning = false
            self?.isStarting = false
            self?.timerTask?.cancel()
            self?.timerTask = nil
        }
    }

    func stop() async {
        guard isRunning else { return }
        await engine.stop()
    }

    func deauth() async {
        guard mode == .external else {
            append(LogLine(deauthExplanation, kind: .warning))
            return
        }
        await engine.deauth(client: deauthClient.isEmpty ? nil : deauthClient)
    }

    func cancelWPS() async {
        await engine.cancelWPS()
    }

    /// wash + reaver against the current target. External adapters only,
    /// because both tools have to transmit.
    func attemptWPS(target: AccessPoint?, defaultInterface: String) async {
        guard mode == .external else {
            append(LogLine(NetCrackError.wpsRequiresExternalAdapter.errorDescription ?? "", kind: .warning))
            return
        }
        guard let target else {
            append(LogLine("Select a target on the Scan pane before trying WPS.", kind: .warning))
            return
        }
        guard !wpsRunning else { return }
        wpsRunning = true
        wpsKey = nil
        wpsMessage = nil
        append(LogLine("Starting WPS attack against \(target.displayName).", kind: .system))
        do {
            let key = try await engine.runWPS(
                interfaceName: effectiveInterface(defaultName: defaultInterface),
                target: target,
                channel: desiredChannel > 0 ? desiredChannel : target.channel,
                logger: { [weak self] line in
                    Task { @MainActor in
                        self?.append(line)
                    }
                }
            )
            if let key {
                wpsKey = key
                wpsMessage = "WPS recovered the key."
                append(LogLine("WPS recovered the key.", kind: .success))
            } else {
                wpsMessage = "PixieWPS did not produce a key. Try the PMKID path instead."
            }
        } catch let error as NetCrackError {
            wpsMessage = error.errorDescription
            append(LogLine(error.errorDescription ?? "WPS failed.", kind: .error))
        } catch {
            wpsMessage = error.localizedDescription
            append(LogLine(error.localizedDescription, kind: .error))
        }
        wpsRunning = false
    }

    func clearWPSResult() {
        wpsKey = nil
        wpsMessage = nil
    }

    func clearLogs() {
        logs.removeAll()
    }

    func clearCapture() {
        guard !isRunning else { return }
        status = .idle
        stats = .empty
        hashes = []
        pcapPath = ""
        diagnostics = .idle
        lastSummary = nil
        elapsed = 0
    }

    func revealPcap() {
        guard let url = pcapURL, FileManager.default.fileExists(atPath: url.path) else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    func copyPcapPath() {
        guard let url = pcapURL else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(url.path, forType: .string)
    }

    func copyLog() {
        let text = logs.map { "\($0.timeString) \($0.text)" }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    // MARK: - Events

    private func handle(_ event: CaptureEngine.Event) {
        switch event {
        case let .status(newStatus):
            status = newStatus
            if newStatus != .starting { isStarting = false }
            if newStatus == .capturing {
                append(LogLine("Capture is live.", kind: .system))
            }
        case let .stats(newStats):
            stats = newStats
            onStats?(newStats)
        case let .hashes(newHashes):
            hashes = newHashes
        case let .diagnostics(newDiagnostics):
            diagnostics = newDiagnostics
        case let .log(line):
            append(line)
        case let .summary(summary):
            lastSummary = summary
            stats = summary.stats
            hashes = summary.hashes
            onSummary?(summary)
        case let .failed(error):
            append(LogLine(error.message, kind: .error))
            status = .failed(error.message)
        }
    }

    private func append(_ line: LogLine) {
        logs.append(line)
        if logs.count > maximumLogLines {
            logs.removeFirst(logs.count - maximumLogLines)
        }
    }

    private func makePcapURL(target: AccessPoint?) -> URL {
        let directory = settings.captureDirectory
        let name: String
        if let target {
            let base = Formatters.safeFileName(target.ssid.isEmpty ? target.bssid : target.ssid, fallback: "capture")
            name = "\(base)-\(Formatters.timestamp()).pcap"
        } else {
            name = "netcrack-\(Formatters.timestamp()).pcap"
        }
        return directory.appendingPathComponent(name)
    }

    private func startTimer() {
        timerTask?.cancel()
        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard let self else { return }
                guard let startedAt = self.startedAt else { return }
                self.elapsed = Date().timeIntervalSince(startedAt)
            }
        }
    }
}
