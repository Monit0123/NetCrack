import Foundation
import AppKit
import UniformTypeIdentifiers

/// Crack stage: wordlist, attack mode and the live hashcat status.
@MainActor
final class CrackViewModel: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var status = HashcatStatus.zero
    @Published private(set) var logs: [LogLine] = []
    @Published private(set) var recoveredKey: String?
    @Published private(set) var outcome: CrackOutcome?
    @Published private(set) var exhaustedReason: String?
    @Published private(set) var hashFile: URL?
    @Published private(set) var hashFormat: Converter.HashFormat = .p22000
    @Published private(set) var pcapFile: URL?
    @Published private(set) var hashCount = 0
    @Published private(set) var elapsed: TimeInterval = 0
    @Published private(set) var target: AccessPoint?
    @Published private(set) var sourceDescription: String = "No hashes loaded"
    @Published var error: UserFacingError?

    @Published var attackMode: AttackMode {
        didSet { settings.attackMode = attackMode }
    }
    @Published var engine: CrackEngineKind {
        didSet { settings.crackEngine = engine }
    }
    @Published var mask: String {
        didSet { settings.mask = mask }
    }
    @Published var ruleFile: String {
        didSet { settings.ruleFile = ruleFile }
    }
    @Published var force: Bool = false
    @Published private(set) var wordlistURL: URL?

    var targetProvider: (() -> AccessPoint?)?

    private let settings: SettingsStore
    private var consumeTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var startedAt: Date?
    private let maximumLogLines = 1_500

    init(settings: SettingsStore) {
        self.settings = settings
        self.attackMode = settings.attackMode
        self.engine = settings.crackEngine
        self.mask = settings.mask
        self.ruleFile = settings.ruleFile
        self.wordlistURL = settings.effectiveWordlist
    }

    // MARK: - Derived

    var effectiveWordlist: URL? {
        if let wordlistURL, FileManager.default.isReadableFile(atPath: wordlistURL.path) {
            return wordlistURL
        }
        return settings.bundledWordlistURL
    }

    var wordlistDisplayName: String {
        guard let list = effectiveWordlist else { return "None" }
        if list.lastPathComponent == "\(SettingsStore.bundledWordlistName).txt" {
            return "Bundled top-10k"
        }
        return list.lastPathComponent
    }

    var wordlistIsBundled: Bool {
        guard let list = effectiveWordlist, let bundled = settings.bundledWordlistURL else { return false }
        return list.standardizedFileURL == bundled.standardizedFileURL
    }

    var canRun: Bool {
        hashFile != nil && !isRunning
    }

    var hasKey: Bool { recoveredKey?.isEmpty == false }

    var progressFraction: Double {
        guard let percent = status.progressPercent else { return 0 }
        return min(1, max(0, percent / 100))
    }

    var progressIsDeterminate: Bool {
        status.progressPercent != nil
    }

    var speedText: String { status.speedLabel }

    var progressText: String { status.progressLabel }

    var etaText: String {
        if let eta = status.etaSeconds, eta > 0 {
            return Formatters.eta(eta)
        }
        if let percent = status.progressPercent, percent > 0.5, elapsed > 0 {
            let remaining = elapsed * (100 - percent) / percent
            return Formatters.eta(remaining)
        }
        return "—"
    }

    var elapsedText: String { Formatters.clock(elapsed) }

    var maskKeyspaceText: String {
        guard attackMode == .mask || attackMode == .incremental else { return "" }
        guard let keyspace = Formatters.maskKeyspace(mask) else {
            return "Custom character set — hashcat computes the keyspace."
        }
        return "\(Formatters.compactNumber(keyspace)) candidates"
    }

    var hashSummary: String {
        guard hashFile != nil else { return "No hashes loaded" }
        switch hashFormat {
        case .p22000:
            return "\(hashCount) hash\(hashCount == 1 ? "" : "es") · 22000"
        case .hccapx:
            return "\(hashCount) handshake\(hashCount == 1 ? "" : "s") · hccapx (mode 2500)"
        }
    }

    // MARK: - Hash sources

    func adopt(summary: CaptureEngine.Summary, target: AccessPoint?) {
        self.target = target
        let allHashes: [CaptureHash]
        if summary.hashes.isEmpty, let file = summary.hashFile,
           let contents = try? String(contentsOf: file, encoding: .utf8) {
            allHashes = contents.split(separator: "\n").compactMap { CaptureLineParser.parseHashLine(String($0)) }
        } else {
            allHashes = summary.hashes
        }

        guard !allHashes.isEmpty else {
            append(LogLine("The last capture produced no hashes, so there is nothing to crack yet.", kind: .warning))
            sourceDescription = "Last capture had no handshake"
            hashFile = nil
            hashCount = 0
            return
        }

        let filtered = Converter.hashes(allHashes, matching: target)
        let usable = filtered.isEmpty ? allHashes : filtered
        let format = summary.conversion?.format ?? .p22000

        do {
            try settings.ensureCaptureDirectory()
            let directory = settings.captureDirectory.appendingPathComponent("hashes", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let name = "\(Formatters.safeFileName(target?.displayName ?? "capture", fallback: "capture"))-\(Formatters.timestamp()).22000"
            let url = directory.appendingPathComponent(name)

            if format == .hccapx, let file = summary.hashFile {
                // Aircrack's hccapx is already a single file per capture.
                hashFile = file
            } else {
                try Converter.writeHashes(usable, to: url)
                hashFile = url
            }
            hashFormat = format
            hashCount = usable.count
            pcapFile = summary.pcapURL
            sourceDescription = summary.pcapURL.lastPathComponent
            recoveredKey = nil
            outcome = nil
            exhaustedReason = nil
            status = .zero
            elapsed = 0
            append(LogLine(
                "Loaded \(usable.count) hash\(usable.count == 1 ? "" : "es") from \(summary.pcapURL.lastPathComponent).",
                kind: .success
            ))
        } catch {
            self.error = UserFacingError(error)
            append(LogLine("Could not write the hash file: \(error.localizedDescription)", kind: .error))
        }
    }

    func loadHashFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a hashcat 22000 or hccapx file"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.canChooseFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let ext = url.pathExtension.lowercased()
        hashFormat = ext == "hccapx" ? .hccapx : .p22000
        hashFile = url
        pcapFile = nil
        target = targetProvider?()
        sourceDescription = url.lastPathComponent

        if hashFormat == .p22000, let contents = try? String(contentsOf: url, encoding: .utf8) {
            hashCount = contents.split(separator: "\n").filter { $0.hasPrefix("WPA*") }.count
        } else if hashFormat == .hccapx {
            hashCount = max(1, Int(Formatters.fileSize(at: url) / 393))
        } else {
            hashCount = 0
        }
        recoveredKey = nil
        outcome = nil
        exhaustedReason = nil
        append(LogLine("Loaded \(url.lastPathComponent) (\(hashCount) entries).", kind: .system))
    }

    /// Converts an existing pcap on disk into hashes, for captures made before
    /// the app started or with another tool.
    func convertPcap() async {
        let panel = NSOpenPanel()
        panel.title = "Choose a pcap to convert"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data, .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let destination = url.deletingPathExtension().appendingPathExtension("22000")
            let result = try await Converter.shared.convert(pcap: url, destination: destination, copyWhileWriting: false)
            guard result.hashCount > 0 else {
                append(LogLine(result.notes.first ?? "No handshake or PMKID in that pcap.", kind: .warning))
                self.error = UserFacingError(message: "Nothing crackable in that capture.", detail: result.statusLine)
                return
            }
            hashFile = result.hashFile
            hashFormat = result.format
            hashCount = result.hashCount
            pcapFile = url
            sourceDescription = url.lastPathComponent
            recoveredKey = nil
            outcome = nil
            exhaustedReason = nil
            append(LogLine("Converted \(url.lastPathComponent): \(result.statusLine).", kind: .success))
        } catch {
            self.error = UserFacingError(error)
        }
    }

    func chooseWordlist() {
        let panel = NSOpenPanel()
        panel.title = "Choose a wordlist"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.plainText, .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        wordlistURL = url
        settings.rememberWordlist(url)
        append(LogLine("Wordlist: \(url.path)", kind: .system))
    }

    func useBundledWordlist() {
        guard let bundled = settings.bundledWordlistURL else {
            self.error = UserFacingError(message: "The bundled wordlist is missing from the app bundle.", detail: "Reinstall the app or pick your own list.")
            return
        }
        wordlistURL = bundled
        settings.rememberWordlist(bundled)
    }

    // MARK: - Run

    func run() async {
        guard let hashFile else {
            self.error = UserFacingError(message: "No hashes loaded.", detail: "Capture a handshake first, or load a .22000 file.")
            return
        }
        guard !isRunning else { return }

        if engine == .aircrack && pcapFile == nil {
            self.error = UserFacingError(message: "aircrack-ng cracks the capture directly, and the pcap for these hashes is not known.", detail: "Pick a pcap with “Convert pcap…”, then run aircrack-ng, or switch the engine to hashcat.")
            return
        }
        if !engine.supports(attackMode) {
            self.error = UserFacingError(message: "\(engine.title) cannot run a \(attackMode.title.lowercased()) attack.", detail: "Use hashcat for mask and incremental attacks.")
            return
        }

        let potfile = try? ensurePotfile()
        guard let potfile else {
            self.error = UserFacingError(message: "Could not create the potfile directory.")
            return
        }

        logs.removeAll()
        recoveredKey = nil
        outcome = nil
        exhaustedReason = nil
        status = .zero
        elapsed = 0
        isRunning = true
        startedAt = Date()
        append(LogLine("Starting \(engine.title) · \(attackMode.title)", kind: .system))

        let job = Cracker.Job(
            engine: engine,
            mode: attackMode,
            hashFile: hashFile,
            hashFormat: hashFormat,
            pcap: pcapFile,
            ssid: target?.ssid ?? "",
            targetBSSID: target?.bssidCompact ?? "",
            wordlist: effectiveWordlist,
            ruleFile: ruleFile.isEmpty ? nil : ruleFile,
            mask: mask,
            potfile: potfile,
            force: force
        )

        startTimer()
        consumeTask = Task { [weak self] in
            for await event in Cracker.shared.run(job) {
                guard let self else { return }
                self.handle(event)
            }
            self?.isRunning = false
            self?.timerTask?.cancel()
            self?.timerTask = nil
        }
    }

    func cancel() async {
        guard isRunning else { return }
        append(LogLine("Stopping the crack…", kind: .system))
        await Cracker.shared.cancel()
    }

    func copyKey() {
        guard let recoveredKey else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(recoveredKey, forType: .string)
    }

    func copyLog() {
        let text = logs.map { "\($0.timeString) \($0.text)" }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func clearLogs() {
        logs.removeAll()
    }

    private func ensurePotfile() throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let directory = base.appendingPathComponent("NetCrack", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("netcrack.potfile")
    }

    private func handle(_ event: Cracker.Event) {
        switch event {
        case let .started(command, _):
            append(LogLine("$ \(command)", kind: .command))
        case let .log(line):
            append(line)
        case let .status(newStatus):
            status = newStatus
            if newStatus.recovered > 0, recoveredKey == nil {
                append(LogLine("hashcat reports a recovered hash; reading the key…", kind: .success))
            }
        case let .finished(result):
            outcome = result
            recoveredKey = result.key
            isRunning = false
            append(LogLine("Key recovered: \(result.key)", kind: .success))
        case let .exhausted(reason):
            exhaustedReason = reason
            isRunning = false
            append(LogLine(reason, kind: .warning))
        case .cancelled:
            isRunning = false
            append(LogLine("Crack cancelled.", kind: .system))
        case let .failed(error):
            self.error = error
            isRunning = false
            append(LogLine(error.message, kind: .error))
        }
    }

    private func append(_ line: LogLine) {
        logs.append(line)
        if logs.count > maximumLogLines {
            logs.removeFirst(logs.count - maximumLogLines)
        }
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
