import Foundation

/// Runs hashcat (or aircrack-ng as an alternative engine) and reports live
/// speed, progress and ETA while it works.
actor Cracker {
    static let shared = Cracker()

    enum Event: Sendable {
        case started(command: String, engine: CrackEngineKind)
        case log(LogLine)
        case status(HashcatStatus)
        case finished(CrackOutcome)
        case exhausted(reason: String)
        case cancelled
        case failed(UserFacingError)
    }

    struct Job: Sendable, Equatable {
        var engine: CrackEngineKind
        var mode: AttackMode
        var hashFile: URL
        var hashFormat: Converter.HashFormat
        /// Needed by the aircrack engine, which cracks the capture directly.
        var pcap: URL?
        var ssid: String
        var targetBSSID: String
        var wordlist: URL?
        var ruleFile: String?
        var mask: String
        var potfile: URL
        var force: Bool
        var deviceIndex: Int?

        init(
            engine: CrackEngineKind,
            mode: AttackMode,
            hashFile: URL,
            hashFormat: Converter.HashFormat,
            pcap: URL? = nil,
            ssid: String = "",
            targetBSSID: String = "",
            wordlist: URL? = nil,
            ruleFile: String? = nil,
            mask: String = "",
            potfile: URL,
            force: Bool = false,
            deviceIndex: Int? = nil
        ) {
            self.engine = engine
            self.mode = mode
            self.hashFile = hashFile
            self.hashFormat = hashFormat
            self.pcap = pcap
            self.ssid = ssid
            self.targetBSSID = targetBSSID
            self.wordlist = wordlist
            self.ruleFile = ruleFile
            self.mask = mask
            self.potfile = potfile
            self.force = force
            self.deviceIndex = deviceIndex
        }
    }

    private let runner = ProcessRunner()
    private var cancelled = false
    private var running = false

    func isRunning() -> Bool { running }

    func cancel() {
        cancelled = true
        Task { await runner.killAll() }
    }

    /// Streams the run. The stream ends after exactly one terminal event.
    nonisolated func run(_ job: Job) -> AsyncStream<Event> {
        AsyncStream { continuation in
            let task = Task {
                await self.execute(job, continuation: continuation)
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination {
                    task.cancel()
                    Task { await self.forceStop() }
                }
            }
        }
    }

    private func forceStop() async {
        cancelled = true
        await runner.killAll()
    }

    // MARK: - Execution

    private func execute(_ job: Job, continuation: AsyncStream<Event>.Continuation) async {
        cancelled = false
        running = true
        defer { running = false }

        do {
            try validate(job)
            if job.engine == .aircrack {
                try await executeAircrack(job, continuation: continuation)
            } else {
                try await executeHashcat(job, continuation: continuation)
            }
        } catch let error as NetCrackError {
            if error.isCancellation || cancelled {
                continuation.yield(.cancelled)
            } else {
                continuation.yield(.failed(UserFacingError(error)))
            }
        } catch {
            continuation.yield(.failed(UserFacingError(error)))
        }
        continuation.finish()
    }

    private func validate(_ job: Job) throws {
        guard FileManager.default.isReadableFile(atPath: job.hashFile.path) else {
            throw NetCrackError.hashFileMissing(job.hashFile.path)
        }
        if job.engine.supports(job.mode) == false {
            throw NetCrackError.other("\(job.engine.title) cannot run the \(job.mode.title) attack. Use hashcat for this mode.")
        }
        if job.mode.needsWordlist {
            guard let wordlist = job.wordlist else {
                throw NetCrackError.wordlistMissing("(no wordlist selected)")
            }
            guard FileManager.default.isReadableFile(atPath: wordlist.path) else {
                throw NetCrackError.wordlistMissing(wordlist.path)
            }
            let size = Formatters.fileSize(at: wordlist)
            guard size > 0 else {
                throw NetCrackError.wordlistEmpty(wordlist.path)
            }
        }
        if job.engine == .aircrack, job.pcap == nil {
            throw NetCrackError.other("aircrack-ng needs the original capture file, not just the hash file.")
        }
        if job.mode == .mask || job.mode == .incremental {
            let mask = resolvedMask(job)
            guard !mask.isEmpty, mask.contains("?") else {
                throw NetCrackError.other("The mask is empty. Use hashcat syntax such as ?d?d?d?d?d?d?d?d for eight digits.")
            }
        }
    }

    private func resolvedMask(_ job: Job) -> String {
        let trimmed = job.mask.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty { return trimmed }
        return "?d?d?d?d?d?d?d?d"
    }

    /// Resolves `best64.rule` (bare names) against the usual hashcat dirs.
    private func resolvedRule(_ job: Job) -> String? {
        guard let raw = job.ruleFile?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        if FileManager.default.isReadableFile(atPath: raw) { return raw }
        let candidates = [
            "/opt/homebrew/share/hashcat/rules/\(raw)",
            "/usr/local/share/hashcat/rules/\(raw)",
            "/opt/homebrew/Cellar/hashcat/rules/\(raw)",
            "\(NSHomeDirectory())/hashcat/rules/\(raw)",
            "/usr/share/hashcat/rules/\(raw)"
        ]
        // Falling back to a bare, unreadable name would make hashcat fail with
        // a cryptic message; returning nil lets the caller run a plain
        // dictionary attack and say so.
        return candidates.first { FileManager.default.isReadableFile(atPath: $0) }
    }

    // MARK: - hashcat

    private func executeHashcat(_ job: Job, continuation: AsyncStream<Event>.Continuation) async throws {
        guard let hashcat = await ToolLocator.shared.executablePath(for: .hashcat) else {
            throw NetCrackError.toolMissing(.hashcat)
        }

        var arguments: [String] = [
            "-m", job.hashFormat.hashcatMode,
            "-w", "3",
            "--status",
            "--status-timer=1",
            "--machine-readable",
            "--potfile-path", job.potfile.path
        ]
        if job.force { arguments.append("--force") }
        if let deviceIndex = job.deviceIndex {
            arguments.append(contentsOf: ["-d", "\(deviceIndex)"])
        }

        switch job.mode {
        case .dictionary, .dictionaryRules:
            guard let wordlist = job.wordlist else { throw NetCrackError.wordlistMissing("(none)") }
            arguments.append(contentsOf: ["-a", "0", job.hashFile.path, wordlist.path])
            if job.mode == .dictionaryRules {
                if let rule = resolvedRule(job) {
                    arguments.append(contentsOf: ["-r", rule])
                } else {
                    continuation.yield(.log(LogLine(
                        "No rule file configured; running a plain dictionary attack instead.",
                        kind: .warning
                    )))
                }
            }
        case .mask:
            arguments.append(contentsOf: ["-a", "3", job.hashFile.path, resolvedMask(job)])
        case .incremental:
            arguments.append(contentsOf: ["-a", "3", job.hashFile.path, resolvedMask(job), "-i"])
        }

        let command = ProcessRunner.Command(executable: hashcat, arguments: arguments)
        continuation.yield(.started(command: command.displayString, engine: .hashcat))
        continuation.yield(.log(LogLine("$ \(command.displayString)", kind: .command)))

        let startedAt = Date()
        var accumulator = HashcatStatusAccumulator()
        var lastStatus = HashcatStatus.zero
        var outputTail: [String] = []
        var exitCode: Int32 = -1

        for await event in runner.stream(command) {
            switch event {
            case let .line(kind, text):
                if let status = accumulator.consume(text) {
                    lastStatus = status
                    continuation.yield(.status(status))
                }
                if kind == .stderr || Self.isInterestingHashcatLine(text) {
                    outputTail.append(text)
                    if outputTail.count > 40 { outputTail.removeFirst() }
                    continuation.yield(.log(LogLine(text, kind: Self.logKind(forHashcatLine: text))))
                }
            case let .output(_, text):
                // Carriage-return progress that never formed a line.
                if let status = accumulator.consume(text) {
                    lastStatus = status
                    continuation.yield(.status(status))
                }
            case let .exited(code):
                exitCode = code
            case let .failed(message):
                throw NetCrackError.processLaunchFailed(message)
            case .started:
                break
            }
        }

        if cancelled {
            continuation.yield(.cancelled)
            return
        }

        let duration = Date().timeIntervalSince(startedAt)
        let combinedTail = outputTail.joined(separator: "\n")

        // Any key ever recovered is authoritative, regardless of exit code:
        // hashcat exits 0 on success, but a cancel or a hash-format warning
        // must not hide a key that is already in the potfile.
        if let key = await recoveredKey(job: job, hashcat: hashcat) {
            continuation.yield(.finished(CrackOutcome(
                key: key,
                hashFile: job.hashFile,
                ssid: job.ssid,
                engine: .hashcat,
                mode: job.mode,
                duration: duration,
                triedCandidates: lastStatus.speedPerSecond * duration,
                deviceName: lastStatus.deviceName
            )))
            return
        }

        let lower = combinedTail.lowercased()
        if lower.contains("no hashes loaded") || lower.contains("no hashes left") {
            throw NetCrackError.other("hashcat could not load any usable hash from the file. Capture again or re-convert the pcap.")
        }
        if lower.contains("no devices found") || lower.contains("no opencl") || lower.contains("no backend devices") {
            throw NetCrackError.other("hashcat found no compute device. On a Mac, make sure the Metal backend is available (hashcat -I).")
        }
        if lower.contains("unsupported hash mode") || lower.contains("invalid hash-mode") {
            throw NetCrackError.other("This hashcat build does not support mode \(job.hashFormat.hashcatMode). Version 6.2.6 or newer is required for the 22000 format.")
        }
        if lower.contains("out of memory") {
            throw NetCrackError.other("hashcat ran out of memory. Reduce the mask keyspace or close other apps.")
        }

        switch exitCode {
        case 0:
            throw NetCrackError.other("hashcat reported success but no key could be read from the potfile. Check \(job.potfile.path).")
        case 1:
            continuation.yield(.exhausted(reason: Self.exhaustedReason(from: combinedTail, mode: job.mode)))
        default:
            throw NetCrackError.hashcatFailed(code: exitCode, output: combinedTail)
        }
    }

    /// Reads the key back with `--show`, which is hashcat's supported way to
    /// ask "what have you already cracked in this file?".
    private func recoveredKey(job: Job, hashcat: String) async -> String? {
        let command = ProcessRunner.Command(
            executable: hashcat,
            arguments: [
                "-m", job.hashFormat.hashcatMode,
                job.hashFile.path,
                "--show",
                "--potfile-path", job.potfile.path
            ]
        )
        guard let result = try? await runner.run(command, timeout: 60) else {
            return readPotfileKey(job: job)
        }
        let lines = result.stdout.split(separator: "\n").map(String.init)
        var candidates: [(hash: String, key: String)] = []
        for line in lines {
            guard let separator = line.firstIndex(of: ":") else { continue }
            let hashPart = String(line[line.startIndex..<separator])
            let key = String(line[line.index(after: separator)...])
            guard !key.isEmpty else { continue }
            candidates.append((hashPart, key))
        }
        guard !candidates.isEmpty else { return readPotfileKey(job: job) }
        if !job.targetBSSID.isEmpty {
            let target = job.targetBSSID.uppercased()
            if let match = candidates.first(where: { $0.hash.uppercased().contains(target) }) {
                return match.key
            }
        }
        return candidates.first?.key
    }

    /// Last-resort potfile read for the case where `--show` itself fails.
    private func readPotfileKey(job: Job) -> String? {
        guard let contents = try? String(contentsOf: job.potfile, encoding: .utf8) else { return nil }
        var hashesInFile = Set<String>()
        if job.hashFormat == .p22000,
           let hashContents = try? String(contentsOf: job.hashFile, encoding: .utf8) {
            for line in hashContents.split(separator: "\n") {
                hashesInFile.insert(String(line))
            }
        }
        for line in contents.split(separator: "\n").reversed() {
            guard let separator = line.firstIndex(of: ":") else { continue }
            let hashPart = String(line[line.startIndex..<separator])
            let key = String(line[line.index(after: separator)...])
            if job.hashFormat == .p22000 && !hashesInFile.isEmpty && !hashesInFile.contains(hashPart) {
                continue
            }
            return key
        }
        return nil
    }

    // MARK: - aircrack-ng

    private func executeAircrack(_ job: Job, continuation: AsyncStream<Event>.Continuation) async throws {
        guard let aircrack = await ToolLocator.shared.executablePath(for: .aircrack) else {
            throw NetCrackError.toolMissing(.aircrack)
        }
        guard let pcap = job.pcap else {
            throw NetCrackError.other("aircrack-ng needs the capture file.")
        }
        guard let wordlist = job.wordlist else {
            throw NetCrackError.wordlistMissing("(none)")
        }

        var arguments = ["-w", wordlist.path]
        if !job.targetBSSID.isEmpty {
            arguments.append(contentsOf: ["-b", job.targetBSSID.lowercased()])
        }
        arguments.append(pcap.path)

        let command = ProcessRunner.Command(executable: aircrack, arguments: arguments)
        continuation.yield(.started(command: command.displayString, engine: .aircrack))
        continuation.yield(.log(LogLine("$ \(command.displayString)", kind: .command)))

        let startedAt = Date()
        var foundKey: String?
        var lastStatus = HashcatStatus.zero
        var speed: Double = 0
        var outputTail: [String] = []

        for await event in runner.stream(command) {
            switch event {
            case let .line(_, text):
                outputTail.append(text)
                if outputTail.count > 60 { outputTail.removeFirst() }
                continuation.yield(.log(LogLine(text, kind: .output)))
                if let key = Self.parseAircrackKey(text) {
                    foundKey = key
                }
                if let parsed = Self.parseAircrackProgress(text, speed: &speed) {
                    lastStatus = HashcatStatus(
                        speedPerSecond: speed,
                        progressPercent: parsed.percent,
                        recovered: foundKey == nil ? 0 : 1,
                        rejected: 0,
                        totalHashes: nil,
                        etaSeconds: parsed.eta,
                        elapsedSeconds: Date().timeIntervalSince(startedAt),
                        deviceName: nil
                    )
                    continuation.yield(.status(lastStatus))
                }
            case let .output(_, text):
                if let key = Self.parseAircrackKey(text), foundKey == nil {
                    foundKey = key
                }
            case let .exited(code):
                _ = code
            case let .failed(message):
                throw NetCrackError.processLaunchFailed(message)
            case .started:
                break
            }
        }

        if cancelled {
            continuation.yield(.cancelled)
            return
        }

        if let key = foundKey {
            let duration = Date().timeIntervalSince(startedAt)
            continuation.yield(.finished(CrackOutcome(
                key: key,
                hashFile: job.hashFile,
                ssid: job.ssid,
                engine: .aircrack,
                mode: job.mode,
                duration: duration,
                triedCandidates: lastStatus.speedPerSecond * duration,
                deviceName: nil
            )))
            return
        }

        let tail = outputTail.joined(separator: "\n")
        if tail.lowercased().contains("passphrase not in dictionary") || tail.lowercased().contains("keys tried") {
            continuation.yield(.exhausted(reason: "aircrack-ng tried the whole wordlist and the passphrase was not in it."))
        } else if tail.lowercased().contains("no valid wpa handshake") {
            throw NetCrackError.other("aircrack-ng found no valid WPA handshake for this network in the capture. Keep capturing, or use hashcat once a PMKID is available.")
        } else if tail.isEmpty {
            continuation.yield(.exhausted(reason: "aircrack-ng produced no output for this capture."))
        } else {
            continuation.yield(.exhausted(reason: tail.split(separator: "\n").last.map(String.init) ?? "No key found."))
        }
    }

    nonisolated static func parseAircrackKey(_ line: String) -> String? {
        guard let range = line.range(of: "KEY FOUND!") else { return nil }
        let rest = line[range.upperBound...]
        guard let open = rest.firstIndex(of: "["), let close = rest.lastIndex(of: "]"), open < close else { return nil }
        let key = rest[rest.index(after: open)..<close].trimmingCharacters(in: .whitespaces)
        return key.isEmpty ? nil : key
    }

    nonisolated static func parseAircrackProgress(
        _ line: String,
        speed: inout Double
    ) -> (percent: Double?, eta: Double?)? {
        // "[00:00:42] 1234/9999 keys tested (250.13 k/s)"
        guard line.contains("keys tested") else { return nil }
        var percent: Double?
        if let slash = line.firstIndex(of: "/"),
           let space = line[..<slash].lastIndex(where: { $0 == " " || $0 == "]" }) {
            let doneText = line[line.index(after: space)..<slash].trimmingCharacters(in: .whitespaces)
            let rest = line[line.index(after: slash)...]
            let totalText = rest.prefix(while: { $0.isNumber })
            if let done = Double(doneText), let total = Double(totalText), total > 0 {
                percent = min(100, done / total * 100)
            }
        }
        if let open = line.lastIndex(of: "("), let close = line.lastIndex(of: ")"), open < close {
            let rateText = line[line.index(after: open)..<close]
            if let parsed = Formatters.parseSpeed(String(rateText)) {
                speed = parsed
            }
        }
        var eta: Double?
        if let open = line.firstIndex(of: "["), let close = line.firstIndex(of: "]"), open < close {
            let clock = line[line.index(after: open)..<close]
            if let seconds = Formatters.parseClockDuration(String(clock)) {
                // In aircrack's progress line the bracket holds *elapsed* time.
                if let percent, percent > 1 {
                    eta = seconds * (100 - percent) / percent
                }
            }
        }
        return (percent, eta)
    }

    // MARK: - Output classification

    nonisolated static func isInterestingHashcatLine(_ line: String) -> Bool {
        let lower = line.lowercased()
        if lower.hasPrefix("status") || lower.hasPrefix("speed") || lower.hasPrefix("progress")
            || lower.hasPrefix("eta") || lower.hasPrefix("recovered") || lower.hasPrefix("rejected")
            || lower.hasPrefix("time") || lower.hasPrefix("guesses") || lower.hasPrefix("kernel")
            || lower.hasPrefix("device") || lower.hasPrefix("hash.target") {
            return false
        }
        return lower.contains("error") || lower.contains("warning") || lower.contains("session")
            || lower.contains("recovered") || lower.contains("exhausted") || lower.contains("cracked")
            || lower.contains("device #") || lower.contains("hashes") || lower.contains("separator")
            || lower.contains("token") || lower.contains("memory") || lower.contains("backend")
            || lower.contains("rules") || lower.contains("wordlist") || lower.contains("dictionary")
    }

    nonisolated static func logKind(forHashcatLine line: String) -> LogLine.Kind {
        let lower = line.lowercased()
        if lower.contains("error") || lower.contains("invalid") || lower.contains("exception") {
            return .error
        }
        if lower.contains("warning") || lower.contains("deprecated") {
            return .warning
        }
        if lower.contains("cracked") || lower.contains("recovered") {
            return .success
        }
        return .output
    }

    nonisolated static func exhaustedReason(from output: String, mode: AttackMode) -> String {
        if output.lowercased().contains("exhausted") {
            switch mode {
            case .dictionary: return "hashcat exhausted the wordlist without a match."
            case .dictionaryRules: return "hashcat exhausted every rule expansion of the wordlist without a match."
            case .mask: return "hashcat exhausted the mask keyspace without a match."
            case .incremental: return "hashcat exhausted the incremental keyspace without a match."
            }
        }
        return "No key found."
    }
}
