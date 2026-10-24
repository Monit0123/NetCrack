import Foundation

/// The "by any means" orchestrator.
///
/// For each selected network it walks the recovery order: Keychain first,
/// then PMKID/EAPOL capture → dictionary → rules → mask → incremental, then
/// WPS on an external adapter, and WEP as its own path. Everything is streamed
/// so the UI can show exactly where a target stands.
actor PipelineEngine {
    enum Event: Sendable {
        case log(LogLine)
        case progress(PipelineProgress)
        case result(PipelineResult)
        case finished([PipelineResult])
        case failed(UserFacingError)
    }

    struct PipelineProgress: Sendable, Equatable {
        var completed: Int
        var total: Int
        var currentSSID: String
        var phase: String
    }

    struct Options: Sendable {
        var mode: CaptureMode
        var interfaceName: String
        var channel: Int?
        var wordlist: URL?
        var ruleFile: String?
        var mask: String
        var crackEngine: CrackEngineKind
        var potfile: URL
        var workDirectory: URL
        var captureSeconds: TimeInterval
        var deauthFirst: Bool
        var runMask: Bool
        var runIncremental: Bool
        var runWPS: Bool
        var runWEP: Bool
        var tryKeychain: Bool
        var forceHashcat: Bool

        static func standard() -> Options {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
                .appendingPathComponent("NetCrack", isDirectory: true)
                ?? FileManager.default.temporaryDirectory.appendingPathComponent("NetCrack", isDirectory: true)
            return Options(
                mode: .builtin,
                interfaceName: "en0",
                channel: nil,
                wordlist: nil,
                ruleFile: nil,
                mask: "?d?d?d?d?d?d?d?d",
                crackEngine: .hashcat,
                potfile: support.appendingPathComponent("netcrack.potfile"),
                workDirectory: support.appendingPathComponent("work", isDirectory: true),
                captureSeconds: 45,
                deauthFirst: false,
                runMask: true,
                runIncremental: false,
                runWPS: false,
                runWEP: true,
                tryKeychain: true,
                forceHashcat: false
            )
        }
    }

    private let captureEngine = CaptureEngine()
    private let runner = ProcessRunner()
    private var cancelled = false
    private var running = false

    func isRunning() -> Bool { running }

    func cancel() async {
        cancelled = true
        await captureEngine.stop()
        await Cracker.shared.cancel()
    }

    /// Streams a whole queue run. Ends with `.finished`.
    nonisolated func run(targets: [AccessPoint], options: Options) -> AsyncStream<Event> {
        AsyncStream { continuation in
            let task = Task {
                await self.execute(targets: targets, options: options, continuation: continuation)
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination {
                    task.cancel()
                    Task { await self.cancel() }
                }
            }
        }
    }

    private func execute(
        targets: [AccessPoint],
        options: Options,
        continuation: AsyncStream<Event>.Continuation
    ) async {
        guard !running else {
            continuation.yield(.failed(UserFacingError(message: "A queue run is already in progress.")))
            continuation.finish()
            return
        }
        guard !targets.isEmpty else {
            continuation.yield(.failed(UserFacingError(message: "Select at least one network first.")))
            continuation.finish()
            return
        }

        running = true
        cancelled = false
        defer { running = false }

        do {
            try FileManager.default.createDirectory(at: options.workDirectory, withIntermediateDirectories: true)
            continuation.yield(.log(LogLine(
                "Queue run: \(targets.count) network\(targets.count == 1 ? "" : "s"), \(Int(options.captureSeconds)) s capture each, engine \(options.crackEngine.title).",
                kind: .system
            )))
        } catch {
            continuation.yield(.failed(UserFacingError(error)))
            continuation.finish()
            return
        }

        var results: [PipelineResult] = []
        for (index, target) in targets.enumerated() {
            if cancelled { break }
            continuation.yield(.progress(PipelineProgress(
                completed: index,
                total: targets.count,
                currentSSID: target.displayName,
                phase: "Starting"
            )))
            let result = await process(
                target,
                options: options,
                index: index + 1,
                total: targets.count,
                continuation: continuation
            )
            results.append(result)
            continuation.yield(.result(result))
            continuation.yield(.log(LogLine(
                "\(target.displayName): \(result.status.rawValue)\(result.key.map { " — key \($0)" } ?? "")",
                kind: result.status == .recovered || result.status == .keychain ? .success : .info
            )))
        }

        continuation.yield(.finished(results))
        continuation.finish()
    }

    // MARK: - Per target

    private func process(
        _ target: AccessPoint,
        options: Options,
        index: Int,
        total: Int,
        continuation: AsyncStream<Event>.Continuation
    ) async -> PipelineResult {
        let startedAt = Date()

        func progress(_ phase: String) {
            continuation.yield(.progress(PipelineProgress(
                completed: index - 1,
                total: total,
                currentSSID: target.displayName,
                phase: phase
            )))
        }

        func makeResult(_ status: PipelineResult.Status, key: String? = nil, detail: String, hashes: Int = 0) -> PipelineResult {
            PipelineResult(
                ssid: target.displayName,
                bssid: target.displayBSSID,
                status: status,
                key: key,
                detail: detail,
                duration: Date().timeIntervalSince(startedAt),
                hashesFound: hashes
            )
        }

        // 1. Keychain: instant, and free.
        if options.tryKeychain, !target.ssid.isEmpty {
            progress("Keychain lookup")
            let probe = await KeychainProbe.shared.lookup(ssid: target.ssid)
            switch probe.outcome {
            case let .found(password):
                continuation.yield(.log(LogLine(
                    "\(target.displayName): the password is already in your Keychain.",
                    kind: .success
                )))
                return makeResult(.keychain, key: password, detail: "Saved on this Mac — no capture needed.")
            case .notFound:
                break
            case let .accessDenied(reason):
                continuation.yield(.log(LogLine("\(target.displayName): Keychain refused access — \(reason)", kind: .warning)))
            case let .failed(reason):
                continuation.yield(.log(LogLine("\(target.displayName): Keychain lookup failed — \(reason)", kind: .warning)))
            }
        }

        if target.ssid.isEmpty {
            return makeResult(.skipped, detail: "Hidden network with no SSID; join it first or select it by BSSID on the Capture pane.")
        }

        guard target.security.isCrackable else {
            let reason: String
            switch target.security {
            case .open, .owe:
                reason = "\(target.security.rawValue) network — there is no password to recover."
            case .enterprise:
                reason = "802.1X enterprise network — the credential is a username/password, not a PSK. Use a capture of the EAP exchange with a dedicated 802.1X tool instead."
            default:
                reason = "Unsupported security type."
            }
            continuation.yield(.log(LogLine("\(target.displayName): skipped (\(reason))", kind: .info)))
            return makeResult(.skipped, detail: reason)
        }

        // 5. WEP is its own path: collect IVs, then aircrack -a 1.
        if target.security == .wep, options.runWEP {
            progress("Capturing WEP IVs")
            let capture = await captureTarget(target, options: options, continuation: continuation)
            if cancelled { return makeResult(.cancelled, detail: "Cancelled.") }
            guard let capture else {
                return makeResult(.failed, detail: "Capture could not start.")
            }
            if capture.stats.frames == 0 {
                return makeResult(.noHandshake, detail: "No frames captured — the built-in radio may not be in real monitor mode, or the adapter is on another channel.")
            }
            progress("Cracking WEP")
            if let key = await crackWEP(pcap: capture.pcapURL, target: target, continuation: continuation) {
                return makeResult(.recovered, key: key, detail: "WEP key recovered from captured IVs.", hashes: capture.stats.frames)
            }
            return makeResult(.exhausted, detail: "Not enough WEP IVs yet. Capture longer or move closer to the AP.", hashes: capture.stats.frames)
        }

        // 2. Capture PMKID / EAPOL.
        progress("Capturing handshake")
        guard let capture = await captureTarget(target, options: options, continuation: continuation) else {
            return makeResult(.failed, detail: "Capture could not start.")
        }
        if cancelled { return makeResult(.cancelled, detail: "Cancelled.") }

        let matched = Converter.hashes(capture.hashes, matching: target)
        let usable = matched.isEmpty ? capture.hashes : matched

        guard !usable.isEmpty else {
            if capture.stats.frames == 0 {
                return makeResult(.noHandshake, detail: "No frames at all. Monitor mode is not delivering data; use an external adapter if this Mac is affected by the macOS 26 monitor-mode bug.")
            }
            return makeResult(.noHandshake, detail: "No handshake or PMKID within \(Int(options.captureSeconds)) s. Wait for a client to connect, or force one with an external adapter.")
        }
        let conversionFormat = capture.conversion?.format ?? .p22000

        continuation.yield(.log(LogLine(
            "\(target.displayName): \(usable.count) usable hash\(usable.count == 1 ? "" : "es") (\(conversionFormat.rawValue)).",
            kind: .success
        )))

        // Write a per-target hash file so a queue never cracks another AP's
        // hashes by accident.
        let hashFile = options.workDirectory
            .appendingPathComponent("\(Formatters.safeFileName(target.displayName, fallback: "target"))-\(Formatters.timestamp()).22000")
        do {
            try Converter.writeHashes(usable, to: hashFile)
        } catch {
            return makeResult(.failed, detail: "Could not write the hash file: \(error.localizedDescription)")
        }

        // 3. Dictionary, rules, mask, incremental.
        let attempts = crackAttempts(options: options, target: target)
        for (mode, timeout) in attempts {
            if cancelled { return makeResult(.cancelled, detail: "Cancelled.") }
            progress("Cracking: \(mode.title)")
            let outcome = await runCrack(
                target: target,
                hashFile: hashFile,
                format: conversionFormat,
                pcap: capture.pcapURL,
                mode: mode,
                options: options,
                timeout: timeout,
                continuation: continuation
            )
            if let key = outcome {
                return makeResult(.recovered, key: key, detail: "Recovered with \(mode.title.lowercased()).", hashes: usable.count)
            }
        }

        // 4. WPS, external adapters only.
        if options.runWPS, options.mode == .external, target.security != .wpa3 {
            progress("WPS")
            do {
                let key = try await captureEngine.runWPS(
                    interfaceName: options.interfaceName,
                    target: target,
                    channel: target.channel,
                    logger: { line in continuation.yield(.log(line)) }
                )
                if let key {
                    return makeResult(.recovered, key: key, detail: "Recovered via WPS.", hashes: usable.count)
                }
            } catch let error as NetCrackError {
                continuation.yield(.log(LogLine(
                    "\(target.displayName): WPS failed — \(error.errorDescription ?? "unknown error")",
                    kind: .warning
                )))
            } catch {
                continuation.yield(.log(LogLine("\(target.displayName): WPS failed — \(error.localizedDescription)", kind: .warning)))
            }
        }

        return makeResult(
            .exhausted,
            detail: "Handshake captured, but none of the \(attempts.count) attack(s) recovered the key.",
            hashes: usable.count
        )
    }

    // MARK: - Capture

    private func captureTarget(
        _ target: AccessPoint,
        options: Options,
        continuation: AsyncStream<Event>.Continuation
    ) async -> CaptureEngine.Summary? {
        // Only ask for administrator rights when the radio is actually
        // needed; a queue of pure Keychain hits never prompts.
        do {
            try await RootExecutor.shared.authorize()
        } catch let error as NetCrackError {
            continuation.yield(.log(LogLine(error.errorDescription ?? "Authorisation failed.", kind: .error)))
            return nil
        } catch {
            continuation.yield(.log(LogLine(error.localizedDescription, kind: .error)))
            return nil
        }

        let pcap = options.workDirectory
            .appendingPathComponent("\(Formatters.safeFileName(target.displayName, fallback: "capture"))-\(Formatters.timestamp()).pcap")

        let configuration = CaptureEngine.Configuration(
            mode: options.mode,
            interfaceName: options.interfaceName,
            desiredChannel: target.channel > 0 ? target.channel : options.channel,
            target: target,
            pcapURL: pcap,
            keepDisplayAwake: true,
            deauthAfterStart: options.deauthFirst && options.mode == .external,
            deauthClient: "",
            lockChannel: true
        )

        var summary: CaptureEngine.Summary?
        var stopRequested = false

        let watchdog = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(options.captureSeconds * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await self?.captureEngine.stop()
        }
        defer { watchdog.cancel() }

        for await event in captureEngine.start(configuration) {
            switch event {
            case let .log(line):
                continuation.yield(.log(line))
            case let .status(status):
                if case .failed = status { /* surfaced through .failed */ }
            case let .hashes(hashes):
                let matched = Converter.hashes(hashes, matching: target)
                let relevant = matched.isEmpty ? hashes : matched
                if !relevant.isEmpty, !stopRequested {
                    // A usable hash is in the file; no reason to keep burning
                    // the radio on this target.
                    stopRequested = true
                    continuation.yield(.log(LogLine(
                        "\(target.displayName): usable hash captured, stopping early.",
                        kind: .success
                    )))
                    await captureEngine.stop()
                }
            case let .summary(value):
                summary = value
            case let .failed(error):
                continuation.yield(.log(LogLine(error.message, kind: .error)))
            case .stats, .diagnostics:
                break
            }
        }

        if cancelled {
            await captureEngine.stop()
        }
        return summary
    }

    // MARK: - Cracking

    private func crackAttempts(options: Options, target: AccessPoint) -> [(AttackMode, TimeInterval)] {
        var modes: [(AttackMode, TimeInterval)] = [(.dictionary, 900)]
        if let rule = options.ruleFile, !rule.isEmpty {
            modes.append((.dictionaryRules, 900))
        }
        if options.runMask {
            modes.append((.mask, 600))
        }
        if options.runIncremental {
            modes.append((.incremental, 900))
        }
        _ = target
        return modes
    }

    private func runCrack(
        target: AccessPoint,
        hashFile: URL,
        format: Converter.HashFormat,
        pcap: URL,
        mode: AttackMode,
        options: Options,
        timeout: TimeInterval,
        continuation: AsyncStream<Event>.Continuation
    ) async -> String? {
        let job = Cracker.Job(
            engine: options.crackEngine,
            mode: mode,
            hashFile: hashFile,
            hashFormat: format,
            pcap: pcap,
            ssid: target.ssid,
            targetBSSID: target.bssidCompact,
            wordlist: options.wordlist,
            ruleFile: options.ruleFile,
            mask: options.mask,
            potfile: options.potfile,
            force: options.forceHashcat
        )

        var key: String?
        let watchdog = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await Cracker.shared.cancel()
        }
        defer { watchdog.cancel() }

        for await event in Cracker.shared.run(job) {
            switch event {
            case let .log(line):
                continuation.yield(.log(line))
            case let .finished(outcome):
                key = outcome.key
            case let .exhausted(reason):
                continuation.yield(.log(LogLine("\(mode.title): \(reason)", kind: .info)))
            case .cancelled:
                continuation.yield(.log(LogLine("\(mode.title): stopped.", kind: .info)))
            case let .failed(error):
                continuation.yield(.log(LogLine("\(mode.title): \(error.message)", kind: .error)))
            case .started, .status:
                break
            }
            if key != nil { break }
        }
        return key
    }

    // MARK: - WEP

    private func crackWEP(
        pcap: URL,
        target: AccessPoint,
        continuation: AsyncStream<Event>.Continuation
    ) async -> String? {
        guard let aircrack = await ToolLocator.shared.executablePath(for: .aircrack) else {
            continuation.yield(.log(LogLine("aircrack-ng is not installed; cannot crack WEP.", kind: .error)))
            return nil
        }
        var arguments = ["-a", "1"]
        if !target.bssid.isEmpty { arguments.append(contentsOf: ["-b", target.bssid.lowercased()]) }
        arguments.append(pcap.path)

        let command = ProcessRunner.Command(executable: aircrack, arguments: arguments)
        continuation.yield(.log(LogLine("$ \(command.displayString)", kind: .command)))
        guard let result = try? await runner.run(command, timeout: 600) else {
            continuation.yield(.log(LogLine("aircrack-ng could not be started.", kind: .error)))
            return nil
        }
        for line in result.stdout.split(separator: "\n") {
            continuation.yield(.log(LogLine(String(line), kind: .output)))
        }
        if let range = result.stdout.range(of: "KEY FOUND!") {
            let rest = result.stdout[range.upperBound...]
            if let open = rest.firstIndex(of: "["), let close = rest.lastIndex(of: "]") {
                let key = rest[rest.index(after: open)..<close].trimmingCharacters(in: .whitespaces)
                if !key.isEmpty { return key }
            }
        }
        return nil
    }
}
