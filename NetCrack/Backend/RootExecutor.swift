import Foundation

/// Runs commands as root after a **single** authorisation prompt.
///
/// `sudo` cannot be primed without a terminal, and calling `do shell script …
/// with administrator privileges` once per command would prompt the user every
/// single time. So the first time NetCrack needs root it asks the user once,
/// and that one prompt starts a tiny shell supervisor running as root. All
/// later privileged work is dropped into that supervisor's inbox.
///
/// Wire protocol (all inside `~/Library/Application Support/NetCrack/rootsession`):
///   `alive`          heartbeat, touched by the daemon, removed to shut it down
///   `<id>.cmd`       a shell command for the daemon to run
///   `<id>.out`       merged stdout+stderr, append-only, read by the app
///   `<id>.code`      exit status, written when the command finishes
///   `<id>.pid`       PID of the shell running the command
///   `<id>.kill`      first line: signal, second line: `pkill -f` pattern
///   `<id>.killed`    the daemon's acknowledgement of a kill request
///
/// The directory is 0700 and owned by the invoking user; the supervisor has an
/// idle timeout and a hard lifetime so a forgotten session cannot linger.
actor RootExecutor {
    static let shared = RootExecutor()

    enum Event: Sendable {
        case started
        case line(String)
        case exited(Int32)
        case failed(String)
    }

    struct CommandResult: Sendable {
        var exitCode: Int32
        var output: String

        var isSuccess: Bool { exitCode == 0 }

        var tail: String {
            output.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .last(where: { !$0.isEmpty }) ?? ""
        }
    }

    enum Status: Equatable, Sendable {
        case authorized
        case needsAuthorization
        case authorizing
        case failed(String)
    }

    struct Configuration: Sendable {
        var sessionDirectory: URL
        var idleTimeout: TimeInterval
        var hardLifetime: TimeInterval
        var authorizationPrompt: String
    }

    // MARK: - Constants

    /// How long the supervisor may sit idle before it shuts itself down.
    private static let defaultIdleTimeout: TimeInterval = 30 * 60
    /// Absolute upper bound for a supervisor session.
    private static let defaultHardLifetime: TimeInterval = 6 * 60 * 60
    /// A heartbeat older than this means the supervisor is gone.
    private static let heartbeatFreshness: TimeInterval = 8

    private var statusValue: Status = .needsAuthorization
    private var authorizationTask: Task<Void, Error>?
    /// Whatever the launcher reported the last time it failed. Empty after a
    /// successful authorisation.
    private var lastAttempt: String = ""

    /// Immutable and Sendable, so the non-isolated streaming API can read it
    /// without hopping onto the actor.
    nonisolated let configuration: Configuration

    init(configuration: Configuration = RootExecutor.defaultConfiguration()) {
        self.configuration = configuration
    }

    static func defaultConfiguration() -> Configuration {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("NetCrack/rootsession", isDirectory: true)
        return Configuration(
            sessionDirectory: dir,
            idleTimeout: defaultIdleTimeout,
            hardLifetime: defaultHardLifetime,
            authorizationPrompt: "NetCrack needs administrator access once to put the Wi-Fi radio into monitor mode and to read captured frames."
        )
    }

    // MARK: - Status

    func status() -> Status {
        if isDaemonAlive() { return .authorized }
        if case .authorizing = statusValue { return .authorizing }
        if case let .failed(message) = statusValue { return .failed(message) }
        return .needsAuthorization
    }

    func isAuthorized() -> Bool {
        isDaemonAlive()
    }

    /// True when the process itself is root (e.g. the app was launched with
    /// `sudo ./NetCrack`), in which case no prompt is needed at all.
    nonisolated static func runningAsRoot() -> Bool {
        geteuid() == 0
    }

    // MARK: - Authorisation

    /// Installed next to the session files and executed as root.
    private static let helperScripts = ["daemon", "launch"]
    static let helperLabel = "com.netcrack.helper"
    static let launchDaemonPath = "/Library/LaunchDaemons/com.netcrack.helper.plist"

    /// Starts the privileged supervisor if it is not already running. Safe to
    /// call concurrently: the second caller waits on the first attempt.
    func authorize() async throws {
        if isDaemonAlive() {
            statusValue = .authorized
            lastAttempt = ""
            return
        }

        if RootExecutor.runningAsRoot() {
            // Already root: no prompt, the launcher just runs.
            try startSupervisorDirectly()
            statusValue = .authorized
            return
        }

        if let existing = authorizationTask {
            try await existing.value
            return
        }

        statusValue = .authorizing
        let task = Task<Void, Error> { [configuration] in
            try await RootExecutor.promptForAuthorization(configuration: configuration)
        }
        authorizationTask = task
        do {
            try await task.value
            authorizationTask = nil
            statusValue = .authorized
            lastAttempt = ""
        } catch {
            authorizationTask = nil
            let mapped: NetCrackError
            if let netCrack = error as? NetCrackError {
                mapped = netCrack
            } else {
                mapped = .authorizationFailed(error.localizedDescription)
            }
            statusValue = .failed(mapped.errorDescription ?? "Authorisation failed.")
            lastAttempt = Self.diagnostics(configuration: configuration)
            throw mapped
        }
    }

    /// Sends the one-off `osascript` prompt and waits for the heartbeat.
    private static func promptForAuthorization(configuration: Configuration) async throws {
        try prepareSessionDirectory(configuration.sessionDirectory)
        try installLauncher(in: configuration.sessionDirectory, configuration: configuration)
        Self.clearArtifacts(in: configuration.sessionDirectory)

        let launcher = configuration.sessionDirectory.appendingPathComponent("launch.sh")
        let command = launcherCommand(
            directory: configuration.sessionDirectory,
            launcher: launcher,
            configuration: configuration
        )
        let appleScript = """
        do shell script "\(Self.appleScriptEscaped(command))" \
        with administrator privileges with prompt "\(Self.appleScriptEscaped(configuration.authorizationPrompt))"
        """

        let result = try await ProcessRunner().run(
            ProcessRunner.Command(
                executable: "/usr/bin/osascript",
                arguments: ["-e", appleScript]
            ),
            timeout: 180
        )

        guard result.exitCode == 0 else {
            let combined = result.combined.lowercased()
            if combined.contains("user canceled") || combined.contains("(-128)") {
                throw NetCrackError.authorizationDenied
            }
            let detail = result.tail.isEmpty ? "osascript exited with \(result.exitCode)" : result.tail
            throw NetCrackError.authorizationFailed(
                "\(detail) \(Self.diagnosticSummary(configuration: configuration, attempt: result.combined))"
            )
        }

        // The launcher reports through stdout as well as launch.log, so a
        // failure can be described instead of guessed at.
        if await waitForSupervisor(configuration: configuration) { return }

        let attempt = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
        throw NetCrackError.authorizationFailed(
            RootExecutor.failureMessage(configuration: configuration, attempt: attempt)
        )
    }

    /// Polls until the supervisor answers a real command, not just until a file
    /// with the right name exists.
    private static func waitForSupervisor(configuration: Configuration) async -> Bool {
        let deadline = Date().addingTimeInterval(25)
        while Date() < deadline {
            if Self.heartbeatIsFresh(configuration: configuration),
               await probeSupervisor(configuration: configuration) {
                return true
            }
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        return false
    }

    /// When the app itself is root there is no dialog to show.
    private func startSupervisorDirectly() throws {
        let directory = configuration.sessionDirectory
        try RootExecutor.prepareSessionDirectory(directory)
        try RootExecutor.installLauncher(in: directory, configuration: configuration)
        RootExecutor.clearArtifacts(in: directory)

        let launcher = directory.appendingPathComponent("launch.sh")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            launcher.path,
            directory.path,
            "\(getuid())",
            "\(getgid())",
            "\(Int(configuration.idleTimeout))",
            "\(Int(configuration.hardLifetime))"
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()

        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if RootExecutor.heartbeatIsFresh(configuration: configuration) { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
        throw NetCrackError.authorizationFailed(
            RootExecutor.failureMessage(
                configuration: configuration,
                attempt: "launcher exited with \(process.terminationStatus) (running as root)"
            )
        )
    }

    private static func launcherCommand(
        directory: URL,
        launcher: URL,
        configuration: Configuration
    ) -> String {
        [
            "/bin/sh",
            Formatters.shellQuoted(launcher.path),
            Formatters.shellQuoted(directory.path),
            "\(getuid())",
            "\(getgid())",
            "\(Int(configuration.idleTimeout))",
            "\(Int(configuration.hardLifetime))"
        ].joined(separator: " ")
    }

    private static func probeSupervisor(configuration: Configuration) async -> Bool {
        // Writing a real command through the channel is the only honest test.
        let marker = "probe-\(UUID().uuidString.prefix(8))"
        do {
            let outcome = try await execute(
                command: "id -u; echo \(marker)",
                configuration: configuration,
                timeout: 10,
                killPattern: nil
            )
            let lines = outcome.output
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
            // `id -u` for root is exactly "0", on its own line.
            return lines.contains("0") && lines.contains(marker)
        } catch {
            return false
        }
    }

    // MARK: - Helper installation

    /// Copies the two shell scripts out of the app bundle and writes the
    /// LaunchDaemon property list. All three live in the session directory so
    /// the launcher — which runs as root, with no idea where the app is — has
    /// everything it needs in one place.
    private static func installLauncher(in directory: URL, configuration: Configuration) throws {
        for name in helperScripts {
            let source = try helperScript(named: name)
            let destination = directory.appendingPathComponent("\(name).sh")
            try source.write(to: destination, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: destination.path
            )
        }

        let plist = launchDaemonPlist(directory: directory, configuration: configuration)
        let plistURL = directory.appendingPathComponent("\(helperLabel).plist")
        try plist.write(to: plistURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: plistURL.path
        )
    }

    private static func helperScript(named name: String) throws -> String {
        var candidates: [URL] = []
        if let url = Bundle.main.url(forResource: name, withExtension: "sh") {
            candidates.append(url)
        }
        if let resources = Bundle.main.resourceURL {
            candidates.append(resources.appendingPathComponent("\(name).sh"))
        }
        let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent()
        if let executableDirectory {
            candidates.append(executableDirectory.deletingLastPathComponent()
                .appendingPathComponent("Resources/\(name).sh"))
        }
        for url in candidates {
            if let text = try? String(contentsOf: url, encoding: .utf8), !text.isEmpty {
                return text
            }
        }
        throw NetCrackError.authorizationFailed(
            "NetCrack's helper scripts (\(name).sh) are missing from the app bundle. "
            + "The copy of NetCrack.app is incomplete — download it again."
        )
    }

    private static func launchDaemonPlist(directory: URL, configuration: Configuration) -> String {
        let daemon = directory.appendingPathComponent("daemon.sh").path
        let log = directory.appendingPathComponent("daemon.log").path
        func escape(_ value: String) -> String {
            value
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        let arguments = [
            "/bin/sh", daemon, directory.path,
            "\(Int(configuration.idleTimeout))",
            "\(Int(configuration.hardLifetime))",
            "\(getuid())", "\(getgid())"
        ]
        let argumentXML = arguments
            .map { "        <string>\(escape($0))</string>" }
            .joined(separator: "\n")

        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(helperLabel)</string>
            <key>ProgramArguments</key>
            <array>
        \(argumentXML)
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <false/>
            <key>ProcessType</key>
            <string>Interactive</string>
            <key>StandardOutPath</key>
            <string>\(escape(log))</string>
            <key>StandardErrorPath</key>
            <string>\(escape(log))</string>
        </dict>
        </plist>
        """
    }

    // MARK: - Diagnostics

    private static func heartbeatIsFresh(configuration: Configuration) -> Bool {
        let heartbeat = configuration.sessionDirectory.appendingPathComponent("alive")
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: heartbeat.path),
              let modified = attributes[.modificationDate] as? Date else {
            return false
        }
        return Date().timeIntervalSince(modified) < heartbeatFreshness
    }

    private static func failureMessage(configuration: Configuration, attempt: String) -> String {
        let reason = launchOutcome(from: attempt)
        let log = configuration.sessionDirectory.appendingPathComponent("launch.log").path
        return """
        The privileged helper did not start. \(reason)
        The full log is at \(log) — Setup → Administrator helper can copy it.
        """
    }

    /// Pulls the useful lines out of the launcher's own report.
    static func launchOutcome(from output: String) -> String {
        let interesting = output
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { line in
                line.contains("launchd:") || line.contains("nohup:")
                    || line.hasPrefix("RESULT=") || line.hasPrefix("FATAL")
                    || line.contains("WARNING:") || line.contains("launchctl")
            }
        if interesting.isEmpty { return "The launcher produced no report." }
        return interesting.joined(separator: " · ")
    }

    private static func diagnosticSummary(configuration: Configuration, attempt: String) -> String {
        let outcome = launchOutcome(from: attempt)
        let log = configuration.sessionDirectory.appendingPathComponent("launch.log").path
        return "\(outcome) Log: \(log)"
    }

    /// Full report for the Setup sheet: directory state, both helper logs and
    /// whether a LaunchDaemon is still registered.
    static func diagnostics(configuration: Configuration, attempt: String = "") -> String {
        let directory = configuration.sessionDirectory
        let manager = FileManager.default
        var report: [String] = []
        report.append("NetCrack privileged helper")
        report.append("app:        \(Bundle.main.bundlePath)")
        report.append("session:    \(directory.path)")
        report.append("effective:  uid \(getuid()), gid \(getgid())")
        report.append("heartbeat:  \(heartbeatIsFresh(configuration: configuration) ? "fresh" : "missing or stale")")
        report.append("daemon:     \(manager.fileExists(atPath: launchDaemonPath) ? "LaunchDaemon installed" : "no LaunchDaemon installed")")
        if !attempt.isEmpty {
            report.append("")
            report.append("--- last attempt")
            report.append(attempt.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        report.append("")
        report.append("--- session directory")
        if let entries = try? manager.contentsOfDirectory(atPath: directory.path), !entries.isEmpty {
            for entry in entries.sorted() {
                let path = directory.appendingPathComponent(entry).path
                let attributes = try? manager.attributesOfItem(atPath: path)
                let size = (attributes?[.size] as? NSNumber)?.intValue ?? 0
                let owner = (attributes?[.ownerAccountID] as? NSNumber)?.intValue ?? -1
                let permissions = (attributes?[.posixPermissions] as? NSNumber)?.intValue ?? 0
                report.append("  \(String(permissions, radix: 8)) \(size) bytes uid=\(owner) \(entry)")
            }
        } else {
            report.append("  (empty or unreadable)")
        }
        for name in ["launch.log", "daemon.log"] {
            report.append("")
            report.append("--- \(name) (tail)")
            report.append(tail(directory.appendingPathComponent(name), lines: 60))
        }
        return report.joined(separator: "\n")
    }

    private static func tail(_ url: URL, lines: Int) -> String {
        guard let text = try? String(contentsOf: url, encoding: .utf8), !text.isEmpty else {
            return "(missing)"
        }
        let all = text.split(separator: "\n", omittingEmptySubsequences: false)
        return all.suffix(lines).joined(separator: "\n")
    }

    // MARK: - Running commands

    func runShell(
        _ command: String,
        timeout: TimeInterval = 60,
        killPattern: String? = nil
    ) async throws -> CommandResult {
        if !isDaemonAlive() {
            try await authorize()
        }
        guard isDaemonAlive() else {
            throw NetCrackError.authorizationFailed("The privileged helper is not running.")
        }
        return try await RootExecutor.execute(
            command: command,
            configuration: configuration,
            timeout: timeout,
            killPattern: killPattern
        )
    }

    /// Streams a root command's merged output. The caller owns cancellation:
    /// cancelling the consuming task triggers a kill request.
    nonisolated func streamShell(
        _ command: String,
        killPattern: String? = nil
    ) -> AsyncStream<Event> {
        let configuration = self.configuration
        return AsyncStream { continuation in
            let task = Task {
                do {
                    guard await self.isAuthorized() else {
                        continuation.yield(.failed(NetCrackError.authorizationFailed("The privileged helper is not running.").errorDescription ?? "not authorised"))
                        continuation.finish()
                        return
                    }
                    let id = UUID().uuidString
                    try RootExecutor.submit(
                        command: command,
                        id: id,
                        configuration: configuration
                    )
                    continuation.yield(.started)
                    var offset: UInt64 = 0
                    var pending = Data()
                    var finished = false

                    while !finished {
                        if Task.isCancelled {
                            RootExecutor.requestKill(id: id, signal: "TERM", pattern: killPattern, configuration: configuration)
                            break
                        }
                        do {
                            try await Task.sleep(nanoseconds: 120_000_000)
                        } catch {
                            RootExecutor.requestKill(id: id, signal: "TERM", pattern: killPattern, configuration: configuration)
                            break
                        }

                        let outputURL = configuration.sessionDirectory.appendingPathComponent("\(id).out")
                        let codeURL = configuration.sessionDirectory.appendingPathComponent("\(id).code")

                        if let chunk = RootExecutor.read(from: outputURL, offset: &offset) {
                            pending.append(chunk)
                            var lines: [String] = []
                            while let newlineIndex = pending.firstIndex(of: 0x0A) {
                                let lineData = pending[pending.startIndex..<newlineIndex]
                                pending.removeSubrange(pending.startIndex...newlineIndex)
                                let line = String(decoding: lineData, as: UTF8.self)
                                    .replacingOccurrences(of: "\r", with: "")
                                if !line.isEmpty { lines.append(line) }
                            }
                            for line in lines { continuation.yield(.line(line)) }
                        }

                        if let codeText = try? String(contentsOf: codeURL, encoding: .utf8),
                           let code = Int32(codeText.trimmingCharacters(in: .whitespacesAndNewlines)) {
                            // One last read catches output written between the
                            // previous poll and the exit status.
                            if let chunk = RootExecutor.read(from: outputURL, offset: &offset) {
                                pending.append(chunk)
                            }
                            if !pending.isEmpty {
                                let tail = String(decoding: pending, as: UTF8.self).replacingOccurrences(of: "\r", with: "")
                                let trimmed = tail.trimmingCharacters(in: .whitespacesAndNewlines)
                                if !trimmed.isEmpty { continuation.yield(.line(trimmed)) }
                            }
                            continuation.yield(.exited(code))
                            finished = true
                            RootExecutor.cleanUp(id: id, configuration: configuration)
                        }
                    }
                    continuation.finish()
                } catch let error as NetCrackError {
                    continuation.yield(.failed(error.errorDescription ?? "root command failed"))
                    continuation.finish()
                } catch {
                    continuation.yield(.failed(error.localizedDescription))
                    continuation.finish()
                }
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination { task.cancel() }
            }
        }
    }

    /// Fire-and-forget kill request by pattern. Used to stop a capture.
    func killByPattern(_ pattern: String, signal: String = "INT") {
        let id = UUID().uuidString
        RootExecutor.requestKill(id: id, signal: signal, pattern: pattern, configuration: configuration)
    }

    func shutdown() {
        let alive = configuration.sessionDirectory.appendingPathComponent("alive")
        try? FileManager.default.removeItem(at: alive)
        RootExecutor.clearArtifacts(in: configuration.sessionDirectory)
        statusValue = .needsAuthorization
    }

    // MARK: - Daemon liveness

    private func isDaemonAlive() -> Bool {
        RootExecutor.heartbeatIsFresh(configuration: configuration)
    }

    // MARK: - File protocol internals

    private static func prepareSessionDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private static func clearArtifacts(in directory: URL) {
        let manager = FileManager.default
        guard let entries = try? manager.contentsOfDirectory(atPath: directory.path) else { return }
        // The launcher, its property list and the logs survive: the logs are the
        // evidence the Setup sheet shows when a launch fails.
        let keep: Set<String> = ["daemon.sh", "launch.sh", "\(helperLabel).plist", "launch.log", "daemon.log"]
        for entry in entries where !keep.contains(entry) {
            try? manager.removeItem(at: directory.appendingPathComponent(entry))
        }
    }

    private static func submit(command: String, id: String, configuration: Configuration) throws {
        try prepareSessionDirectory(configuration.sessionDirectory)
        let pidFile = configuration.sessionDirectory.appendingPathComponent("\(id).pid").path
        // `$$` is the shell that the daemon forks; the tool inherits the
        // process group, and cancellation also uses a pkill pattern.
        let body = "echo $$ > \(Formatters.shellQuoted(pidFile))\n\(command)\n"

        let finalURL = configuration.sessionDirectory.appendingPathComponent("\(id).cmd")
        let temporaryURL = configuration.sessionDirectory.appendingPathComponent("\(id).cmd.partial")
        try body.write(to: temporaryURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporaryURL.path)
        // Rename keeps the daemon from reading a half-written command.
        try FileManager.default.moveItem(at: temporaryURL, to: finalURL)
    }

    private static func execute(
        command: String,
        configuration: Configuration,
        timeout: TimeInterval,
        killPattern: String?
    ) async throws -> CommandResult {
        let id = UUID().uuidString
        try submit(command: command, id: id, configuration: configuration)

        let deadline = Date().addingTimeInterval(timeout)
        let outputURL = configuration.sessionDirectory.appendingPathComponent("\(id).out")
        let codeURL = configuration.sessionDirectory.appendingPathComponent("\(id).code")
        var offset: UInt64 = 0
        var output = ""

        while Date() < deadline {
            if Task.isCancelled {
                requestKill(id: id, signal: "TERM", pattern: killPattern, configuration: configuration)
                throw NetCrackError.cancelled
            }
            try await Task.sleep(nanoseconds: 100_000_000)
            if let chunk = read(from: outputURL, offset: &offset),
               let text = String(data: chunk, encoding: .utf8) {
                output += text
            }
            if let codeText = try? String(contentsOf: codeURL, encoding: .utf8),
               let code = Int32(codeText.trimmingCharacters(in: .whitespacesAndNewlines)) {
                if let chunk = read(from: outputURL, offset: &offset),
                   let text = String(data: chunk, encoding: .utf8) {
                    output += text
                }
                cleanUp(id: id, configuration: configuration)
                return CommandResult(exitCode: code, output: output)
            }
        }

        requestKill(id: id, signal: "TERM", pattern: killPattern, configuration: configuration)
        cleanUp(id: id, configuration: configuration)
        throw NetCrackError.other("The privileged command did not finish within \(Int(timeout)) s and was stopped.")
    }

    /// Reads bytes appended since `offset`.
    private static func read(from url: URL, offset: inout UInt64) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let end = try? handle.seekToEnd() else { return nil }
        guard end > offset else { return nil }
        do {
            try handle.seek(toOffset: offset)
            let data = handle.readDataToEndOfFile()
            offset += UInt64(data.count)
            return data
        } catch {
            return nil
        }
    }

    private static func requestKill(
        id: String,
        signal: String,
        pattern: String?,
        configuration: Configuration
    ) {
        let directory = configuration.sessionDirectory
        let body = "\(signal)\n\(pattern ?? "")\n"
        let url = directory.appendingPathComponent("\(id).kill")
        try? body.write(to: url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private static func cleanUp(id: String, configuration: Configuration) {
        let directory = configuration.sessionDirectory
        for suffix in ["cmd", "out", "code", "pid", "kill", "killed", "run", "partial"] {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent("\(id).\(suffix)"))
        }
    }

    private static func appleScriptEscaped(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    // MARK: - Diagnostics snapshot

    /// The report the Setup sheet shows. Collected on demand so it is always
    /// current, even after a failed attempt.
    func diagnosticsReport() -> String {
        let attempt = lastAttempt.isEmpty
            ? RootExecutor.diagnostics(configuration: configuration)
            : lastAttempt
        return attempt
    }
}
