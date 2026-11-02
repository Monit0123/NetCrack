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

    private let runner = ProcessRunner()
    private var statusValue: Status = .needsAuthorization
    private var authorizationTask: Task<Void, Error>?

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

    /// Starts the privileged supervisor if it is not already running. Safe to
    /// call concurrently: the second caller waits on the first attempt.
    func authorize() async throws {
        if isDaemonAlive() {
            statusValue = .authorized
            return
        }

        if RootExecutor.runningAsRoot() {
            // Already root: no prompt, the supervisor is just a normal child.
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
        } catch {
            authorizationTask = nil
            let mapped: NetCrackError
            if let netCrack = error as? NetCrackError {
                mapped = netCrack
            } else {
                mapped = .authorizationFailed(error.localizedDescription)
            }
            statusValue = .failed(mapped.errorDescription ?? "Authorisation failed.")
            throw mapped
        }
    }

    /// Sends the one-off `osascript` prompt and waits for the heartbeat.
    private static func promptForAuthorization(configuration: Configuration) async throws {
        try prepareSessionDirectory(configuration.sessionDirectory)
        let daemonScript = configuration.sessionDirectory.appendingPathComponent("daemon.sh")
        try Self.daemonSource.write(to: daemonScript, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: daemonScript.path)

        // Anything left over from a previous session is garbage now.
        Self.clearArtifacts(in: configuration.sessionDirectory)

        let dir = configuration.sessionDirectory.path
        let shellCommand = """
        nohup /bin/sh \(Formatters.shellQuoted(daemonScript.path)) \(Formatters.shellQuoted(dir)) \
        \(Int(configuration.idleTimeout)) \(Int(configuration.hardLifetime)) >/dev/null 2>&1 </dev/null &
        """

        let appleScript = """
        do shell script "\(Self.appleScriptEscaped(shellCommand))" \
        with administrator privileges with prompt "\(Self.appleScriptEscaped(configuration.authorizationPrompt))"
        """

        let runner = ProcessRunner()
        let result = try await runner.run(
            ProcessRunner.Command(
                executable: "/usr/bin/osascript",
                arguments: ["-e", appleScript]
            ),
            timeout: 120
        )

        guard result.exitCode == 0 else {
            let combined = result.combined.lowercased()
            if combined.contains("user canceled") || combined.contains("(-128)") {
                throw NetCrackError.authorizationDenied
            }
            throw NetCrackError.authorizationFailed(result.tail.isEmpty ? "osascript exited with \(result.exitCode)" : result.tail)
        }

        // Wait for the supervisor's first heartbeat.
        let heartbeat = configuration.sessionDirectory.appendingPathComponent("alive")
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: heartbeat.path) {
                // Confirm it really answers, not just that the file exists.
                if await Self.probeSupervisor(configuration: configuration) { return }
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        throw NetCrackError.authorizationFailed("The privileged helper did not start. Try again, or run `sudo tcpdump -i en0 -I` in Terminal to test your system.")
    }

    /// When the app itself is root there is no dialog to show.
    private func startSupervisorDirectly() throws {
        try RootExecutor.prepareSessionDirectory(configuration.sessionDirectory)
        let daemonScript = configuration.sessionDirectory.appendingPathComponent("daemon.sh")
        try RootExecutor.daemonSource.write(to: daemonScript, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: daemonScript.path)
        RootExecutor.clearArtifacts(in: configuration.sessionDirectory)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            daemonScript.path,
            configuration.sessionDirectory.path,
            "\(Int(configuration.idleTimeout))",
            "\(Int(configuration.hardLifetime))"
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try process.run()

        let heartbeat = configuration.sessionDirectory.appendingPathComponent("alive")
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: heartbeat.path) { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
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
        let heartbeat = configuration.sessionDirectory.appendingPathComponent("alive")
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: heartbeat.path),
              let modified = attributes[.modificationDate] as? Date else {
            return false
        }
        return Date().timeIntervalSince(modified) < RootExecutor.heartbeatFreshness
    }

    // MARK: - File protocol internals

    private static func prepareSessionDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private static func clearArtifacts(in directory: URL) {
        let manager = FileManager.default
        guard let entries = try? manager.contentsOfDirectory(atPath: directory.path) else { return }
        for entry in entries where entry != "daemon.sh" {
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

    // MARK: - Supervisor script

    /// The root-side supervisor. POSIX sh only: macOS images do not ship with
    /// Bash 4 features and we cannot rely on the user's shell configuration.
    static let daemonSource = #"""
    #!/bin/sh
    # NetCrack privileged command supervisor.
    # Usage: daemon.sh <session-dir> <idle-seconds> <lifetime-seconds>
    # Started exactly once per authorisation via an administrator prompt.
    DIR="$1"
    IDLE_LIMIT="${2:-1800}"
    LIFETIME="${3:-21600}"
    HEARTBEAT="$DIR/alive"

    [ -d "$DIR" ] || exit 1
    umask 077
    chmod 700 "$DIR" 2>/dev/null
    : > "$HEARTBEAT" 2>/dev/null || exit 1

    START=$(date +%s)
    LAST_ACTIVITY=$START
    LAST_TOUCH=0

    while :; do
      NOW=$(date +%s)

      # The app removes the heartbeat to ask the supervisor to exit.
      [ -f "$HEARTBEAT" ] || break

      if [ $((NOW - LAST_TOUCH)) -ge 2 ]; then
        : > "$HEARTBEAT" 2>/dev/null
        LAST_TOUCH=$NOW
      fi

      for cmd in "$DIR"/*.cmd; do
        [ -e "$cmd" ] || continue
        base=${cmd##*/}
        id=${base%.cmd}
        run="$DIR/$id.run"
        mv "$cmd" "$run" 2>/dev/null || continue
        : > "$DIR/$id.out"
        chmod 644 "$DIR/$id.out" 2>/dev/null
        (
          /bin/sh "$run" > "$DIR/$id.out" 2>&1
          echo $? > "$DIR/$id.code"
          chmod 644 "$DIR/$id.code" 2>/dev/null
          rm -f "$run"
        ) &
        LAST_ACTIVITY=$NOW
      done

      for killfile in "$DIR"/*.kill; do
        [ -e "$killfile" ] || continue
        base=${killfile##*/}
        id=${base%.kill}
        SIG=$(sed -n '1p' "$killfile" 2>/dev/null)
        PATTERN=$(sed -n '2p' "$killfile" 2>/dev/null)
        [ -n "$SIG" ] || SIG=TERM
        if [ -n "$PATTERN" ]; then
          pkill -"$SIG" -f "$PATTERN" 2>/dev/null
        fi
        if [ -f "$DIR/$id.pid" ]; then
          kill -"$SIG" "$(cat "$DIR/$id.pid")" 2>/dev/null
        fi
        mv "$killfile" "$DIR/$id.killed" 2>/dev/null
        LAST_ACTIVITY=$NOW
      done

      # A running command keeps the session alive even if the app is idle.
      for running in "$DIR"/*.run; do
        [ -e "$running" ] || continue
        LAST_ACTIVITY=$NOW
        break
      done

      if [ $((NOW - LAST_ACTIVITY)) -gt "$IDLE_LIMIT" ]; then break; fi
      if [ $((NOW - START)) -gt "$LIFETIME" ]; then break; fi

      sleep 1
    done

    rm -f "$HEARTBEAT"
    exit 0
    """#
}
