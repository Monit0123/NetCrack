import Foundation

/// Async wrapper around `Foundation.Process`.
///
/// Every byte a helper tool writes is delivered as a line through an
/// `AsyncStream`. Nothing here touches the main thread, and no caller ever
/// blocks waiting for a pipe.
actor ProcessRunner {
    // MARK: - Types

    struct Command: Sendable, Equatable {
        var executable: String
        var arguments: [String]
        var environment: [String: String]
        var workingDirectory: URL?

        init(
            executable: String,
            arguments: [String] = [],
            environment: [String: String] = [:],
            workingDirectory: URL? = nil
        ) {
            self.executable = executable
            self.arguments = arguments
            self.environment = environment
            self.workingDirectory = workingDirectory
        }

        var displayString: String {
            ([executable] + arguments)
                .map { argument -> String in
                    if argument.contains(" ") { return "'" + argument + "'" }
                    return argument
                }
                .joined(separator: " ")
        }
    }

    enum StreamKind: String, Sendable {
        case stdout
        case stderr
    }

    enum Event: Sendable {
        case started(pid: Int32)
        case line(StreamKind, String)
        /// A partial line was produced without a trailing newline. Tools
        /// that use carriage returns for progress land here when the poll
        /// interval expires.
        case output(StreamKind, String)
        case exited(Int32)
        case failed(String)
    }

    struct Result: Sendable {
        var exitCode: Int32
        var stdout: String
        var stderr: String

        var combined: String {
            if stdout.isEmpty { return stderr }
            if stderr.isEmpty { return stdout }
            return stdout + "\n" + stderr
        }

        var isSuccess: Bool { exitCode == 0 }

        /// Last non-empty line, handy for error messages.
        var tail: String {
            combined
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .last(where: { !$0.isEmpty }) ?? ""
        }
    }

    enum CancelSignal: Sendable {
        case terminate
        case interrupt
    }

    // MARK: - State

    private var processes: [UUID: Process] = [:]

    /// PATH handed to children: a GUI app inherits a minimalist PATH, so the
    /// Homebrew prefixes are added explicitly.
    static let childPath = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin"
    ].joined(separator: ":")

    // MARK: - Public API

    /// Streams a command. The stream always ends after `.exited` or `.failed`.
    nonisolated func stream(_ command: Command) -> AsyncStream<Event> {
        let id = UUID()
        return AsyncStream { continuation in
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination {
                    Task { await self.kill(id: id) }
                }
            }
            Task {
                await self.launch(command, id: id, continuation: continuation)
            }
        }
    }

    /// Runs a command to completion and collects its output. Output is
    /// capped so a runaway tool cannot exhaust memory.
    func run(
        _ command: Command,
        timeout: TimeInterval? = nil,
        outputLimit: Int = 262_144
    ) async throws -> Result {
        let id = UUID()
        var stdout = ""
        var stderr = ""
        var exitCode: Int32?

        let stream = stream(command)
        let timeoutTask = Task<Void, Never> { [weak self] in
            guard let timeout else { return }
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await self?.kill(id: id, signal: .terminate)
        }
        defer { timeoutTask.cancel() }

        for await event in stream {
            switch event {
            case let .line(kind, text):
                switch kind {
                case .stdout:
                    if stdout.count < outputLimit { stdout += text + "\n" }
                case .stderr:
                    if stderr.count < outputLimit { stderr += text + "\n" }
                }
            case let .output(kind, text):
                switch kind {
                case .stdout:
                    if stdout.count < outputLimit { stdout += text }
                case .stderr:
                    if stderr.count < outputLimit { stderr += text }
                }
            case let .exited(code):
                exitCode = code
            case let .failed(message):
                throw NetCrackError.processLaunchFailed("\(command.executable): \(message)")
            case .started:
                break
            }
        }

        // A stream cancelled by the timeout task unblocks iteration but the
        // exit event never arrives; treat that as a failure the caller sees.
        guard let code = exitCode else {
            if timeout != nil {
                throw NetCrackError.other("\(command.executable) did not finish in time and was stopped.")
            }
            throw NetCrackError.other("\(command.executable) ended without an exit status.")
        }
        return Result(exitCode: code, stdout: stdout, stderr: stderr)
    }

    /// Runs one of the fixed system utilities where a non-zero exit is an
    /// expected answer (e.g. `security` returning 44) instead of a throw.
    func runLenient(_ command: Command, timeout: TimeInterval = 20) async -> Result? {
        try? await run(command, timeout: timeout)
    }

    func kill(id: UUID, signal: CancelSignal = .terminate) {
        guard let process = processes[id], process.isRunning else {
            processes[id] = nil
            return
        }
        switch signal {
        case .terminate: process.terminate()
        case .interrupt: process.interrupt()
        }
    }

    /// Stops every child. Used when the app quits.
    func killAll() {
        for process in processes.values where process.isRunning {
            process.terminate()
        }
        processes.removeAll()
    }

    func activeCount() -> Int {
        processes.values.filter(\.isRunning).count
    }

    // MARK: - Launch

    private func launch(
        _ command: Command,
        id: UUID,
        continuation: AsyncStream<Event>.Continuation
    ) {
        guard FileManager.default.isExecutableFile(atPath: command.executable) else {
            continuation.yield(.failed("not executable at \(command.executable)"))
            continuation.finish()
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        if let directory = command.workingDirectory {
            process.currentDirectoryURL = directory
        }
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = ProcessRunner.childPath
        environment["LC_ALL"] = "C"
        environment["LANG"] = "en_US.UTF-8"
        environment["TERM"] = "dumb"
        environment["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        environment["HOMEBREW_NO_ENV_HINTS"] = "1"
        for (key, value) in command.environment {
            environment[key] = value
        }
        process.environment = environment
        process.standardInput = FileHandle.nullDevice

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdoutReader = PipeLineReader(continuation: continuation, kind: .stdout)
        let stderrReader = PipeLineReader(continuation: continuation, kind: .stderr)

        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                stdoutReader.flush()
            } else {
                stdoutReader.append(data)
            }
        }
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                stderrReader.flush()
            } else {
                stderrReader.append(data)
            }
        }

        process.terminationHandler = { finished in
            stdoutPipe.fileHandleForReading.readabilityHandler = nil
            stderrPipe.fileHandleForReading.readabilityHandler = nil
            let remainingOut = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            if !remainingOut.isEmpty { stdoutReader.append(remainingOut) }
            let remainingErr = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            if !remainingErr.isEmpty { stderrReader.append(remainingErr) }
            stdoutReader.flush()
            stderrReader.flush()
            continuation.yield(.exited(finished.terminationStatus))
            continuation.finish()
            Task { await self.didExit(id: id) }
        }

        do {
            try process.run()
        } catch {
            continuation.yield(.failed(error.localizedDescription))
            continuation.finish()
            return
        }

        processes[id] = process
        continuation.yield(.started(pid: process.processIdentifier))
    }

    private func didExit(id: UUID) {
        processes[id] = nil
    }
}

/// Splits pipe bytes into lines and forwards them. Read from Foundation's
/// readability handlers, which may hop between queues, hence the lock.
private final class PipeLineReader: @unchecked Sendable {
    private let continuation: AsyncStream<ProcessRunner.Event>.Continuation
    private let kind: ProcessRunner.StreamKind
    private let lock = NSLock()
    private var buffer = Data()

    init(continuation: AsyncStream<ProcessRunner.Event>.Continuation, kind: ProcessRunner.StreamKind) {
        self.continuation = continuation
        self.kind = kind
    }

    func append(_ data: Data) {
        lock.lock()
        buffer.append(data)
        var lines: [String] = []
        while let newlineIndex = buffer.firstIndex(of: 0x0A) {
            let lineData = buffer[buffer.startIndex..<newlineIndex]
            buffer.removeSubrange(buffer.startIndex...newlineIndex)
            if let line = String(data: lineData, encoding: .utf8) {
                lines.append(line)
            } else {
                lines.append(String(decoding: lineData, as: UTF8.self))
            }
        }
        // Guard against a tool that streams without newlines.
        if buffer.count > 65_536 {
            if let text = String(data: buffer, encoding: .utf8) {
                continuation.yield(.output(kind, text))
            }
            buffer.removeAll(keepingCapacity: true)
        }
        lock.unlock()

        for line in lines where !line.isEmpty {
            continuation.yield(.line(kind, line))
        }
    }

    func flush() {
        lock.lock()
        let remaining = buffer
        buffer.removeAll(keepingCapacity: false)
        lock.unlock()
        guard !remaining.isEmpty, let text = String(data: remaining, encoding: .utf8) else { return }
        let trimmed = text.replacingOccurrences(of: "\r", with: "")
        guard !trimmed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        continuation.yield(.line(kind, trimmed))
    }
}
