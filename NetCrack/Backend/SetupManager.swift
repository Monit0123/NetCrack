import Foundation

/// Installs the Homebrew toolchain with streamed output.
///
/// Homebrew formulae other than aircrack-ng have bottles on Apple Silicon;
/// aircrack-ng does not, hence the `--build-from-source` path that the UI
/// warns about.
actor SetupManager {
    enum Event: Sendable {
        case log(LogLine)
        case started(String)
        case finished(ToolchainReport)
        case failed(UserFacingError)
    }

    static let shared = SetupManager()

    private let runner = ProcessRunner()
    private var installing = false

    private static let homebrewInstallScript = """
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    """

    /// Formulae that provide the required tools. `tcpdump` is usually already
    /// present at /usr/bin/tcpdump, so it is only installed when missing.
    static func formulas(for tools: [ExternalTool]) -> [String] {
        var ordered: [String] = []
        for tool in tools {
            let formula = tool.installFormula
            if formula == "aircrack-ng" {
                continue
            }
            if formula == "reaver" {
                continue
            }
            if formula == "tcpdump" {
                continue
            }
            if !ordered.contains(formula) { ordered.append(formula) }
        }
        return ordered
    }

    func isRunning() -> Bool {
        installing
    }

    func cancelInstall() {
        installing = false
        Task { await runner.killAll() }
    }

    /// Runs the full install chain for whatever is missing.
    nonisolated func install(
        missing: [ExternalTool],
        includeOptional: Bool,
        buildAircrackFromSource: Bool
    ) -> AsyncStream<Event> {
        AsyncStream { continuation in
            let task = Task {
                await self.performInstall(
                    missing: missing,
                    includeOptional: includeOptional,
                    buildAircrackFromSource: buildAircrackFromSource,
                    continuation: continuation
                )
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination {
                    task.cancel()
                    Task { await self.runner.killAll() }
                }
            }
        }
    }

    private func performInstall(
        missing: [ExternalTool],
        includeOptional: Bool,
        buildAircrackFromSource: Bool,
        continuation: AsyncStream<Event>.Continuation
    ) async {
        installing = true
        defer { installing = false }
        let locator = ToolLocator.shared

        guard let brewPath = await locator.executablePath(for: .brew) else {
            continuation.yield(.log(LogLine("Homebrew was not found in /opt/homebrew/bin or /usr/local/bin.", kind: .error)))
            continuation.yield(.log(LogLine("Install it with the command below, then press “Check again”.", kind: .info)))
            continuation.yield(.log(LogLine(#"/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)""#, kind: .command)))
            continuation.yield(.failed(UserFacingError(
                message: "Homebrew is required before the other tools can be installed.",
                detail: "Open Terminal and run the Homebrew install command shown in the log, then press “Check again”."
            )))
            continuation.finish()
            return
        }

        let needsAircrack = missing.contains(.aircrack) || missing.contains(.wash)

        // 1. Bottled formulae in a single command so brew resolves the
        //    dependency graph once.
        var bottled = SetupManager.formulas(for: missing)
        if includeOptional && missing.contains(.reaver) {
            bottled.append("reaver")
        }
        if missing.contains(.tcpdump) {
            bottled.append("tcpdump")
        }
        var brewEnv: [String: String] = [
            "NONINTERACTIVE": "1",
            "HOMEBREW_NO_AUTO_UPDATE": "1",
            "HOMEBREW_NO_ANALYTICS": "1",
            "HOMEBREW_NO_ENV_HINTS": "1"
        ]
        if let prefix = Self.brewPrefix(for: brewPath) {
            brewEnv["HOMEBREW_PREFIX"] = prefix
        }

        if !bottled.isEmpty {
            let command = ProcessRunner.Command(
                executable: brewPath,
                arguments: ["install"] + bottled,
                environment: brewEnv
            )
            continuation.yield(.started(command.displayString))
            let exit = await stream(command: command, label: "brew install", continuation: continuation)
            if exit != 0 {
                continuation.yield(.log(LogLine("brew install exited with \(exit). Continuing with the remaining steps so you can see every error.", kind: .warning)))
            }
        }

        // 2. aircrack-ng: no Apple Silicon bottle, so build it. This is slow
        //    but it is the only supported route on arm64.
        if needsAircrack {
            let isAppleSilicon = Self.isAppleSilicon()
            let fromSource = buildAircrackFromSource || (isAppleSilicon && missing.contains(.aircrack))
            var arguments = ["install"]
            if fromSource { arguments.append("--build-from-source") }
            arguments.append("aircrack-ng")
            let command = ProcessRunner.Command(
                executable: brewPath,
                arguments: arguments,
                environment: brewEnv
            )
            continuation.yield(.log(LogLine(
                fromSource
                    ? "aircrack-ng has no Apple Silicon bottle — building from source. This typically takes 5–15 minutes; the log below is live."
                    : "Installing the aircrack-ng bottle.",
                kind: fromSource ? .warning : .info
            )))
            continuation.yield(.started(command.displayString))
            let exit = await stream(command: command, label: "brew install aircrack-ng", continuation: continuation)
            if exit != 0 {
                continuation.yield(.log(LogLine("aircrack-ng did not install. WPS, deauth and the aircrack engine stay unavailable until it does.", kind: .warning)))
            }
        }

        // 3. Re-probe and report.
        await locator.invalidate()
        let report = await locator.report(refresh: true)

        if report.missing.isEmpty {
            continuation.yield(.log(LogLine("All required tools are installed.", kind: .success)))
        } else {
            continuation.yield(.log(LogLine(
                "Still missing: \(report.missing.map(\.executable).joined(separator: ", ")). Check the log for the failing formula.",
                kind: .error
            )))
        }
        continuation.yield(.finished(report))
        continuation.finish()
    }

    /// Installs Homebrew itself. Needs root, so it goes through the same
    /// single-prompt privileged channel; afterwards the prefix is handed back
    /// to the current user because brew refuses to run as root.
    nonisolated func installHomebrew() -> AsyncStream<Event> {
        AsyncStream { continuation in
            let task = Task {
                do {
                    try await RootExecutor.shared.authorize()
                    let uid = Self.currentUserID()
                    let gid = Self.currentGroupID()
                    let prefix = Self.isAppleSilicon() ? "/opt/homebrew" : "/usr/local"
                    let command = """
                    export NONINTERACTIVE=1
                    \(Self.homebrewInstallScript) || exit $?
                    if [ -d \(prefix) ]; then chown -R \(uid):\(gid) \(prefix); fi
                    """
                    continuation.yield(.started("install Homebrew into \(prefix)"))
                    for await event in RootExecutor.shared.streamShell(command, killPattern: "install.sh") {
                        switch event {
                        case let .line(line):
                            continuation.yield(.log(LogLine(line, kind: Self.kind(forBrewLine: line))))
                        case let .exited(code):
                            if code != 0 {
                                continuation.yield(.log(LogLine("Homebrew installer exited with \(code).", kind: .error)))
                            } else {
                                continuation.yield(.log(LogLine("Homebrew installed.", kind: .success)))
                            }
                        case let .failed(message):
                            throw NetCrackError.other(message)
                        case .started:
                            break
                        }
                    }
                    await ToolLocator.shared.invalidate()
                    let report = await ToolLocator.shared.report(refresh: true)
                    continuation.yield(.finished(report))
                } catch {
                    continuation.yield(.failed(UserFacingError(error)))
                }
                continuation.finish()
            }
            continuation.onTermination = { @Sendable termination in
                if case .cancelled = termination { task.cancel() }
            }
        }
    }

    // MARK: - Helpers

    private func stream(
        command: ProcessRunner.Command,
        label: String,
        continuation: AsyncStream<Event>.Continuation,
        quietSuccess: Bool = false
    ) async -> Int32 {
        continuation.yield(.log(LogLine("$ \(command.displayString)", kind: .command)))
        var exitCode: Int32 = -1
        for await event in runner.stream(command) {
            switch event {
            case let .line(_, text):
                continuation.yield(.log(LogLine(text, kind: SetupManager.kind(forBrewLine: text))))
            case let .output(_, text):
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    continuation.yield(.log(LogLine(trimmed, kind: .progress)))
                }
            case let .exited(code):
                exitCode = code
                if code == 0 && !quietSuccess {
                    continuation.yield(.log(LogLine("\(label) finished.", kind: .success)))
                }
            case let .failed(message):
                continuation.yield(.log(LogLine(message, kind: .error)))
            case .started:
                break
            }
        }
        return exitCode
    }

    private static func kind(forBrewLine line: String) -> LogLine.Kind {
        let lower = line.lowercased()
        if lower.hasPrefix("error") || lower.contains("error:") || lower.contains("failed to") {
            return .error
        }
        if lower.hasPrefix("warning") || lower.contains("warning:") || lower.contains("deprecated") {
            return .warning
        }
        if lower.hasPrefix("==>") {
            return .info
        }
        return .output
    }

    private static func brewPrefix(for brewPath: String) -> String? {
        if brewPath.hasPrefix("/opt/homebrew") { return "/opt/homebrew" }
        if brewPath.hasPrefix("/usr/local") { return "/usr/local" }
        return nil
    }

    nonisolated static func isAppleSilicon() -> Bool {
        var isArm: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let result = sysctlbyname("hw.optional.arm64", &isArm, &size, nil, 0)
        return result == 0 && isArm == 1
    }

    private static func currentUserID() -> uid_t {
        getuid()
    }

    private static func currentGroupID() -> gid_t {
        getgid()
    }
}
