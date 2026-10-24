import Foundation

/// Finds the external binaries and asks each one for its version. Results are
/// cached; `refresh` re-probes (used after an install).
actor ToolLocator {
    static let shared = ToolLocator()

    private var cache: [ExternalTool: ToolStatus] = [:]
    private let runner = ProcessRunner()

    /// Absolute locations to search, most specific first.
    nonisolated static func candidates(for tool: ExternalTool) -> [String] {
        var results: [String] = []
        if let hint = tool.bundledHintPath {
            results.append(hint)
        }
        // Prefer the Homebrew prefix that actually exists on this Mac.
        let prefixes = ["/opt/homebrew", "/usr/local"]
        for prefix in prefixes {
            let candidate = "\(prefix)/bin/\(tool.executable)"
            if FileManager.default.isExecutableFile(atPath: candidate) {
                results.append(candidate)
            }
        }
        if let fromPath = lookupInEnvironmentPath(tool.executable) {
            results.append(fromPath)
        }
        for directory in tool.searchDirectories {
            results.append("\(directory)/\(tool.executable)")
        }
        var seen = Set<String>()
        return results.filter { seen.insert($0).inserted }
    }

    private nonisolated static func lookupInEnvironmentPath(_ executable: String) -> String? {
        let path = ProcessInfo.processInfo.environment["PATH"] ?? ""
        for directory in path.split(separator: ":") {
            let candidate = "\(directory)/\(executable)"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    func status(for tool: ExternalTool, refresh: Bool = false) async -> ToolStatus {
        if !refresh, let cached = cache[tool] { return cached }
        let status = await Self.probe(tool, runner: runner)
        cache[tool] = status
        return status
    }

    func report(refresh: Bool = false) async -> ToolchainReport {
        var statuses: [ExternalTool: ToolStatus] = [:]
        await withTaskGroup(of: ToolStatus.self) { group in
            for tool in ExternalTool.allCases {
                group.addTask { [runner] in
                    if !refresh, let cached = await self.cachedStatus(tool) { return cached }
                    return await ToolLocator.probe(tool, runner: runner)
                }
            }
            for await status in group {
                statuses[status.tool] = status
            }
        }
        for (tool, status) in statuses {
            cache[tool] = status
        }
        return ToolchainReport(statuses: statuses, checkedAt: Date(), isChecking: false)
    }

    private func cachedStatus(_ tool: ExternalTool) -> ToolStatus? {
        cache[tool]
    }

    func executablePath(for tool: ExternalTool) async -> String? {
        if let cached = cache[tool] { return cached.path }
        return await status(for: tool).path
    }

    func invalidate() {
        cache.removeAll()
    }

    // MARK: - Probing

    nonisolated static func probe(_ tool: ExternalTool, runner: ProcessRunner) async -> ToolStatus {
        guard let path = candidates(for: tool).first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return ToolStatus(tool: tool, path: nil, version: nil, failure: "not found")
        }
        let command = ProcessRunner.Command(
            executable: path,
            arguments: tool.versionArguments
        )
        let result: ProcessRunner.Result?
        do {
            result = try await runner.run(command, timeout: 12)
        } catch {
            result = nil
        }

        let versionText = result.map { firstVersionLine($0.stdout + "\n" + $0.stderr) } ?? nil
        // A non-zero exit for --version is common (wash, some wrappers). The
        // binary exists, which is what matters; keep whatever text came back.
        return ToolStatus(
            tool: tool,
            path: path,
            version: versionText,
            failure: versionText == nil ? "installed, version unavailable" : nil
        )
    }

    nonisolated static func firstVersionLine(_ output: String) -> String? {
        let lines = output
            .split(whereSeparator: { $0 == "\n" || $0 == "\r" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !lines.isEmpty else { return nil }
        // Skip banners such as "hashcat (v6.2.6) starting in backend...".
        if let line = lines.first(where: { $0.lowercased().contains("version") || $0.hasPrefix("v") || $0.first?.isNumber == true }) {
            return line
        }
        return lines[0]
    }
}
