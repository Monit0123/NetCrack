import Foundation

/// Reads Wi-Fi passwords that macOS already saved.
///
/// This is the fastest possible path to a "recovered" key: if the Mac has ever
/// joined the network, the password is sitting in the login keychain already.
/// macOS stores those items with the protection class
/// `AirPort network password`, so `security` can retrieve them without
/// touching the radio at all.
actor KeychainProbe {
    static let shared = KeychainProbe()

    enum Outcome: Equatable, Sendable {
        case found(String)
        /// The item does not exist: macOS never saved a key for this SSID.
        case notFound
        /// The keychain refused access (locked, or the user declined the prompt).
        case accessDenied(String)
        case failed(String)

        var password: String? {
            if case let .found(value) = self { return value }
            return nil
        }

        var isFound: Bool { password != nil }
    }

    struct Result: Equatable, Sendable {
        var ssid: String
        var outcome: Outcome
        var checkedAt: Date
    }

    private let runner = ProcessRunner()
    private var cache: [String: Result] = [:]

    /// SSID currently joined, straight from `networksetup` (no root, no
    /// Location permission needed for this particular call).
    func joinedSSID(interfaceName: String) async -> String? {
        let result = try? await runner.run(
            ProcessRunner.Command(
                executable: "/usr/sbin/networksetup",
                arguments: ["-getairportnetwork", interfaceName]
            ),
            timeout: 10
        )
        guard let result, result.exitCode == 0 else { return nil }
        // "Current Wi-Fi Network: MyNet" or "You are not associated with an AirPort network."
        guard let range = result.stdout.range(of: ":") else { return nil }
        let ssid = result.stdout[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ssid.isEmpty, !ssid.lowercased().contains("not associated") else { return nil }
        return ssid
    }

    /// Looks a password up for the joined network.
    func probeJoinedNetwork(interfaceName: String) async -> Result? {
        guard let ssid = await joinedSSID(interfaceName: interfaceName) else { return nil }
        return await lookup(ssid: ssid)
    }

    func lookup(ssid: String) async -> Result {
        let trimmed = ssid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return Result(ssid: ssid, outcome: .notFound, checkedAt: Date())
        }
        if let cached = cache[trimmed] {
            return cached
        }

        let result = await readPassword(ssid: trimmed)
        cache[trimmed] = result
        return result
    }

    func invalidate(ssid: String? = nil) {
        if let ssid {
            cache.removeValue(forKey: ssid)
        } else {
            cache.removeAll()
        }
    }

    // MARK: - security(1)

    private func readPassword(ssid: String) async -> Result {
        // The canonical lookup documented for AirPort items.
        let primary = ProcessRunner.Command(
            executable: "/usr/bin/security",
            arguments: [
                "find-generic-password",
                "-D", "AirPort network password",
                "-a", ssid,
                "-w"
            ]
        )

        if let outcome = await interpret(await safeRun(primary)) {
            return Result(ssid: ssid, outcome: outcome, checkedAt: Date())
        }

        // Some macOS versions key the item by service name instead of account.
        let fallback = ProcessRunner.Command(
            executable: "/usr/bin/security",
            arguments: [
                "find-generic-password",
                "-D", "AirPort network password",
                "-s", ssid,
                "-w"
            ]
        )
        let fallbackOutcome = await interpret(await safeRun(fallback)) ?? .notFound
        return Result(ssid: ssid, outcome: fallbackOutcome, checkedAt: Date())
    }

    private func safeRun(_ command: ProcessRunner.Command) async -> ProcessRunner.Result? {
        do {
            return try await runner.run(command, timeout: 30)
        } catch {
            return nil
        }
    }

    /// Returns nil when the lookup should be retried with different flags.
    private func interpret(_ result: ProcessRunner.Result?) -> Outcome? {
        guard let result else { return .failed("security(1) could not be started.") }

        if result.exitCode == 0 {
            var password = result.stdout
            if password.hasSuffix("\n") { password.removeLast() }
            if password.hasSuffix("\r") { password.removeLast() }
            guard !password.isEmpty else { return .notFound }
            return .found(password)
        }

        let combined = result.combined.lowercased()
        if result.exitCode == 44 || combined.contains("could not be found") {
            return .notFound
        }
        if combined.contains("user canceled") || combined.contains("user cancelled") {
            return .accessDenied("The keychain prompt was dismissed. Allow access to read the saved password.")
        }
        if combined.contains("keychain") && (combined.contains("locked") || combined.contains("timeout")) {
            return .accessDenied("The login keychain is locked. Unlock it in Keychain Access and try again.")
        }
        if combined.contains("not permitted") || combined.contains("denied") {
            return .accessDenied(result.tail)
        }
        // Exit status 51 is "item not found" on some releases; a fresh exit
        // code without a matching message means the item simply is not there.
        if result.exitCode == 51 { return .notFound }
        return .failed(result.tail.isEmpty ? "security exited with \(result.exitCode)" : result.tail)
    }
}
