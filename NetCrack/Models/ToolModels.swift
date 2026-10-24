import Foundation

/// Every external binary NetCrack relies on, with the Homebrew package that
/// provides it and the places we look for it.
enum ExternalTool: String, CaseIterable, Identifiable, Codable, Sendable {
    case brew
    case hashcat
    case hcxpcapngtool
    case aircrack
    case tcpdump
    case wash
    case reaver

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .brew: return "Homebrew"
        case .hashcat: return "hashcat"
        case .hcxpcapngtool: return "hcxpcapngtool (hcxtools)"
        case .aircrack: return "aircrack-ng"
        case .tcpdump: return "tcpdump"
        case .wash: return "wash (WPS scan)"
        case .reaver: return "reaver (WPS PIN)"
        }
    }

    /// Binary name as it appears on disk.
    var executable: String {
        switch self {
        case .brew: return "brew"
        case .hashcat: return "hashcat"
        case .hcxpcapngtool: return "hcxpcapngtool"
        case .aircrack: return "aircrack-ng"
        case .tcpdump: return "tcpdump"
        case .wash: return "wash"
        case .reaver: return "reaver"
        }
    }

    var brewFormula: String {
        switch self {
        case .brew: return "homebrew"
        case .hashcat: return "hashcat"
        case .hcxpcapngtool: return "hcxtools"
        case .aircrack: return "aircrack-ng"
        case .tcpdump: return "tcpdump"
        case .wash: return "aircrack-ng"
        case .reaver: return "reaver"
        }
    }

    var searchDirectories: [String] {
        var dirs = [
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin"
        ]
        dirs.append("\(NSHomeDirectory())/.local/bin")
        return dirs
    }

    /// Absolute path compiled in at build time by the "Installation paths"
    /// build setting. Empty in a plain Xcode build, so the runtime search
    /// is what normally finds the tool.
    var bundledHintPath: String? {
        let hint = Bundle.main.object(forInfoDictionaryKey: "NC\(executable)Path") as? String
        guard let hint, !hint.isEmpty, FileManager.default.isExecutableFile(atPath: hint) else { return nil }
        return hint
    }

    /// Arguments that make the tool print its version and exit.
    var versionArguments: [String] {
        switch self {
        case .tcpdump: return ["--version"]
        case .brew: return ["--version"]
        default: return ["--version"]
        }
    }

    var isRequired: Bool {
        switch self {
        case .brew: return false
        case .hashcat, .hcxpcapngtool, .tcpdump, .aircrack: return true
        case .wash, .reaver: return false
        }
    }

    var purpose: String {
        switch self {
        case .brew: return "Installs the rest of the toolchain."
        case .hashcat: return "Cracks PMKID/PMKID and EAPOL hashes (mode 22000)."
        case .hcxpcapngtool: return "Converts raw pcap frames into hashcat 22000 hashes."
        case .aircrack: return "Alternative cracker and the engine behind capture/deauth."
        case .tcpdump: return "Records 802.11 frames from the built-in radio in monitor mode."
        case .wash: return "Lists WPS-enabled access points on an external adapter."
        case .reaver: return "Runs the WPS PIN exchange against a WPS AP."
        }
    }

    /// aircrack-ng ships no Apple Silicon bottle, so the installer has to
    /// build it, which takes a while.
    var requiresSourceBuildOnAppleSilicon: Bool {
        guard self == .aircrack || self == .wash || self == .reaver else { return false }
        return true
    }

    /// Wash and reaver are not separate formulae in every tap; they live in
    /// the aircrack-ng formula.
    var installFormula: String { brewFormula }

    var installHint: String {
        switch self {
        case .aircrack:
            return "# no Apple Silicon bottle → brew install --build-from-source aircrack-ng (slow, expect 5-15 min)"
        case .wash:
            return "# ships with aircrack-ng"
        case .reaver:
            return "# optional: brew install reaver"
        default:
            return "# brew install \(brewFormula)"
        }
    }
}

/// Result of probing one tool.
struct ToolStatus: Identifiable, Equatable, Sendable {
    var tool: ExternalTool
    var path: String?
    var version: String?
    var failure: String?

    var id: ExternalTool { tool }

    var isAvailable: Bool { path != nil }

    var versionLabel: String {
        version ?? (isAvailable ? "installed" : "not found")
    }

    var shortVersion: String {
        guard let version else { return versionLabel }
        // "hashcat v6.2.6" -> "v6.2.6", "tcpdump version 4.99.4" -> "4.99.4"
        let tokens = version.split(separator: " ").map(String.init)
        if let token = tokens.first(where: { $0.first == "v" && $0.count > 1 }) { return token }
        if let token = tokens.first(where: { $0.first?.isNumber == true }) { return token }
        return version
    }
}

/// Whole-toolchain snapshot.
struct ToolchainReport: Equatable, Sendable {
    var statuses: [ExternalTool: ToolStatus]
    var checkedAt: Date
    var isChecking: Bool

    init(statuses: [ExternalTool: ToolStatus] = [:], checkedAt: Date = Date(), isChecking: Bool = false) {
        self.statuses = statuses
        self.checkedAt = checkedAt
        self.isChecking = isChecking
    }

    static let pending = ToolchainReport(isChecking: true)

    var missing: [ExternalTool] {
        ExternalTool.allCases.filter { tool in
            guard tool.isRequired else { return false }
            return statuses[tool]?.isAvailable != true
        }
    }

    var optionalMissing: [ExternalTool] {
        ExternalTool.allCases.filter { tool in
            guard !tool.isRequired else { return false }
            guard tool != .brew else { return false }
            return statuses[tool]?.isAvailable != true
        }
    }

    var hasRequiredTools: Bool { missing.isEmpty }

    var hasBrew: Bool { statuses[.brew]?.isAvailable == true }

    var hasHashcat: Bool { statuses[.hashcat]?.isAvailable == true }

    var hasConverter: Bool { statuses[.hcxpcapngtool]?.isAvailable == true }

    var hasAircrack: Bool { statuses[.aircrack]?.isAvailable == true }

    var hasTcpdump: Bool { statuses[.tcpdump]?.isAvailable == true }

    func path(for tool: ExternalTool) -> String? {
        statuses[tool]?.path
    }

    var summary: String {
        if isChecking { return "Checking tools…" }
        if missing.isEmpty {
            let optional = optionalMissing.count
            return optional == 0
                ? "All tools ready"
                : "Required tools ready · \(optional) optional missing"
        }
        return "Missing: " + missing.map(\.executable).joined(separator: ", ")
    }
}

/// Network interface facts, used by the capture engine and the UI banner.
struct InterfaceInfo: Equatable, Sendable {
    var name: String
    var isPoweredOn: Bool
    var isMonitorMode: Bool
    var channel: Int?
    var ssid: String?
    var bssid: String?
    var hardwareAddress: String?
    var transmitPower: Int?
    var supportsMonitorMode: Bool
    var note: String?

    static let unknown = InterfaceInfo(
        name: "en0",
        isPoweredOn: false,
        isMonitorMode: false,
        channel: nil,
        ssid: nil,
        bssid: nil,
        hardwareAddress: nil,
        transmitPower: nil,
        supportsMonitorMode: false,
        note: nil
    )

    var statusLine: String {
        var parts: [String] = [name]
        parts.append(isPoweredOn ? "on" : "off")
        if isMonitorMode { parts.append("monitor") }
        if let channel { parts.append("ch \(channel)") }
        if let ssid, !ssid.isEmpty { parts.append(ssid) }
        return parts.joined(separator: " · ")
    }
}

/// A monitor-capable USB adapter (or the built-in radio) as seen by the app.
struct WirelessInterface: Identifiable, Hashable, Sendable {
    var name: String
    var description: String
    var isBuiltin: Bool
    var supportsMonitorMode: Bool

    var id: String { name }

    var canDeauth: Bool { !isBuiltin }
}
