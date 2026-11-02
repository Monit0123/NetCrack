import Foundation

/// The four attack shapes the Crack pane exposes. `hashcat` covers three of
/// them directly; `incremental` is hashcat mask mode with a growing mask,
/// which is what people usually mean by "incremental" for WPA.
enum AttackMode: String, CaseIterable, Identifiable, Codable, Sendable {
    case dictionary
    case dictionaryRules
    case mask
    case incremental

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dictionary: return "Dictionary"
        case .dictionaryRules: return "Dictionary + rules"
        case .mask: return "Mask"
        case .incremental: return "Incremental"
        }
    }

    var subtitle: String {
        switch self {
        case .dictionary: return "-a 0 · one wordlist, no mangling"
        case .dictionaryRules: return "-a 0 -r best64.rule · wordlist with expansion"
        case .mask: return "-a 3 · fixed character positions, e.g. ?d?d?d?d?d?d?d?d"
        case .incremental: return "-a 3 · growing masks, 8-hex first (default WPA keys)"
        }
    }

    var symbol: String {
        switch self {
        case .dictionary: return "text.book.closed"
        case .dictionaryRules: return "wand.and.stars"
        case .mask: return "square.grid.3x3"
        case .incremental: return "arrow.triangle.2.circlepath"
        }
    }

    var needsWordlist: Bool {
        switch self {
        case .dictionary, .dictionaryRules: return true
        case .mask, .incremental: return false
        }
    }

    var needsRules: Bool { self == .dictionaryRules }

    /// Shortest mask length worth trying for each mode, used to explain the
    /// candidate-space estimate in the UI.
    var defaultMaskPlaceholder: String {
        switch self {
        case .mask: return "?d?d?d?d?d?d?d?d"
        case .incremental: return "?d?d?d?d?d?d?d?d"
        default: return ""
        }
    }
}

/// A single cracking job handed to `Cracker`.
struct CrackRequest: Sendable, Equatable {
    var hashFile: URL
    var mode: AttackMode
    var wordlist: URL?
    /// Raw rule file path/name. `best64` is resolved against the hashcat
    /// install directory when it is not a path.
    var ruleFile: String?
    /// Mask for `.mask`; a starting mask for `.incremental`.
    var mask: String
    var incrementalIncrement: Bool
    var ssid: String

    init(
        hashFile: URL,
        mode: AttackMode,
        wordlist: URL? = nil,
        ruleFile: String? = nil,
        mask: String = "",
        incrementalIncrement: Bool = true,
        ssid: String = ""
    ) {
        self.hashFile = hashFile
        self.mode = mode
        self.wordlist = wordlist
        self.ruleFile = ruleFile
        self.mask = mask
        self.incrementalIncrement = incrementalIncrement
        self.ssid = ssid
    }
}

/// Parsed hashcat status. Percent is `nil` while hashcat cannot know it
/// (mask mode reports progress against a keyspace it computes lazily, and
/// the very first status line arrives before that).
struct HashcatStatus: Equatable, Sendable {
    var speedPerSecond: Double
    var progressPercent: Double?
    var recovered: Int
    var rejected: Int
    var totalHashes: Int?
    var etaSeconds: Double?
    var elapsedSeconds: Double?
    var deviceName: String?
    var kernelTime: Int?
    var updatedAt: Date

    init(
        speedPerSecond: Double = 0,
        progressPercent: Double? = nil,
        recovered: Int = 0,
        rejected: Int = 0,
        totalHashes: Int? = nil,
        etaSeconds: Double? = nil,
        elapsedSeconds: Double? = nil,
        deviceName: String? = nil,
        kernelTime: Int? = nil,
        updatedAt: Date = Date()
    ) {
        self.speedPerSecond = speedPerSecond
        self.progressPercent = progressPercent
        self.recovered = recovered
        self.rejected = rejected
        self.totalHashes = totalHashes
        self.etaSeconds = etaSeconds
        self.elapsedSeconds = elapsedSeconds
        self.deviceName = deviceName
        self.kernelTime = kernelTime
        self.updatedAt = updatedAt
    }

    static let zero = HashcatStatus()

    var speedLabel: String { Formatters.speed(speedPerSecond) }

    var progressLabel: String { Formatters.percent(progressPercent) }

    var etaLabel: String { Formatters.eta(etaSeconds) }
}

/// Incremental parser for the two shapes hashcat writes to stdout while it
/// runs. Keeping the state here (rather than in the parser's caller) makes it
/// trivial to unit test the exact byte sequences seen in the wild.
///
/// 1. `--machine-readable` CSV rows, one field per line:
///    `STATUS\t5`, `SPEED\t12345`, `PROGRESS\t42/1000`, `ETA\t00:00:12`, ...
/// 2. Human status blocks (`Speed.#1.........: 1234.5 kH/s`, `Progress.........: ...`).
struct HashcatStatusAccumulator: Sendable {
    private var pendingSpeed: Double?
    private var pendingProgress: Double?
    private var pendingETA: Double?
    private var pendingRecovered: Int?
    private var pendingRejected: Int?
    private var pendingTotal: Int?
    private var pendingElapsed: Double?
    private var pendingDevice: String?
    private var pendingKernel: Int?
    private var lastStatus: HashcatStatus = .zero

    /// Feeds one line and returns a status when it finished a report.
    mutating func consume(_ line: String) -> HashcatStatus? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let csv = machineReadableDelta(trimmed) {
            return csv
        }

        if let human = humanReadableDelta(trimmed) {
            return human
        }

        if let statusLine = classicStatusLine(trimmed) {
            return statusLine
        }

        return nil
    }

    /// STATUS arrives last in a machine-readable block; values line up with
    /// the classic status fields but are emitted one per line.
    private mutating func machineReadableDelta(_ line: String) -> HashcatStatus? {
        // Real output is "STATUS<TAB><TAB>5", so the value is the last field,
        // not the second one.
        let parts = line.components(separatedBy: "\t")
        let key = parts.first?.uppercased() ?? ""
        let value = parts.dropFirst().last ?? ""

        switch key {
        case "SPEED":
            pendingSpeed = Double(value)
        case "PROGRESS":
            let pair = value.components(separatedBy: "/")
            if let done = Double(pair.first ?? ""), let total = Double(pair.last ?? ""), total > 0 {
                pendingProgress = min(100, max(0, done / total * 100))
                pendingTotal = Int(total)
            }
        case "ETA":
            // Machine readable ETA is seconds, classic is HH:MM:SS.
            if let seconds = Double(value) {
                pendingETA = seconds
            } else {
                pendingETA = Formatters.parseClockDuration(value)
            }
        case "RECOVERED":
            pendingRecovered = Int(value)
        case "REJECTED":
            pendingRejected = Int(value)
        case "TIME":
            pendingElapsed = Double(value)
        case "DEVICE":
            pendingDevice = value
        case "KERNEL":
            pendingKernel = Int(value)
        case "STATUS":
            // 5 = exhausted, 6 = cracked: the block is complete either way.
            let status = finish()
            resetPending()
            return status
        case "HASH.TARGET":
            break
        default:
            return nil
        }
        return nil
    }

    private mutating func humanReadableDelta(_ line: String) -> HashcatStatus? {
        let lower = line.lowercased()
        let digits = line.components(separatedBy: ":").dropFirst().joined(separator: ":")

        if lower.hasPrefix("speed") {
            pendingSpeed = Formatters.parseSpeed(digits)
        } else if lower.hasPrefix("progress") {
            let pair = digits.trimmingCharacters(in: .whitespaces).components(separatedBy: "/")
            if let done = Double(pair.first?.trimmingCharacters(in: .whitespaces) ?? ""),
               let total = Double(pair.last?.trimmingCharacters(in: .whitespaces) ?? ""),
               total > 0 {
                pendingProgress = min(100, max(0, done / total * 100))
                pendingTotal = Int(total)
            }
        } else if lower.hasPrefix("recovered") {
            let pair = digits.trimmingCharacters(in: .whitespaces).components(separatedBy: "/")
            pendingRecovered = Int(pair.first?.trimmingCharacters(in: .whitespaces) ?? "")
            pendingRejected = Int(pair.last?.trimmingCharacters(in: .whitespaces) ?? "")
        } else if lower.hasPrefix("rejected") {
            pendingRejected = Int(digits.trimmingCharacters(in: .whitespaces))
        } else if lower.hasPrefix("time started") || lower.hasPrefix("time.") {
            return nil
        } else if lower.hasPrefix("eta") {
            pendingETA = Formatters.parseClockDuration(digits.trimmingCharacters(in: .whitespaces))
        } else if lower.hasPrefix("elapsed") || lower.hasPrefix("runtime") {
            pendingElapsed = Formatters.parseClockDuration(digits.trimmingCharacters(in: .whitespaces))
        } else if lower.hasPrefix("guesses") || lower.hasPrefix("guesses.pt") {
            return nil
        } else if lower.hasPrefix("status") {
            // Ends a human-readable block, same as the classic status line.
            let status = finish()
            resetPending()
            return status
        } else {
            return nil
        }
        return nil
    }

    /// Classic `hashcat -w 3` status block ends with `Status...........: Running`
    /// or `Exhausted` / `Cracked`. Emitting on that boundary keeps consumers
    /// from redrawing once per field.
    private mutating func classicStatusLine(_ line: String) -> HashcatStatus? {
        guard line.lowercased().hasPrefix("status") else { return nil }
        let status = finish()
        resetPending()
        return status
    }

    private mutating func finish() -> HashcatStatus {
        var status = lastStatus
        if let speed = pendingSpeed { status.speedPerSecond = speed }
        if let progress = pendingProgress { status.progressPercent = progress }
        if let recovered = pendingRecovered { status.recovered = recovered }
        if let rejected = pendingRejected { status.rejected = rejected }
        if let total = pendingTotal { status.totalHashes = total }
        if let eta = pendingETA { status.etaSeconds = eta }
        if let elapsed = pendingElapsed { status.elapsedSeconds = elapsed }
        if let device = pendingDevice { status.deviceName = device }
        if let kernel = pendingKernel { status.kernelTime = kernel }
        status.updatedAt = Date()
        lastStatus = status
        return status
    }

    private mutating func resetPending() {
        pendingSpeed = nil
        pendingProgress = nil
        pendingETA = nil
        pendingRecovered = nil
        pendingRejected = nil
        pendingTotal = nil
        pendingElapsed = nil
        pendingDevice = nil
        pendingKernel = nil
    }
}

/// Live view of a running crack, surfaced to the UI.
struct CrackProgress: Equatable, Sendable {
    var status: HashcatStatus
    var startedAt: Date
    var engine: CrackEngineKind
    var hashCount: Int

    var elapsed: TimeInterval { Date().timeIntervalSince(startedAt) }
}

enum CrackEngineKind: String, CaseIterable, Identifiable, Codable, Sendable {
    case hashcat
    case aircrack

    var id: String { rawValue }

    var title: String {
        switch self {
        case .hashcat: return "hashcat"
        case .aircrack: return "aircrack-ng"
        }
    }

    var detail: String {
        switch self {
        case .hashcat:
            return "GPU/CPU optimised, reads the 22000 format. Recommended."
        case .aircrack:
            return "Airport-compatible CPU engine. Dictionary only, one SSID at a time."
        }
    }

    /// aircrack-ng cannot use rules or masks here, only a wordlist.
    func supports(_ mode: AttackMode) -> Bool {
        switch self {
        case .hashcat: return true
        case .aircrack: return mode == .dictionary || mode == .dictionaryRules
        }
    }
}

/// Final outcome of one cracking job.
struct CrackOutcome: Equatable, Sendable {
    var key: String
    var hashFile: URL
    var ssid: String
    var engine: CrackEngineKind
    var mode: AttackMode
    var duration: TimeInterval
    var triedCandidates: Double?
    var deviceName: String?
}

/// Final outcome of a whole pipeline (queue mode or the single-target
/// "run everything" button).
struct PipelineResult: Identifiable, Hashable, Sendable {
    enum Status: String, Hashable, Sendable {
        case recovered = "Recovered"
        case keychain = "From Keychain"
        case exhausted = "Not found"
        case noHandshake = "No handshake"
        case skipped = "Skipped"
        case failed = "Failed"
        case cancelled = "Cancelled"

        var symbol: String {
            switch self {
            case .recovered: return "checkmark.seal.fill"
            case .keychain: return "key.fill"
            case .exhausted: return "xmark.circle"
            case .noHandshake: return "antenna.radiowaves.left.and.right.slash"
            case .skipped: return "forward.end"
            case .failed: return "exclamationmark.triangle.fill"
            case .cancelled: return "stop.circle"
            }
        }
    }

    var id: UUID
    var ssid: String
    var bssid: String
    var status: Status
    var key: String?
    var detail: String
    var duration: TimeInterval
    var hashesFound: Int

    init(
        id: UUID = UUID(),
        ssid: String,
        bssid: String,
        status: Status,
        key: String? = nil,
        detail: String = "",
        duration: TimeInterval = 0,
        hashesFound: Int = 0
    ) {
        self.id = id
        self.ssid = ssid
        self.bssid = bssid
        self.status = status
        self.key = key
        self.detail = detail
        self.duration = duration
        self.hashesFound = hashesFound
    }
}

/// WPS state discovered by `wash`.
struct WPSTarget: Identifiable, Hashable, Sendable {
    var bssid: String
    var channel: Int
    var rssi: Int
    var wpsVersion: String
    var wpsLocked: Bool
    var wpsState: String

    var id: String { bssid }

    var isLocked: Bool { wpsLocked }

    var summary: String {
        "ch \(channel) · \(wpsVersion) · \(wpsLocked ? "locked" : "unlocked") · \(wpsState)"
    }
}
