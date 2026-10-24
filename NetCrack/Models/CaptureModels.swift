import Foundation

/// How frames are being collected.
enum CaptureMode: String, CaseIterable, Identifiable, Codable, Sendable {
    /// The built-in Mac radio via `tcpdump -I`. Passive only: it cannot
    /// transmit, so no deauthentication and no active WPS.
    case builtin
    /// A monitor-capable USB adapter driven by the aircrack-ng suite, which
    /// can deauth and therefore can force a handshake on demand.
    case external

    var id: String { rawValue }

    var title: String {
        switch self {
        case .builtin: return "Built-in Wi-Fi (passive)"
        case .external: return "External adapter (active)"
        }
    }

    var shortTitle: String {
        switch self {
        case .builtin: return "Built-in"
        case .external: return "External"
        }
    }

    var detail: String {
        switch self {
        case .builtin:
            return "Uses the Mac's own radio in monitor mode with tcpdump. The built-in radio cannot transmit in monitor mode, so this mode only records handshakes that happen naturally."
        case .external:
            return "Uses a monitor-capable USB adapter. Active deauthentication is available, so a handshake can be forced instead of waited for."
        }
    }

    var supportsDeauth: Bool { self == .external }
}

/// What the big status pill on the Capture pane is doing.
enum CaptureStatus: Equatable, Sendable {
    case idle
    case starting
    case capturing
    case handshakeFound
    case pmkidFound
    case noSignal
    case failed(String)

    var title: String {
        switch self {
        case .idle: return "Idle"
        case .starting: return "Starting"
        case .capturing: return "Capturing"
        case .handshakeFound: return "Handshake found"
        case .pmkidFound: return "PMKID found"
        case .noSignal: return "No signal"
        case .failed: return "Failed"
        }
    }

    var isCapturing: Bool {
        switch self {
        case .starting, .capturing, .handshakeFound, .pmkidFound: return true
        case .idle, .noSignal, .failed: return false
        }
    }

    var isRunning: Bool {
        switch self {
        case .starting, .capturing: return true
        default: return false
        }
    }

    var hasResult: Bool {
        switch self {
        case .handshakeFound, .pmkidFound: return true
        default: return false
        }
    }

    var failureMessage: String? {
        if case let .failed(message) = self { return message }
        return nil
    }
}

/// Live counters for the Capture pane.
struct CaptureStats: Equatable, Sendable {
    var frames: Int
    var bytes: UInt64
    var eapolFrames: Int
    var pmkidFrames: Int
    var eapolHashes: Int
    var pmkidHashes: Int
    var beacons: Int
    var dataFrames: Int
    var clients: [WirelessClient]
    var firstFrameAt: Date?
    var lastFrameAt: Date?
    var pcapSize: UInt64
    var channel: Int?

    init(
        frames: Int = 0,
        bytes: UInt64 = 0,
        eapolFrames: Int = 0,
        pmkidFrames: Int = 0,
        eapolHashes: Int = 0,
        pmkidHashes: Int = 0,
        beacons: Int = 0,
        dataFrames: Int = 0,
        clients: [WirelessClient] = [],
        firstFrameAt: Date? = nil,
        lastFrameAt: Date? = nil,
        pcapSize: UInt64 = 0,
        channel: Int? = nil
    ) {
        self.frames = frames
        self.bytes = bytes
        self.eapolFrames = eapolFrames
        self.pmkidFrames = pmkidFrames
        self.eapolHashes = eapolHashes
        self.pmkidHashes = pmkidHashes
        self.beacons = beacons
        self.dataFrames = dataFrames
        self.clients = clients
        self.firstFrameAt = firstFrameAt
        self.lastFrameAt = lastFrameAt
        self.pcapSize = pcapSize
        self.channel = channel
    }

    static let empty = CaptureStats()

    var hasHandshake: Bool { eapolHashes > 0 }

    var hasPMKID: Bool { pmkidHashes > 0 }

    /// True when we are running but nothing at all is arriving. The engine
    /// turns this into the "No signal" state / macOS 26 diagnostic.
    func looksSilent(after seconds: TimeInterval) -> Bool {
        guard seconds >= 8 else { return false }
        if frames == 0 { return true }
        // A trickle of our own beacons is fine; nothing at all is not.
        return bytes < 4_096 && frames == 0
    }

    var summary: String {
        "\(frames) frames · \(eapolFrames) EAPOL · \(pmkidFrames) PMKID · \(Formatters.bytes(bytes))"
    }
}

/// A single `WPA*...` line recovered by hcxpcapngtool.
struct CaptureHash: Identifiable, Hashable, Sendable {
    enum Kind: String, Hashable, Sendable {
        case pmkid = "PMKID"
        case eapol = "EAPOL"
        case unknown = "Hash"

        var sortIndex: Int {
            switch self {
            case .pmkid: return 0
            case .eapol: return 1
            case .unknown: return 2
            }
        }
    }

    var typeCode: String
    var kind: Kind
    var mic: String
    var accessPoint: String
    var client: String
    var ssid: String
    var raw: String

    var id: String { raw }

    var kindLabel: String {
        switch kind {
        case .pmkid: return "PMKID"
        case .eapol: return "EAPOL"
        case .unknown: return "Hash \(typeCode)"
        }
    }

    var displaySSID: String {
        ssid.isEmpty ? "(hidden)" : ssid
    }
}

/// Parser for hcxtools `WPA*` lines. Shared by the capture engine, the
/// converter and the queue pipeline so there is exactly one interpretation.
enum CaptureLineParser {
    /// Field layout of the 22000 line:
    /// `WPA*TYPE*MIC/PMKID*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*...`
    static func parseHashLine(_ line: String) -> CaptureHash? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("WPA*") else { return nil }
        let fields = trimmed.components(separatedBy: "*")
        guard fields.count >= 6 else { return nil }

        let typeCode = fields[1]
        let kind: CaptureHash.Kind
        switch typeCode {
        case "01", "03", "04": kind = .pmkid
        case "02", "05": kind = .eapol
        default: kind = .unknown
        }

        let ssidHex = fields[5]
        return CaptureHash(
            typeCode: typeCode,
            kind: kind,
            mic: fields[2],
            accessPoint: fields[3].uppercased(),
            client: fields[4].uppercased(),
            ssid: decodeHexSSID(ssidHex),
            raw: trimmed
        )
    }

    /// `<essid>` in a 22000 line is hex of the SSID bytes, but tools
    /// occasionally emit the plain string. Accept both.
    static func decodeHexSSID(_ value: String) -> String {
        guard !value.isEmpty else { return "" }
        let hexCharacters = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        let isEvenLength = value.count % 2 == 0
        let isHex = isEvenLength && value.unicodeScalars.allSatisfy { hexCharacters.contains($0) }
        guard isHex else { return value }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return value }
            bytes.append(byte)
            index = next
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// `hcxpcapngtool` writes `EAPOL 0x888e` / `PMKID` notes with verbose
    /// output; `hcxdumptool` writes `EAPOL ...` / `PMKID ...` lines.
    static func classifyFrameNote(_ line: String) -> Kind? {
        let upper = line.uppercased()
        if upper.contains("PMKID") { return .pmkid }
        if upper.contains("EAPOL") || upper.contains("0X888E") { return .eapol }
        return nil
    }

    enum Kind { case pmkid, eapol }
}

/// Snapshot of monitor-mode health, used for the macOS 26 "0 frames"
/// diagnostic.
struct MonitorDiagnostics: Equatable, Sendable {
    enum Verdict: Equatable, Sendable {
        case healthy
        case silent
        case notMonitor
        case wrongChannel(expected: Int, seen: Int)
        case wifiOff
        case unknown(String)
    }

    var verdict: Verdict
    var framesSeen: Int
    var channel: Int?
    var interfaceName: String
    var detail: String

    var title: String {
        switch verdict {
        case .healthy: return "Monitor mode looks healthy"
        case .silent: return "Monitor mode started but no frames arrived"
        case .notMonitor: return "Interface is not in monitor mode"
        case let .wrongChannel(expected, seen): return "Channel mismatch: wanted \(expected), radio is on \(seen)"
        case .wifiOff: return "Wi-Fi is turned off"
        case .unknown: return "Monitor mode state unknown"
        }
    }

    var requiresExternalAdapter: Bool {
        switch verdict {
        case .silent, .wifiOff: return true
        default: return false
        }
    }

    static let idle = MonitorDiagnostics(
        verdict: .healthy,
        framesSeen: 0,
        channel: nil,
        interfaceName: "—",
        detail: "No capture has been started yet."
    )
}
