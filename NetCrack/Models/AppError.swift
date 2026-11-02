import Foundation

/// Every failure the app knows how to explain. The raw tool output is kept
/// in `diagnostic` so the log can show it, while `errorDescription` is what
/// a person needs to read.
enum NetCrackError: LocalizedError, Equatable, Sendable {
    case wiFiOff
    case noInterface
    case notInMonitorMode(interface: String)
    case monitorModeUnsupported(interface: String)
    case monitorModeSilent(frames: Int)
    case channelMismatch(expected: Int, actual: Int?, interface: String)
    case zeroFramesCaptured
    case adapterBusy(interface: String)
    case screenLocked
    case toolMissing(ExternalTool)
    case wordlistMissing(String)
    case wordlistEmpty(String)
    case hashFileMissing(String)
    case noHashesYet
    case hashcatFailed(code: Int32, output: String)
    case converterFailed(code: Int32, output: String)
    case authorizationDenied
    case authorizationFailed(String)
    case brewInstallFailed(code: Int32)
    case processLaunchFailed(String)
    case cancelled
    case unsupportedSecurity(String)
    case noTarget
    case keyNotInKeychain(String)
    case wpsRequiresExternalAdapter
    case wpsLocked(String)
    case deauthUnsupportedBuiltin
    case malformedHashLine(String)
    case other(String)

    var errorDescription: String? {
        switch self {
        case .wiFiOff:
            return "Wi-Fi is turned off. Turn it on in the menu bar and try again."
        case .noInterface:
            return "No Wi-Fi interface was found on this Mac."
        case let .notInMonitorMode(interface):
            return "\(interface) is not in monitor mode. The capture cannot see 802.11 management frames until monitor mode is active."
        case let .monitorModeUnsupported(interface):
            return "\(interface) does not support monitor mode on this Mac."
        case let .monitorModeSilent(frames):
            return "Monitor mode reported success but only \(frames) frame(s) arrived. This is a known macOS 26 problem on some Apple Silicon Macs. Plug in an external adapter to capture reliably."
        case let .channelMismatch(expected, actual, interface):
            let actualLabel = actual.map { "\($0)" } ?? "unknown"
            return "\(interface) is on channel \(actualLabel) but the target AP is on channel \(expected). The adapter has to listen on the AP's channel, otherwise no handshake frames are recorded."
        case .zeroFramesCaptured:
            return "Zero frames were captured. Usually that means monitor mode is not really active, the adapter is on the wrong channel, or the target is out of range."
        case let .adapterBusy(interface):
            return "\(interface) is busy: another program (or a previous capture) still holds it. Stop the other capture and try again."
        case .screenLocked:
            return "The screen is locked, so macOS paused the capture session. Unlock the Mac and start the capture again."
        case let .toolMissing(tool):
            return "\(tool.displayName) is not installed. Open the Setup pane to install it with Homebrew."
        case let .wordlistMissing(path):
            return "The wordlist could not be read: \(path). Pick another file or restore the path."
        case let .wordlistEmpty(path):
            return "The wordlist \(path) contains no usable lines."
        case let .hashFileMissing(path):
            return "The hash file is gone: \(path). Capture again, or re-convert the pcap."
        case .noHashesYet:
            return "No handshake yet — keep capturing. hcxpcapngtool found no EAPOL or PMKID frames that belong to this network."
        case let .hashcatFailed(code, output):
            let tail = output.split(separator: "\n").suffix(3).joined(separator: " ")
            return "hashcat exited with code \(code). \(tail.isEmpty ? "See the log for details." : tail)"
        case let .converterFailed(code, output):
            let tail = output.split(separator: "\n").suffix(3).joined(separator: " ")
            return "hcxpcapngtool exited with code \(code). \(tail.isEmpty ? "See the log for details." : tail)"
        case .authorizationDenied:
            return "Administrator authorisation was declined. Capturing needs root; nothing was changed."
        case let .authorizationFailed(message):
            return "Could not obtain administrator rights: \(message)"
        case let .brewInstallFailed(code):
            return "The Homebrew install exited with code \(code). Check the log above for the failing formula."
        case let .processLaunchFailed(message):
            return "A helper process could not be started: \(message)"
        case .cancelled:
            return "Stopped."
        case let .unsupportedSecurity(security):
            return "This network uses \(security). There is no PSK to recover — 802.1X needs credentials, and open/OWE networks have no key."
        case .noTarget:
            return "Select a network on the Target pane first."
        case let .keyNotInKeychain(ssid):
            return "No saved password for \(ssid) in your Keychain. Join the network once (macOS only saves keys for networks it has joined) or capture a handshake instead."
        case .wpsRequiresExternalAdapter:
            return "WPS attacks need an external monitor-capable adapter. The built-in radio cannot transmit frames."
        case let .wpsLocked(bssid):
            return "The access point \(bssid) has WPS locked after too many failed PIN attempts. Wait a few minutes, or use the PMKID path instead."
        case .deauthUnsupportedBuiltin:
            return "The built-in Mac radio cannot inject frames, so it cannot deauthenticate a client. Attach an external adapter to force a handshake."
        case let .malformedHashLine(line):
            return "The hash line could not be parsed: \(line.prefix(80))"
        case let .other(message):
            return message
        }
    }

    var recoverySuggestion: String? {
        switch self {
        case .wiFiOff:
            return "Click the Wi-Fi menu bar icon and turn Wi-Fi on."
        case .notInMonitorMode, .monitorModeUnsupported:
            return "NetCrack runs `sudo tcpdump -I` for you; if that fails, try an external adapter."
        case .monitorModeSilent:
            return "Confirm the diagnosis on the Capture pane, then continue on an external adapter (see the README shopping list)."
        case .channelMismatch:
            return "Pin the adapter's channel in the Capture pane, or lock the AP to a single channel."
        case .zeroFramesCaptured:
            return "Move closer to the AP, pick the exact channel, and wait for a client to connect."
        case .adapterBusy:
            return "Run `sudo lsof | grep -i 802` to see what is holding the interface."
        case .toolMissing, .brewInstallFailed:
            return "Open Setup and run the one-click installer."
        case .wordlistMissing, .wordlistEmpty:
            return "The bundled top-10k list is always available from the Crack pane."
        case .noHashesYet:
            return "Wait for a client to connect, or force one with deauth on an external adapter."
        case .keyNotInKeychain:
            return "Join the network from System Settings → Wi-Fi so macOS stores the key."
        case .wpsLocked:
            return "Reaver can resume with `--no-nacks` later; PMKID capture is usually faster."
        case .deauthUnsupportedBuiltin:
            return "Use Target → Capture mode → External adapter."
        case .screenLocked:
            return "Capture stops when the Mac sleeps or locks; keep the display awake during a capture."
        default:
            return nil
        }
    }

    var isCancellation: Bool {
        self == .cancelled
    }

    /// Equality ignores human text in `.other`, which is intentional below.
    static func == (lhs: NetCrackError, rhs: NetCrackError) -> Bool {
        switch (lhs, rhs) {
        case (.wiFiOff, .wiFiOff), (.noInterface, .noInterface),
             (.zeroFramesCaptured, .zeroFramesCaptured), (.screenLocked, .screenLocked),
             (.noHashesYet, .noHashesYet), (.authorizationDenied, .authorizationDenied),
             (.cancelled, .cancelled), (.noTarget, .noTarget),
             (.wpsRequiresExternalAdapter, .wpsRequiresExternalAdapter),
             (.deauthUnsupportedBuiltin, .deauthUnsupportedBuiltin):
            return true
        case let (.notInMonitorMode(a), .notInMonitorMode(b)):
            return a == b
        case let (.monitorModeUnsupported(a), .monitorModeUnsupported(b)):
            return a == b
        case let (.monitorModeSilent(a), .monitorModeSilent(b)):
            return a == b
        case let (.channelMismatch(e1, a1, i1), .channelMismatch(e2, a2, i2)):
            return e1 == e2 && a1 == a2 && i1 == i2
        case let (.adapterBusy(a), .adapterBusy(b)):
            return a == b
        case let (.toolMissing(a), .toolMissing(b)):
            return a == b
        case let (.wordlistMissing(a), .wordlistMissing(b)):
            return a == b
        case let (.wordlistEmpty(a), .wordlistEmpty(b)):
            return a == b
        case let (.hashFileMissing(a), .hashFileMissing(b)):
            return a == b
        case let (.hashcatFailed(c1, o1), .hashcatFailed(c2, o2)):
            return c1 == c2 && o1 == o2
        case let (.converterFailed(c1, o1), .converterFailed(c2, o2)):
            return c1 == c2 && o1 == o2
        case let (.authorizationFailed(a), .authorizationFailed(b)):
            return a == b
        case let (.brewInstallFailed(a), .brewInstallFailed(b)):
            return a == b
        case let (.processLaunchFailed(a), .processLaunchFailed(b)):
            return a == b
        case let (.unsupportedSecurity(a), .unsupportedSecurity(b)):
            return a == b
        case let (.keyNotInKeychain(a), .keyNotInKeychain(b)):
            return a == b
        case let (.wpsLocked(a), .wpsLocked(b)):
            return a == b
        case let (.malformedHashLine(a), .malformedHashLine(b)):
            return a == b
        case let (.other(a), .other(b)):
            return a == b
        default:
            return false
        }
    }
}

/// Small wrapper so view models can surface an error without losing the
/// underlying value type.
struct UserFacingError: Identifiable, Equatable, Sendable {
    let id = UUID()
    let message: String
    let detail: String?

    init(_ error: Error) {
        if let netCrack = error as? NetCrackError {
            self.message = netCrack.errorDescription ?? netCrack.localizedDescription
            self.detail = netCrack.recoverySuggestion
        } else {
            self.message = error.localizedDescription
            self.detail = nil
        }
    }

    init(message: String, detail: String? = nil) {
        self.message = message
        self.detail = detail
    }
}
