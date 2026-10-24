import Foundation

/// Target stage: details for one AP, the Keychain instant-win probe and the
/// clients observed for it.
@MainActor
final class TargetViewModel: ObservableObject {
    @Published var accessPoint: AccessPoint?
    @Published private(set) var keychain: KeychainProbe.Result?
    @Published private(set) var isProbing = false
    @Published private(set) var clients: [WirelessClient] = []
    @Published private(set) var hashes: [CaptureHash] = []
    @Published private(set) var joinedSSID: String?
    @Published var error: UserFacingError?

    private let probe = KeychainProbe.shared
    private let settings: SettingsStore
    private var probeTask: Task<Void, Never>?

    init(settings: SettingsStore) {
        self.settings = settings
    }

    func select(_ accessPoint: AccessPoint?) {
        guard accessPoint?.id != self.accessPoint?.id else { return }
        self.accessPoint = accessPoint
        keychain = nil
        clients = []
        hashes = []
        error = nil
        probeTask?.cancel()
        probeTask = Task { [weak self] in
            guard let self else { return }
            await self.loadJoinedNetwork()
            await self.probeKeychain()
        }
    }

    func loadJoinedNetwork() async {
        let interface = await Scanner.shared.interfaceInfo()
        joinedSSID = await probe.joinedSSID(interfaceName: interface.name)
    }

    /// The Keychain lookup is the fastest possible win, so it runs as soon as a
    /// target is selected.
    func probeKeychain() async {
        guard let accessPoint, !accessPoint.ssid.isEmpty else {
            keychain = nil
            return
        }
        isProbing = true
        defer { isProbing = false }
        let result = await probe.lookup(ssid: accessPoint.ssid)
        guard !Task.isCancelled else { return }
        keychain = result
        switch result.outcome {
        case .found:
            settings.lastTargetSSID = accessPoint.ssid
        case .notFound:
            break
        case let .accessDenied(reason):
            error = UserFacingError(message: "Keychain access was refused.", detail: reason)
        case let .failed(reason):
            error = UserFacingError(message: "Keychain lookup failed.", detail: reason)
        }
    }

    func recheckKeychain() async {
        if let ssid = accessPoint?.ssid {
            await probe.invalidate(ssid: ssid)
        }
        await probeKeychain()
    }

    func updateClients(_ list: [WirelessClient], excludingBSSID: String) {
        let bssid = excludingBSSID.lowercased()
        clients = list
            .filter { $0.mac.lowercased() != bssid }
            .filter { client in
                // Multicast/broadcast addresses never belong to a station.
                guard let firstByte = client.mac.split(separator: ":").first,
                      let value = UInt8(firstByte, radix: 16) else { return true }
                return value & 0x01 == 0
            }
            .sorted { $0.frames > $1.frames }
    }

    func updateHashes(_ list: [CaptureHash]) {
        guard let accessPoint else {
            hashes = list
            return
        }
        let filtered = Converter.hashes(list, matching: accessPoint)
        hashes = filtered.isEmpty ? list : filtered
    }

    // MARK: - Derived

    var knownPassword: String? {
        keychain?.outcome.password
    }

    var isJoinedNetwork: Bool {
        guard let ssid = accessPoint?.ssid, !ssid.isEmpty else { return false }
        return joinedSSID?.caseInsensitiveCompare(ssid) == .orderedSame
    }

    var keychainStatusTitle: String {
        if isProbing { return "Checking Keychain…" }
        guard let accessPoint else { return "No target selected" }
        if accessPoint.ssid.isEmpty { return "Hidden network" }
        switch keychain?.outcome {
        case .found: return "Already known"
        case .notFound: return "Not in this Mac's Keychain"
        case let .accessDenied(reason): return reason
        case let .failed(reason): return reason
        case nil: return "Not checked yet"
        }
    }

    var keychainStatusDetail: String {
        if knownPassword != nil {
            return isJoinedNetwork
                ? "This Mac is joined to this network, so macOS has the key saved."
                : "macOS saved this network's key the last time it was joined."
        }
        if isProbing { return "Asking the login keychain for “AirPort network password” items." }
        guard let accessPoint else { return "Pick a network on the Scan pane." }
        if accessPoint.ssid.isEmpty {
            return "macOS keys saved networks by SSID; a hidden network has to be revealed before its key can be looked up."
        }
        return "macOS only stores keys for networks it has joined at least once. If this Mac never joined “\(accessPoint.displayName)”, use the capture path instead."
    }

    var crackable: Bool {
        accessPoint?.security.isCrackable ?? false
    }

    var securityExplanation: String {
        guard let accessPoint else { return "" }
        switch accessPoint.security {
        case .open:
            return "Open network: there is no password to recover."
        case .owe:
            return "Enhanced Open (OWE) encrypts traffic without a shared password, so there is no PSK."
        case .enterprise:
            return "802.1X enterprise: users authenticate with credentials against a RADIUS server. Capturing a handshake does not give you a crackable PSK."
        case .wep:
            return "WEP: legacy and broken. Capture a few thousand IVs and aircrack-ng recovers the key."
        case .wpa, .wpa2:
            return "WPA/WPA2-Personal: crackable from an EAPOL handshake or a PMKID."
        case .wpa3:
            return "WPA3-SAE: capture via hcxtools and let hashcat 22000 handle the SAE handshake. A PMKID is usually available without waiting for a client."
        case .wpa2wpa3:
            return "WPA2/WPA3 transition: the WPA2 half still offers a crackable PMKID or EAPOL handshake."
        case .unknown:
            return "Security type could not be classified. Capture and inspect the result."
        }
    }
}
