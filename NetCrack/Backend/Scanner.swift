import Foundation
import AppKit
import Combine
import CoreWLAN
import CoreLocation

/// Wi-Fi scanning through CoreWLAN.
///
/// Deliberately native: `airport` was removed from macOS 14.4, so shelling out
/// to it is not an option. CoreWLAN needs Location Services authorisation on
/// macOS 14 and later before it will reveal SSIDs at all, which is what
/// `LocationAuthorizer` exists for.
actor Scanner {
    static let shared = Scanner()

    struct Snapshot: Sendable {
        var accessPoints: [AccessPoint]
        var interface: InterfaceInfo
        var scannedAt: Date
        var errorMessage: String?

        static let empty = Snapshot(
            accessPoints: [],
            interface: .unknown,
            scannedAt: Date(),
            errorMessage: nil
        )
    }

    private let runner = ProcessRunner()
    private var lastSnapshot = Snapshot.empty

    func latest() -> Snapshot { lastSnapshot }

    /// Full scan, sorted by signal strength (strongest first).
    func scan(includeHidden: Bool = true) async -> Snapshot {
        let interfaceInfo = await interfaceInfo()

        guard interfaceInfo.isPoweredOn else {
            lastSnapshot = Snapshot(
                accessPoints: [],
                interface: interfaceInfo,
                scannedAt: Date(),
                errorMessage: NetCrackError.wiFiOff.errorDescription
            )
            return lastSnapshot
        }

        let client = CWWiFiClient.shared()
        guard let interface = client.interface() else {
            lastSnapshot = Snapshot(
                accessPoints: [],
                interface: interfaceInfo,
                scannedAt: Date(),
                errorMessage: NetCrackError.noInterface.errorDescription
            )
            return lastSnapshot
        }

        do {
            let networks = try interface.scanForNetworks(withSSID: nil, includeHidden: includeHidden)
            var accessPoints = networks.map { Self.map($0) }
            accessPoints.sort { lhs, rhs in
                if lhs.rssi != rhs.rssi { return lhs.rssi > rhs.rssi }
                return lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
            }
            lastSnapshot = Snapshot(
                accessPoints: accessPoints,
                interface: interfaceInfo,
                scannedAt: Date(),
                errorMessage: accessPoints.isEmpty ? "No networks were returned. Move closer to the router and scan again." : nil
            )
        } catch {
            lastSnapshot = Snapshot(
                accessPoints: [],
                interface: interfaceInfo,
                scannedAt: Date(),
                errorMessage: "The scan failed: \(error.localizedDescription)"
            )
        }
        return lastSnapshot
    }

    /// Current radio state without scanning.
    func interfaceInfo() async -> InterfaceInfo {
        let client = CWWiFiClient.shared()
        guard let interface = client.interface() else {
            return InterfaceInfo(
                name: "en0",
                isPoweredOn: false,
                isMonitorMode: false,
                channel: nil,
                ssid: nil,
                bssid: nil,
                hardwareAddress: nil,
                transmitPower: nil,
                supportsMonitorMode: false,
                note: "CoreWLAN returned no interface."
            )
        }

        let name = interface.interfaceName() ?? "en0"
        let powered = interface.powerOn()
        let channel = interface.channel()
        let ssid = interface.ssid()
        let bssid = interface.bssid()
        let monitor = await monitorState(interfaceName: name)

        return InterfaceInfo(
            name: name,
            isPoweredOn: powered,
            isMonitorMode: monitor.isMonitor ?? false,
            channel: channel?.channelNumber ?? monitor.channel,
            ssid: ssid,
            bssid: bssid,
            hardwareAddress: interface.hardwareAddress(),
            transmitPower: interface.transmitPower(),
            supportsMonitorMode: true,
            note: monitor.note
        )
    }

    /// Best-effort monitor-mode detection. `airport` is gone on macOS 14.4+,
    /// and plain `ifconfig` does not always print the op mode, so "unknown" is
    /// an honest answer rather than a guess.
    func monitorState(interfaceName: String) async -> (isMonitor: Bool?, channel: Int?, note: String?) {
        if let airportPath = Self.airportPath() {
            let result = try? await runner.run(
                ProcessRunner.Command(executable: airportPath, arguments: ["-I"]),
                timeout: 8
            )
            if let result, result.exitCode == 0 {
                var isMonitor: Bool?
                var channelNumber: Int?
                for line in result.stdout.split(separator: "\n") {
                    let text = line.trimmingCharacters(in: .whitespaces)
                    if text.hasPrefix("op mode:") {
                        isMonitor = text.lowercased().contains("monitor")
                    }
                    if text.hasPrefix("channel:") {
                        let value = text.replacingOccurrences(of: "channel:", with: "")
                            .trimmingCharacters(in: .whitespaces)
                        channelNumber = Int(value.split(separator: ",").first?.trimmingCharacters(in: .whitespaces) ?? "")
                    }
                }
                return (
                    isMonitor,
                    channelNumber,
                    isMonitor == true ? "Monitor mode reported by airport(1)." : nil
                )
            }
        }

        let result = try? await runner.run(
            ProcessRunner.Command(executable: "/sbin/ifconfig", arguments: [interfaceName]),
            timeout: 8
        )
        guard let result, result.exitCode == 0 else {
            return (nil, nil, "Could not read interface state.")
        }
        let text = result.stdout.lowercased()
        if text.contains("monitor") {
            return (true, nil, "ifconfig reports a monitor flag.")
        }
        // "status: inactive" while tcpdump holds the radio is common and does
        // not mean the capture is broken; do not claim managed mode from it.
        return (nil, nil, "Monitor mode cannot be confirmed on this macOS version; the capture itself is the test.")
    }

    nonisolated static func airportPath() -> String? {
        ["/usr/bin/airport", "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    // MARK: - CoreWLAN mapping

    nonisolated static func map(_ network: CWNetwork) -> AccessPoint {
        let ssid = network.ssid ?? ""
        let channelNumber = network.wlanChannel?.channelNumber ?? 0
        let band = band(for: network.wlanChannel)
        let security = security(for: network)
        let phy = phyMode(for: network)
        let width = width(for: network.wlanChannel)

        return AccessPoint(
            ssid: ssid,
            bssid: (network.bssid ?? "").lowercased(),
            channel: channelNumber,
            band: band,
            security: security,
            rssi: network.rssiValue,
            noise: network.noiseValue,
            phy: phy,
            widthMHz: width,
            isHidden: ssid.isEmpty,
            isIBSS: network.ibss
        )
    }

    nonisolated static func band(for channel: CWChannel?) -> AccessPoint.Band {
        guard let channel else { return .unknown }
        switch channel.channelBand {
        case .band2GHz: return .ghz2
        case .band5GHz: return .ghz5
        case .band6GHz: return .ghz6
        default: return fallbackBand(channelNumber: channel.channelNumber)
        }
    }

    /// Some drivers report `CWChannelBand.unknown`. Channel numbers overlap
    /// between 5 GHz and 6 GHz, so only unambiguous ranges are mapped.
    nonisolated static func fallbackBand(channelNumber: Int) -> AccessPoint.Band {
        switch channelNumber {
        case 1...14: return .ghz2
        case 36...177: return .ghz5
        case 181...233: return .ghz6
        default: return .unknown
        }
    }

    nonisolated static func width(for channel: CWChannel?) -> Int {
        guard let channel else { return 0 }
        switch channel.channelWidth {
        case .width20MHz: return 20
        case .width40MHz: return 40
        case .width80MHz: return 80
        case .width160MHz: return 160
        default: return 0
        }
    }

    nonisolated static func phyMode(for network: CWNetwork) -> String {
        if network.supportsPHYMode(.mode11ax) { return "802.11ax" }
        if network.supportsPHYMode(.mode11ac) { return "802.11ac" }
        if network.supportsPHYMode(.mode11n) { return "802.11n" }
        if network.supportsPHYMode(.mode11g) { return "802.11g" }
        if network.supportsPHYMode(.mode11a) { return "802.11a" }
        if network.supportsPHYMode(.mode11b) { return "802.11b" }
        return "—"
    }

    /// Classifies the security using only the *base* modes.
    ///
    /// `supportsSecurity(_:)` answers "could a profile saved for this mode
    /// join this AP?", not "does the AP advertise this mode?" — so a plain
    /// WPA2 AP happily answers yes to `.wpa3Transition`. Querying the
    /// transition flags would therefore label every WPA2 network as
    /// WPA2+WPA3. Base modes are reliable, so the transition label is derived
    /// from the combination of WPA3 Personal and WPA2 Personal instead.
    nonisolated static func security(for network: CWNetwork) -> AccessPoint.Security {
        let enhancedOpen = CWSecurity(rawValue: 14) // kCWSecurityOWE
        let hasWPA3Personal = network.supportsSecurity(.wpa3Personal)
        let hasWPA2Personal = network.supportsSecurity(.wpa2Personal)
        let hasWPA1 = network.supportsSecurity(.wpaPersonal)
            || network.supportsSecurity(.wpaPersonalMixed)
        let hasEnterprise = network.supportsSecurity(.wpa3Enterprise)
            || network.supportsSecurity(.wpa2Enterprise)
            || network.supportsSecurity(.enterprise)
            || network.supportsSecurity(.wpaEnterprise)
            || network.supportsSecurity(.wpaEnterpriseMixed)
        let hasWEP = network.supportsSecurity(.WEP) || network.supportsSecurity(.dynamicWEP)
        let hasOWE = enhancedOpen.map { network.supportsSecurity($0) } ?? false

        if hasEnterprise { return .enterprise }
        if hasWPA3Personal && hasWPA2Personal { return .wpa2wpa3 }
        if hasWPA3Personal { return .wpa3 }
        if hasWPA2Personal { return .wpa2 }
        if hasWPA1 { return .wpa }
        if hasWEP { return .wep }
        if hasOWE { return .owe }
        if network.supportsSecurity(.none) { return .open }
        return .unknown
    }
}

/// Location Services gate for SSIDs on macOS 14+.
///
/// Without authorisation CoreWLAN still returns networks but blanks the SSID,
/// which makes the whole app useless, so the request happens at launch and the
/// UI explains what to do when it was declined.
@MainActor
final class LocationAuthorizer: NSObject, ObservableObject {
    enum State: Equatable {
        case unknown
        case authorized
        case denied
        case restricted
        case notDetermined
        case servicesDisabled

        var canSeeSSIDs: Bool {
            self == .authorized
        }

        var explanation: String? {
            switch self {
            case .authorized, .unknown:
                return nil
            case .denied, .restricted:
                return "Location access is off, so macOS hides network names from NetCrack. Open System Settings → Privacy & Security → Location Services and enable NetCrack."
            case .notDetermined:
                return "NetCrack needs Location access to read network names on macOS 14 and later."
            case .servicesDisabled:
                return "Location Services is disabled system-wide, which hides Wi-Fi network names from every app."
            }
        }
    }

    @Published private(set) var state: State = .unknown

    private let manager = CLLocationManager()
    private var didStart = false

    override init() {
        super.init()
        manager.delegate = self
        refresh()
    }

    func commence() {
        guard !didStart else { return }
        didStart = true
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
        refresh()
    }

    func refresh() {
        guard CLLocationManager.locationServicesEnabled() else {
            state = .servicesDisabled
            return
        }
        switch manager.authorizationStatus {
        case .authorized, .authorizedAlways:
            state = .authorized
        case .denied:
            state = .denied
        case .restricted:
            state = .restricted
        case .notDetermined:
            state = .notDetermined
        @unknown default:
            state = .unknown
        }
    }

    func openSettings() {
        let urls = [
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_LocationServices",
            "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
        ]
        for string in urls {
            if let url = URL(string: string), NSWorkspace.shared.open(url) { return }
        }
    }
}

extension LocationAuthorizer: CLLocationManagerDelegate {
    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in
            self.refresh()
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didChangeAuthorization status: CLAuthorizationStatus) {
        Task { @MainActor in
            self.refresh()
        }
    }
}
