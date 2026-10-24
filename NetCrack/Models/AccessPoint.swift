import Foundation

/// A single Wi-Fi access point as reported by CoreWLAN (or by an external
/// adapter's scan). Pure value type so it can cross actor boundaries freely.
struct AccessPoint: Identifiable, Hashable, Sendable {
    enum Band: String, Hashable, Sendable {
        case ghz2 = "2.4 GHz"
        case ghz5 = "5 GHz"
        case ghz6 = "6 GHz"
        case unknown = "Unknown"

        var shortLabel: String {
            switch self {
            case .ghz2: return "2.4"
            case .ghz5: return "5"
            case .ghz6: return "6"
            case .unknown: return "?"
            }
        }

        var sortIndex: Int {
            switch self {
            case .ghz2: return 0
            case .ghz5: return 1
            case .ghz6: return 2
            case .unknown: return 3
            }
        }
    }

    enum Security: String, Hashable, Sendable {
        case open = "Open"
        case wep = "WEP"
        case wpa = "WPA"
        case wpa2 = "WPA2"
        case wpa3 = "WPA3"
        case wpa2wpa3 = "WPA2+WPA3"
        case enterprise = "Enterprise"
        case owe = "Enhanced Open"
        case unknown = "Unknown"

        /// False for open networks (there is nothing to crack) and for
        /// enterprise networks (802.1X credentials, not a PSK).
        var isCrackable: Bool {
            switch self {
            case .wep, .wpa, .wpa2, .wpa3, .wpa2wpa3, .unknown: return true
            case .open, .enterprise, .owe: return false
            }
        }

        var isEnterprise: Bool { self == .enterprise }

        var isOpen: Bool { self == .open || self == .owe }

        /// PMKID comes from an RSN IE, so WPA2/WPA3/transition APs can offer
        /// one. WPA1 (TKIP) and WEP do not, and enterprise APs use a different
        /// key derivation with no PSK at all.
        var supportsPMKID: Bool {
            switch self {
            case .wpa2, .wpa3, .wpa2wpa3, .unknown: return true
            default: return false
            }
        }

        var supportsSAE: Bool { self == .wpa3 || self == .wpa2wpa3 }

        var shortCode: String {
            switch self {
            case .open: return "OPEN"
            case .wep: return "WEP"
            case .wpa: return "WPA"
            case .wpa2: return "WPA2"
            case .wpa3: return "WPA3"
            case .wpa2wpa3: return "WPA2/3"
            case .enterprise: return "802.1X"
            case .owe: return "OWE"
            case .unknown: return "?"
            }
        }
    }

    var ssid: String
    var bssid: String
    var channel: Int
    var band: Band
    var security: Security
    var rssi: Int
    var noise: Int
    var phy: String
    var widthMHz: Int
    var isHidden: Bool
    var isIBSS: Bool

    init(
        ssid: String,
        bssid: String,
        channel: Int,
        band: Band,
        security: Security,
        rssi: Int,
        noise: Int = 0,
        phy: String = "—",
        widthMHz: Int = 0,
        isHidden: Bool = false,
        isIBSS: Bool = false
    ) {
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.band = band
        self.security = security
        self.rssi = rssi
        self.noise = noise
        self.phy = phy
        self.widthMHz = widthMHz
        self.isHidden = isHidden
        self.isIBSS = isIBSS
    }
}

extension AccessPoint {
    var id: String {
        bssid.isEmpty ? "\(ssid)-\(channel)" : bssid.lowercased()
    }

    var displayName: String {
        if !ssid.isEmpty { return ssid }
        return isHidden ? "Hidden network" : "(no SSID)"
    }

    var displayBSSID: String {
        bssid.isEmpty ? "—" : bssid.uppercased()
    }

    /// MAC with separators removed and uppercased, matching the `WPA*` lines
    /// written by hcxpcapngtool.
    var bssidCompact: String {
        bssid.replacingOccurrences(of: ":", with: "").uppercased()
    }

    var normalizedBSSID: String {
        guard !bssid.isEmpty else { return "" }
        return bssid.lowercased()
    }

    var bandLabel: String { band.rawValue }

    var securityLabel: String { security.rawValue }

    var channelLabel: String {
        channel == 0 ? "—" : "\(channel)"
    }

    /// "44 · 5 GHz · 80 MHz"
    var channelSummary: String {
        var parts: [String] = []
        if channel > 0 { parts.append("ch \(channel)") }
        if band != .unknown { parts.append(band.shortLabel + " GHz") }
        if widthMHz > 0 { parts.append("\(widthMHz) MHz") }
        return parts.isEmpty ? "Unknown" : parts.joined(separator: " · ")
    }

    /// 0...4 bars, thresholds tuned to typical macOS RSSI readings.
    var rssiBars: Int {
        switch rssi {
        case _ where rssi >= -55: return 4
        case _ where rssi >= -67: return 3
        case _ where rssi >= -76: return 2
        case _ where rssi >= -86: return 1
        default: return 0
        }
    }

    var rssiQuality: String {
        switch rssiBars {
        case 4: return "Excellent"
        case 3: return "Good"
        case 2: return "Fair"
        case 1: return "Weak"
        default: return "Unusable"
        }
    }

    var snr: Int? {
        guard noise < 0 else { return nil }
        return rssi - noise
    }

    var isOpen: Bool { security.isOpen }

    var isWEP: Bool { security == .wep }

    /// Rough vendor lookup from the OUI. Kept intentionally small: it is a
    /// convenience label, not a database.
    var vendorHint: String? {
        let compact = bssidCompact
        guard compact.count >= 6 else { return nil }
        let prefix = String(compact.prefix(6))
        return AccessPoint.ouiTable[prefix]
    }

    private static let ouiTable: [String: String] = [
        "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google", "9C4FCF": "Google",
        "001B63": "Apple", "001124": "Apple", "3C0754": "Apple", "A45E60": "Apple",
        "F0B479": "Apple", "8C8590": "Apple", "BC926B": "Apple", "D0E140": "Apple",
        "001DD3": "Amazon", "44650D": "Amazon", "747548": "Amazon", "F0272D": "Amazon",
        "0018E7": "Ubiquiti", "002722": "Ubiquiti", "245A4C": "Ubiquiti", "788A20": "Ubiquiti",
        "000C42": "Cisco", "00170F": "Cisco", "2C542D": "Cisco", "58971E": "Cisco",
        "0009B0": "TP-Link", "14CC20": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
        "000C43": "Netgear", "20E52A": "Netgear", "A00460": "Netgear", "C03F0E": "Netgear",
        "001CF0": "D-Link", "1CBDB9": "D-Link", "340804": "D-Link",
        "000E58": "Sonos", "5CAAFD": "Sonos", "949F3E": "Sonos",
        "001DE5": "Cisco/ Linksys", "48F8B3": "Linksys", "C0C1C0": "Linksys",
        "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
        "001CB3": "Apple", "D8BB2C": "Apple", "F0DBE2": "Apple",
        "F4F26D": "Routerboard/MikroTik", "48A98A": "Routerboard/MikroTik",
        "001F3B": "Intel", "5CE0C5": "Intel", "A0A4C5": "Intel",
        "0024D7": "Intel", "E4B318": "Intel",
        "0026BB": "Apple", "68AB1E": "Apple", "7CD1C3": "Apple",
        "FCA13E": "Samsung", "8425DB": "Samsung", "78BDBC": "Samsung",
        "00248C": "ASUS", "08606E": "ASUS", "1C872C": "ASUS", "AC9E17": "ASUS",
        "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox"
    ]
}

/// A station observed while capturing traffic for a target network.
struct WirelessClient: Identifiable, Hashable, Sendable {
    var mac: String
    var frames: Int

    var id: String { mac }

    var compact: String {
        mac.replacingOccurrences(of: ":", with: "").uppercased()
    }
}
