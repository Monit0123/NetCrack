import Foundation
import Combine

/// Scan stage: owns the list, the search field and refresh state.
@MainActor
final class ScanViewModel: ObservableObject {
    enum SortKey: String, CaseIterable, Identifiable {
        case signal = "Signal"
        case name = "Name"
        case channel = "Channel"
        case band = "Band"
        case security = "Security"

        var id: String { rawValue }
    }

    @Published private(set) var networks: [AccessPoint] = []
    @Published private(set) var interface: InterfaceInfo = .unknown
    @Published private(set) var isScanning = false
    @Published private(set) var lastScan: Date?
    @Published var searchText: String = ""
    @Published var sortKey: SortKey = .signal
    @Published var ascending = false
    @Published var selectedID: String? {
        didSet {
            if selectedID != oldValue {
                let accessPoint = networks.first { $0.id == selectedID }
                onSelectionChanged?(accessPoint)
            }
        }
    }
    @Published var error: String?

    var onSelectionChanged: ((AccessPoint?) -> Void)?

    private let scanner = Scanner.shared
    private let settings: SettingsStore

    init(settings: SettingsStore) {
        self.settings = settings
    }

    func scan(includeHidden: Bool) async {
        guard !isScanning else { return }
        isScanning = true
        error = nil
        let snapshot = await scanner.scan(includeHidden: includeHidden)
        networks = snapshot.accessPoints
        interface = snapshot.interface
        lastScan = snapshot.scannedAt
        error = snapshot.errorMessage
        isScanning = false

        if let selectedID, !networks.contains(where: { $0.id == selectedID }) {
            self.selectedID = nil
        }
    }

    func selectNext() {
        guard !sortedNetworks.isEmpty else { return }
        let currentIndex = sortedNetworks.firstIndex { $0.id == selectedID } ?? -1
        let next = sortedNetworks[(currentIndex + 1) % sortedNetworks.count]
        selectedID = next.id
    }

    func selectPrevious() {
        guard !sortedNetworks.isEmpty else { return }
        let currentIndex = sortedNetworks.firstIndex { $0.id == selectedID } ?? 0
        let previous = sortedNetworks[(currentIndex - 1 + sortedNetworks.count) % sortedNetworks.count]
        selectedID = previous.id
    }

    var sortedNetworks: [AccessPoint] {
        let filtered: [AccessPoint]
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        if query.isEmpty {
            filtered = networks
        } else {
            filtered = networks.filter { accessPoint in
                accessPoint.ssid.lowercased().contains(query)
                    || accessPoint.bssid.lowercased().contains(query)
                    || accessPoint.securityLabel.lowercased().contains(query)
                    || "\(accessPoint.channel)".contains(query)
                    || accessPoint.phy.lowercased().contains(query)
                    || (accessPoint.vendorHint?.lowercased().contains(query) ?? false)
            }
        }

        let sorted = filtered.sorted { lhs, rhs in
            switch sortKey {
            case .signal:
                return ascending ? lhs.rssi < rhs.rssi : lhs.rssi > rhs.rssi
            case .name:
                let result = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                return ascending ? result == .orderedAscending : result == .orderedDescending
            case .channel:
                return ascending ? lhs.channel < rhs.channel : lhs.channel > rhs.channel
            case .band:
                return ascending ? lhs.band.sortIndex < rhs.band.sortIndex : lhs.band.sortIndex > rhs.band.sortIndex
            case .security:
                let result = lhs.security.rawValue.localizedCaseInsensitiveCompare(rhs.security.rawValue)
                return ascending ? result == .orderedAscending : result == .orderedDescending
            }
        }
        return sorted
    }

    var crackableCount: Int {
        networks.filter { $0.security.isCrackable }.count
    }

    var strongest: AccessPoint? {
        networks.max { $0.rssi < $1.rssi }
    }

    func toggleSort(_ key: SortKey) {
        if sortKey == key {
            ascending.toggle()
        } else {
            sortKey = key
            ascending = key == .name
        }
    }

    func sortIndicator(for key: SortKey) -> String? {
        guard sortKey == key else { return nil }
        return ascending ? "chevron.up" : "chevron.down"
    }

    var selectedAccessPoint: AccessPoint? {
        guard let selectedID else { return nil }
        return networks.first { $0.id == selectedID }
    }
}
