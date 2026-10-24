import Foundation
import SwiftUI
import AppKit
import Combine

/// Top-level coordinator: owns the stages, wires the view models together and
/// keeps the toolchain snapshot fresh.
@MainActor
final class AppModel: ObservableObject {
    enum Stage: String, CaseIterable, Identifiable {
        case scan = "Scan"
        case target = "Target"
        case capture = "Capture"
        case crack = "Crack"

        var id: String { rawValue }

        var symbol: String {
            switch self {
            case .scan: return "dot.radiowaves.left.and.right"
            case .target: return "scope"
            case .capture: return "record.circle"
            case .crack: return "key.horizontal"
            }
        }

        var tagline: String {
            switch self {
            case .scan: return "Nearby access points"
            case .target: return "Everything about one network"
            case .capture: return "Record 802.11 frames"
            case .crack: return "Turn hashes into a key"
            }
        }
    }

    @Published var stage: Stage = .scan
    @Published var settings: SettingsStore
    @Published var scan: ScanViewModel
    @Published var target: TargetViewModel
    @Published var capture: CaptureViewModel
    @Published var crack: CrackViewModel
    @Published var queue: QueueViewModel
    @Published var setup: SetupViewModel

    @Published var toolchain: ToolchainReport = .pending
    @Published var showSetup = false
    @Published var showQueue = false
    @Published var error: UserFacingError?
    @Published var statusNote: String?

    let location = LocationAuthorizer()

    private var didStart = false
    private var cancellables: Set<AnyCancellable> = []

    init(settings: SettingsStore = SettingsStore()) {
        let settings = settings
        self.settings = settings
        self.scan = ScanViewModel(settings: settings)
        self.target = TargetViewModel(settings: settings)
        self.capture = CaptureViewModel(settings: settings)
        self.crack = CrackViewModel(settings: settings)
        self.queue = QueueViewModel(settings: settings)
        self.setup = SetupViewModel(settings: settings)

        scan.onSelectionChanged = { [weak self] accessPoint in
            self?.adoptTarget(accessPoint, changeStage: false)
        }
        capture.onSummary = { [weak self] summary in
            guard let self else { return }
            self.crack.adopt(summary: summary, target: self.target.accessPoint)
            self.target.updateHashes(summary.hashes)
            if summary.status.hasResult {
                self.statusNote = "Capture finished with a usable hash. Move to Crack."
            }
        }
        capture.onStats = { [weak self] stats in
            self?.target.updateClients(stats.clients, excludingBSSID: self?.target.accessPoint?.bssid ?? "")
        }
        crack.targetProvider = { [weak self] in self?.target.accessPoint }
        queue.targetsProvider = { [weak self] in self?.scan.filteredNetworks ?? [] }

        // Views observe the individual view models directly, but the sidebar
        // reads across all of them (radio state, capture dot, recovered key),
        // so child changes are re-published through AppModel.
        let children: [ObservableObjectPublisher] = [
            scan.objectWillChange,
            target.objectWillChange,
            capture.objectWillChange,
            crack.objectWillChange,
            queue.objectWillChange,
            setup.objectWillChange,
            location.objectWillChange
        ]
        for publisher in children {
            publisher
                .sink { [weak self] _ in self?.objectWillChange.send() }
                .store(in: &cancellables)
        }
    }

    // MARK: - Lifecycle

    func startup() async {
        guard !didStart else { return }
        didStart = true
        location.commence()
        await checkTools()
        await scanNow()
        if !toolchain.hasRequiredTools {
            showSetup = true
        }
    }

    func checkTools() async {
        toolchain = await ToolLocator.shared.report(refresh: true)
        setup.report = toolchain
    }

    func scanNow() async {
        await scan.scan(includeHidden: settings.showAllNetworks)
        if let message = scan.error {
            statusNote = message
        }
        if location.state == .denied || location.state == .restricted {
            statusNote = LocationAuthorizer.State.denied.explanation
        }
        // Keep the target fresh if the same BSSID is still visible.
        if let current = target.accessPoint,
           let updated = scan.networks.first(where: { $0.bssid == current.bssid }) {
            target.accessPoint = updated
        }
    }

    // MARK: - Target selection

    func adoptTarget(_ accessPoint: AccessPoint?, changeStage: Bool) {
        target.select(accessPoint)
        if let accessPoint {
            settings.rememberTarget(accessPoint)
        }
        if changeStage {
            stage = .target
        }
    }

    func select(networkID: String) {
        guard let accessPoint = scan.networks.first(where: { $0.id == networkID }) else { return }
        adoptTarget(accessPoint, changeStage: false)
    }

    func openTargetDetails() {
        stage = .target
        guard let accessPoint = target.accessPoint else { return }
        Task { await target.probeKeychain() }
        _ = accessPoint
    }

    // MARK: - Actions

    func startCapture() async {
        guard let accessPoint = target.accessPoint else {
            error = UserFacingError(NetCrackError.noTarget)
            stage = .target
            return
        }
        // Capturing only needs tcpdump. The crackers are needed later, so a
        // missing hashcat must not block recording a handshake.
        guard toolchain.hasTcpdump else {
            showSetup = true
            error = UserFacingError(
                message: "tcpdump is missing.",
                detail: "tcpdump normally ships with macOS at /usr/bin/tcpdump. Install it from the Setup pane."
            )
            return
        }
        if !toolchain.hasConverter {
            statusNote = "hcxpcapngtool is missing: the capture will be recorded, but no hashes can be extracted until it is installed."
        }
        stage = .capture
        await capture.start(target: accessPoint, interfaceName: scan.interface.name)
    }

    func stopCapture() async {
        await capture.stop()
    }

    func sendDeauth() async {
        await capture.deauth()
    }

    func runQueue() async {
        await queue.run(
            interfaceName: capture.effectiveInterface(defaultName: scan.interface.name),
            captureMode: capture.mode,
            channel: capture.desiredChannel,
            wordlist: settings.effectiveWordlist
        )
    }

    func shutdown() async {
        await capture.stop()
        await queue.cancel()
        await crack.cancel()
        await Cracker.shared.cancel()
        await SetupManager.shared.cancelInstall()
        await RootExecutor.shared.shutdown()
    }

    var canSeeSSIDs: Bool { location.state.canSeeSSIDs || location.state == .unknown }

    var missingToolBanner: String? {
        guard !toolchain.hasRequiredTools else { return nil }
        return toolchain.summary
    }
}
