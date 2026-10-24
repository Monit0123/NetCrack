import SwiftUI
import AppKit

/// Capture stage: mode, counters, status pill and the live tcpdump log.
struct CaptureView: View {
    @ObservedObject var viewModel: CaptureViewModel
    @ObservedObject var app: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            controls
            metrics
            pcapPathRow

            if let banner = diagnosticBanner {
                banner
            }

            honestyNotice

            if viewModel.hasUsableHash {
                hashStrip
            }

            if viewModel.wpsRunning || viewModel.wpsKey != nil || viewModel.wpsMessage != nil {
                wpsCard
            }

            LogConsole(
                lines: viewModel.logs,
                title: "Capture log",
                emptyText: "Start a capture to see tcpdump output here.",
                onClear: { viewModel.clearLogs() },
                onCopy: { viewModel.copyLog() }
            )
            .frame(maxHeight: .infinity)
        }
        .panePadding()
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header

    private var header: some View {
        PaneHeader(
            title: "Capture",
            subtitle: targetSubtitle,
            systemImage: AppModel.Stage.capture.symbol
        ) {
            HStack(spacing: 12) {
                StatusPill(status: viewModel.status)
                VStack(alignment: .trailing, spacing: 1) {
                    Text(Formatters.clock(viewModel.elapsed))
                        .font(.system(size: 15, weight: .semibold, design: .monospaced))
                    Text(viewModel.statusDetail)
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(maxWidth: 300, alignment: .trailing)
                }

                if viewModel.isRunning {
                    Button {
                        Task { await viewModel.stop() }
                    } label: {
                        Label("Stop", systemImage: "stop.fill")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.danger))
                    .keyboardShortcut(".", modifiers: .command)
                } else {
                    Button {
                        Task { await app.startCapture() }
                    } label: {
                        Label("Start capture", systemImage: "record.circle")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.accent))
                    .disabled(app.target.accessPoint == nil)
                    .keyboardShortcut(.return, modifiers: .command)
                }
            }
        }
    }

    private var targetSubtitle: String {
        guard let target = app.target.accessPoint else {
            return "No target selected — pick a network on the Scan pane first."
        }
        return "\(target.displayName) · ch \(target.channelLabel) · \(target.securityLabel) · \(viewModel.mode.shortTitle.lowercased()) mode"
    }

    // MARK: - Controls

    private var controls: some View {
        Card(title: "Configuration", systemImage: "slider.horizontal.3", tint: Theme.accent, padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 18) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("CAPTURE MODE")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.9)
                            .foregroundStyle(.tertiary)
                        Picker("", selection: $viewModel.mode) {
                            ForEach(CaptureMode.allCases) { mode in
                                Text(mode.shortTitle).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 190)
                        .disabled(viewModel.isRunning)
                    }

                    VStack(alignment: .leading, spacing: 5) {
                        Text("CHANNEL")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.9)
                            .foregroundStyle(.tertiary)
                        HStack(spacing: 6) {
                            TextField("auto", value: $viewModel.desiredChannel, format: .number)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 64)
                                .disabled(viewModel.isRunning)
                            Toggle("Lock", isOn: $viewModel.lockChannel)
                                .toggleStyle(.checkbox)
                                .disabled(viewModel.isRunning || viewModel.desiredChannel == 0)
                                .help("Try airport(1) channel locking. Removed in macOS 14.4, so this may be unavailable.")
                        }
                    }

                    if viewModel.mode == .external {
                        VStack(alignment: .leading, spacing: 5) {
                            Text("EXTERNAL INTERFACE")
                                .font(.system(size: 9, weight: .bold))
                                .kerning(0.9)
                                .foregroundStyle(.tertiary)
                            TextField("en5", text: $viewModel.externalInterface)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 92)
                                .disabled(viewModel.isRunning)
                                .help("Interface name of the USB adapter, e.g. en5. Check with `networksetup -listallhardwareports`.")
                        }
                    }

                    VStack(alignment: .leading, spacing: 5) {
                        Text("OPTIONS")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.9)
                            .foregroundStyle(.tertiary)
                        Toggle("Keep display awake", isOn: $viewModel.keepAwake)
                            .toggleStyle(.checkbox)
                            .help("Holds an IOPM assertion while capturing so the radio is not suspended.")
                    }

                    Spacer(minLength: 0)
                }

                HStack(spacing: 10) {
                    Button {
                        Task { await viewModel.deauth() }
                    } label: {
                        Label("Deauth client", systemImage: "bolt.horizontal.circle")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.warning, filled: false))
                    .disabled(!viewModel.canDeauth)
                    .help(viewModel.deauthExplanation)

                    if viewModel.mode == .external {
                        HStack(spacing: 6) {
                            Text("client")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                            TextField("broadcast", text: $viewModel.deauthClient)
                                .textFieldStyle(.roundedBorder)
                                .font(Theme.monoSmall)
                                .frame(width: 132)
                                .help("Optional unicast target, e.g. aa:bb:cc:dd:ee:ff. Leave empty for a broadcast deauth.")
                        }
                    }

                    Divider().frame(height: 18)

                    Button {
                        Task { await viewModel.attemptWPS(target: app.target.accessPoint, defaultInterface: app.scan.interface.name) }
                    } label: {
                        if viewModel.wpsRunning {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("WPS…")
                            }
                        } else {
                            Label("Try WPS", systemImage: "number.circle")
                        }
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.violet, filled: false))
                    .disabled(viewModel.mode != .external || viewModel.wpsRunning || app.target.accessPoint == nil)

                    Spacer()

                    Text(viewModel.mode.detail)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .frame(maxWidth: 430, alignment: .trailing)
                }
            }
        }
    }

    // MARK: - Metrics

    private var metrics: some View {
        HStack(spacing: 10) {
            MetricTile(
                label: "EAPOL",
                value: "\(viewModel.stats.eapolFrames)",
                caption: "\(viewModel.eapolTotal) hash\(viewModel.eapolTotal == 1 ? "" : "es")",
                tint: Theme.accent,
                systemImage: "hand.raised"
            )
            MetricTile(
                label: "PMKID",
                value: "\(viewModel.pmkidTotal)",
                caption: viewModel.pmkidTotal == 0 ? "detected by hcxpcapngtool" : "ready to crack",
                tint: Theme.violet,
                systemImage: "sparkles"
            )
            MetricTile(
                label: "Frames",
                value: Formatters.integer(viewModel.stats.frames),
                caption: Formatters.bytes(viewModel.stats.bytes),
                tint: Theme.info,
                systemImage: "waveform"
            )
            MetricTile(
                label: "Beacons",
                value: Formatters.integer(viewModel.stats.beacons),
                caption: "\(viewModel.stats.clients.count) clients",
                tint: Theme.success,
                systemImage: "dot.radiowaves.left.and.right"
            )
            MetricTile(
                label: "pcap",
                value: Formatters.bytes(viewModel.stats.pcapSize),
                caption: viewModel.stats.channel.map { "channel \($0)" } ?? "channel unknown",
                tint: Theme.warning,
                systemImage: "internaldrive"
            )
        }
    }

    private var pcapPathRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "doc.text")
                .font(.system(size: 10))
                .foregroundStyle(Theme.accent)
            Text(viewModel.pcapPath.isEmpty ? "No capture file yet — the path appears here once capture starts." : viewModel.pcapPath)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Spacer(minLength: 8)
            if viewModel.pcapURL != nil {
                Button("Reveal") { viewModel.revealPcap() }
                    .buttonStyle(.link)
                    .font(.system(size: 10))
                Button("Copy path") { viewModel.copyPcapPath() }
                    .buttonStyle(.link)
                    .font(.system(size: 10))
            }
        }
        .padding(.horizontal, 2)
    }

    // MARK: - Banners

    private var diagnosticBanner: AnyView? {
        switch viewModel.diagnostics.verdict {
        case .healthy:
            return nil
        case .silent:
            return AnyView(NoticeBanner(
                level: .danger,
                title: "Monitor mode is up but delivering nothing",
                message: "This is the known macOS 26 problem on some Apple Silicon Macs: tcpdump reports success, monitor mode is accepted, and zero frames arrive. NetCrack cannot fix that from software. Continue on an external monitor-capable adapter.",
                actionTitle: "Setup",
                action: { app.showSetup = true }
            ))
        case .notMonitor:
            return AnyView(NoticeBanner(
                level: .warning,
                title: "Not in monitor mode",
                message: "The interface did not switch to monitor mode, so management frames are invisible. Try stopping other capture tools and starting again, or use an external adapter."
            ))
        case let .wrongChannel(expected, seen):
            return AnyView(NoticeBanner(
                level: .warning,
                title: "Channel mismatch",
                message: "The radio is on channel \(seen) but the target is on \(expected). A monitor-mode radio only sees its own channel. Lock the channel, join a network on channel \(expected), or use an adapter that can be pinned."
            ))
        case .wifiOff:
            return AnyView(NoticeBanner(
                level: .danger,
                title: "Wi-Fi is off",
                message: "Turn Wi-Fi on in the menu bar, then start the capture again."
            ))
        case let .unknown(detail):
            return AnyView(NoticeBanner(level: .info, title: "Capture state", message: detail))
        }
    }

    private var honestyNotice: some View {
        Group {
            if viewModel.mode == .builtin {
                NoticeBanner(
                    level: .info,
                    title: "Built-in radio: passive capture only",
                    message: "The Mac's built-in Wi-Fi cannot transmit while in monitor mode, so there is no deauth and no WPS. NetCrack waits for a natural handshake or a PMKID. Attach a monitor-capable USB adapter to force the issue."
                )
            } else {
                NoticeBanner(
                    level: .success,
                    title: "External adapter: active capture",
                    message: "Deauth (aireplay-ng) and WPS (wash + reaver) are available. Make sure the adapter is the interface selected above and is not held by another program."
                )
            }
        }
    }

    private var hashStrip: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.seal.fill")
                .foregroundStyle(Theme.success)
            VStack(alignment: .leading, spacing: 1) {
                Text("Usable hashes captured")
                    .font(.system(size: 11.5, weight: .semibold))
                Text(viewModel.hashes.map(\.kindLabel).uniqued().joined(separator: " · "))
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            ForEach(viewModel.hashes.prefix(3)) { hash in
                Chip(text: hash.kindLabel, systemImage: hash.kind == .pmkid ? "sparkles" : "hand.raised", color: hash.kind == .pmkid ? Theme.violet : Theme.accent)
            }
            Spacer()
            if let url = viewModel.pcapURL {
                Button {
                    viewModel.revealPcap()
                } label: {
                    Label("Show pcap", systemImage: "folder")
                }
                .buttonStyle(PrimaryActionStyle(filled: false))
                .help(url.path)
            }
            Button {
                app.stage = .crack
            } label: {
                Label("Crack now", systemImage: "key.horizontal")
            }
            .buttonStyle(PrimaryActionStyle(tint: Theme.success))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Theme.success.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Theme.success.opacity(0.25), lineWidth: 1)
        )
    }

    private var wpsCard: some View {
        Card(title: "WPS", systemImage: "number.circle", tint: Theme.violet, padding: 14) {
            VStack(alignment: .leading, spacing: 8) {
                if viewModel.wpsRunning {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("wash + reaver are running. The PixieWPS attack is usually quick; a full PIN run is not.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Stop") {
                            Task { await viewModel.cancelWPS() }
                        }
                        .buttonStyle(PrimaryActionStyle(tint: Theme.danger, filled: false))
                    }
                }
                if let key = viewModel.wpsKey {
                    KeyReveal(key: key, label: "WPS PIN → PSK", subtitle: viewModel.wpsMessage) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(key, forType: .string)
                    }
                } else if let message = viewModel.wpsMessage {
                    Text(message)
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Dismiss") { viewModel.clearWPSResult() }
                        .buttonStyle(.link)
                }
            }
        }
    }
}

extension Array where Element == String {
    /// Tiny helper for the hash-kind summary line.
    func uniqued() -> [String] {
        var seen = Set<String>()
        return filter { seen.insert($0).inserted }
    }
}
