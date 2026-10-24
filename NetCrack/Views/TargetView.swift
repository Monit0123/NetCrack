import SwiftUI
import AppKit

/// Target stage: everything known about one network, including the instant
/// "is the password already on this Mac?" answer.
struct TargetView: View {
    @ObservedObject var viewModel: TargetViewModel
    @ObservedObject var app: AppModel

    var body: some View {
        Group {
            if let accessPoint = viewModel.accessPoint {
                content(accessPoint)
            } else {
                emptyState
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Content

    private func content(_ accessPoint: AccessPoint) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header(accessPoint)

                HStack(alignment: .top, spacing: 16) {
                    VStack(spacing: 16) {
                        detailsCard(accessPoint)
                        securityCard(accessPoint)
                        clientsCard
                        hashesCard
                    }
                    .frame(maxWidth: .infinity)

                    VStack(spacing: 16) {
                        keychainCard(accessPoint)
                        actionsCard(accessPoint)
                        honestyCard(accessPoint)
                    }
                    .frame(width: 336)
                }
            }
            .panePadding()
        }
    }

    private func header(_ accessPoint: AccessPoint) -> some View {
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Theme.color(for: accessPoint.security).opacity(0.14))
                Image(systemName: accessPoint.isHidden ? "eye.slash" : "wifi")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(Theme.color(for: accessPoint.security))
            }
            .frame(width: 52, height: 52)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(accessPoint.displayName)
                        .font(.system(size: 24, weight: .semibold, design: .rounded))
                        .lineLimit(1)
                    SecurityBadge(security: accessPoint.security)
                    if viewModel.isJoinedNetwork {
                        Chip(text: "joined", systemImage: "checkmark.circle.fill", color: Theme.success)
                    }
                }
                HStack(spacing: 8) {
                    Text(accessPoint.displayBSSID)
                        .font(Theme.mono)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Button {
                        copy(accessPoint.displayBSSID)
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 9))
                    }
                    .buttonStyle(.borderless)
                    .help("Copy the BSSID")
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text(accessPoint.channelSummary)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text("\(accessPoint.rssi) dBm · \(accessPoint.rssiQuality)")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button {
                app.stage = .scan
            } label: {
                Label("Rescan", systemImage: "arrow.clockwise")
            }
            .buttonStyle(PrimaryActionStyle(filled: false))
        }
    }

    // MARK: - Cards

    private func detailsCard(_ accessPoint: AccessPoint) -> some View {
        Card(title: "Network", systemImage: "scope", tint: Theme.accent) {
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 8) {
                GridRow {
                    InfoRow(label: "SSID", value: accessPoint.ssid.isEmpty ? "(hidden)" : accessPoint.ssid, monospaced: false)
                }
                GridRow {
                    InfoRow(label: "BSSID", value: accessPoint.displayBSSID)
                }
                GridRow {
                    InfoRow(label: "Channel", value: "\(accessPoint.channelLabel) · \(accessPoint.bandLabel) · \(accessPoint.widthMHz > 0 ? "\(accessPoint.widthMHz) MHz" : "width unknown")")
                }
                GridRow {
                    InfoRow(label: "Security", value: accessPoint.securityLabel, monospaced: false, tint: Theme.color(for: accessPoint.security))
                }
                GridRow {
                    InfoRow(label: "PHY", value: accessPoint.phy, monospaced: false)
                }
                GridRow {
                    InfoRow(label: "Signal", value: "\(accessPoint.rssi) dBm\(accessPoint.noise < 0 ? " · noise \(accessPoint.noise) dBm" : "")\(accessPoint.snr.map { " · SNR \($0) dB" } ?? "")", monospaced: true)
                }
                GridRow {
                    InfoRow(label: "Vendor", value: accessPoint.vendorHint ?? "Unknown OUI", monospaced: false)
                }
                GridRow {
                    InfoRow(label: "Flags", value: flags(accessPoint), monospaced: false)
                }
            }
        }
    }

    private func flags(_ accessPoint: AccessPoint) -> String {
        var parts: [String] = []
        if accessPoint.isHidden { parts.append("hidden SSID") }
        if accessPoint.isIBSS { parts.append("ad-hoc (IBSS)") }
        if accessPoint.security.supportsPMKID { parts.append("PMKID possible") }
        if accessPoint.security.supportsSAE { parts.append("SAE") }
        if parts.isEmpty { parts.append("—") }
        return parts.joined(separator: " · ")
    }

    private func securityCard(_ accessPoint: AccessPoint) -> some View {
        Card(title: "How this network can be recovered", systemImage: "lock.shield", tint: Theme.color(for: accessPoint.security)) {
            Text(viewModel.securityExplanation)
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if accessPoint.security == .wep {
                HStack(spacing: 6) {
                    Chip(text: "aircrack -a 1", systemImage: "bolt.fill", color: Theme.warning)
                    Chip(text: "needs IVs", systemImage: "waveform", color: Theme.warning)
                }
            } else if accessPoint.security.isCrackable {
                HStack(spacing: 6) {
                    Chip(text: "22000", systemImage: "number", color: Theme.accent)
                    Chip(text: "PMKID or EAPOL", systemImage: "antenna.radiowaves.left.and.right", color: Theme.accent)
                    if accessPoint.security.supportsSAE {
                        Chip(text: "SAE", systemImage: "lock.rotation", color: Theme.violet)
                    }
                }
            }
        }
    }

    private var clientsCard: some View {
        Card(title: "Observed clients", systemImage: "person.2.wave.2", tint: Theme.info) {
            if viewModel.clients.isEmpty {
                Text("No client MACs yet. Clients appear here after a capture observes their traffic — which is also when a handshake becomes likely.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(spacing: 4) {
                    ForEach(viewModel.clients.prefix(8)) { client in
                        HStack(spacing: 8) {
                            Image(systemName: "iphone")
                                .font(.system(size: 10))
                                .foregroundStyle(Theme.info)
                            Text(client.mac.uppercased())
                                .font(Theme.mono)
                                .textSelection(.enabled)
                            Spacer()
                            Text("\(client.frames) frames")
                                .font(.system(size: 10))
                                .foregroundStyle(.tertiary)
                            Button {
                                copy(client.mac)
                            } label: {
                                Image(systemName: "doc.on.doc").font(.system(size: 9))
                            }
                            .buttonStyle(.borderless)
                            .help("Copy this MAC (useful for a targeted deauth)")
                        }
                        .padding(.vertical, 3)
                        Divider().opacity(0.3)
                    }
                }
            }
        }
    }

    private var hashesCard: some View {
        Card(title: "Captured hashes", systemImage: "number", tint: Theme.violet) {
            if viewModel.hashes.isEmpty {
                Text("Nothing captured for this network yet.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(viewModel.hashes.prefix(6)) { hash in
                        HStack(spacing: 8) {
                            Chip(text: hash.kindLabel, systemImage: hash.kind == .pmkid ? "sparkles" : "hand.raised", color: hash.kind == .pmkid ? Theme.violet : Theme.accent)
                            Text(hash.accessPoint.isEmpty ? "—" : hash.accessPoint)
                                .font(Theme.monoSmall)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text(hash.displaySSID)
                                .font(.system(size: 10))
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                        }
                    }
                    Button {
                        app.stage = .crack
                    } label: {
                        Label("Open Crack", systemImage: "key.horizontal")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.violet, filled: false))
                }
            }
        }
    }

    private func keychainCard(_ accessPoint: AccessPoint) -> some View {
        Card(title: "Password already known?", systemImage: "key.fill", tint: viewModel.knownPassword == nil ? Theme.accent : Theme.success) {
            if let password = viewModel.knownPassword {
                KeyReveal(
                    key: password,
                    label: "From your Keychain",
                    subtitle: "macOS already stored this network's key — no capture needed.",
                    onCopy: { copy(password) }
                )
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Text(viewModel.keychainStatusTitle)
                        .font(.system(size: 12, weight: .semibold))
                    Text(viewModel.keychainStatusDetail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 8) {
                        Button {
                            Task { await viewModel.recheckKeychain() }
                        } label: {
                            if viewModel.isProbing {
                                ProgressView().controlSize(.small)
                            } else {
                                Label("Check again", systemImage: "arrow.clockwise")
                            }
                        }
                        .buttonStyle(PrimaryActionStyle(filled: false))
                        .disabled(viewModel.isProbing || accessPoint.ssid.isEmpty)
                    }

                    Text("Lookup: security find-generic-password -D “AirPort network password” -a “\(accessPoint.ssid.isEmpty ? "<ssid>" : accessPoint.ssid)” -w")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func actionsCard(_ accessPoint: AccessPoint) -> some View {
        Card(title: "Next step", systemImage: "arrow.triangle.branch", tint: Theme.accent) {
            VStack(alignment: .leading, spacing: 8) {
                Button {
                    Task { await app.startCapture() }
                } label: {
                    Label("Capture a handshake", systemImage: "record.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionStyle())
                .disabled(!accessPoint.security.isCrackable)

                Button {
                    app.stage = .crack
                } label: {
                    Label("Crack existing hashes", systemImage: "key.horizontal")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.violet, filled: false))

                Button {
                    app.queue.selectedIDs.insert(accessPoint.id)
                    app.showQueue = true
                } label: {
                    Label("Add to queue", systemImage: "square.stack.3d.up")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.info, filled: false))
            }
        }
    }

    private func honestyCard(_ accessPoint: AccessPoint) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "info.circle.fill")
                    .foregroundStyle(Theme.info)
                    .font(.system(size: 11))
                Text("What this Mac can do")
                    .font(.system(size: 11, weight: .semibold))
            }
            Text("The built-in radio is passive: it can record a handshake that happens on its own, but it cannot deauth or run WPS. An external monitor-capable adapter unlocks both.")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !accessPoint.security.supportsPMKID {
                Text("No PMKID is available for \(accessPoint.securityLabel); the EAPOL path needs a client to connect.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.warning)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Theme.info.opacity(0.06))
        )
    }

    // MARK: - Empty

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "scope")
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(Theme.accent)
            Text("No target selected")
                .font(.system(size: 17, weight: .semibold, design: .rounded))
            Text("Pick a network on the Scan pane, then come back here for its details, observed clients and the Keychain lookup.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
            Button {
                app.stage = .scan
            } label: {
                Label("Go to Scan", systemImage: "dot.radiowaves.left.and.right")
            }
            .buttonStyle(PrimaryActionStyle())
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
