import SwiftUI
import AppKit
import Foundation

/// Scan stage: every nearby access point, sortable and searchable.
struct ScanView: View {
    @ObservedObject var viewModel: ScanViewModel
    @ObservedObject var app: AppModel

    @State private var sortOrder: [KeyPathComparator<AccessPoint>] = []

    private var rows: [AccessPoint] {
        let base = viewModel.sortedNetworks
        guard !sortOrder.isEmpty else { return base }
        return base.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(
                title: "Scan",
                subtitle: "Nearby access points, strongest first. CoreWLAN, no sudo, no airport(1).",
                systemImage: AppModel.Stage.scan.symbol
            ) {
                HStack(spacing: 8) {
                    Button {
                        app.showQueue = true
                    } label: {
                        Label("Queue…", systemImage: "square.stack.3d.up")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.violet, filled: false))
                    .help("Run the whole pipeline against several networks unattended")

                    Button {
                        viewModel.selectNext()
                    } label: {
                        Image(systemName: "arrow.down")
                    }
                    .buttonStyle(PrimaryActionStyle(filled: false))
                    .help("Select the next network")

                    Button {
                        Task { await app.scanNow() }
                    } label: {
                        if viewModel.isScanning {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Scan", systemImage: "arrow.clockwise")
                        }
                    }
                    .buttonStyle(PrimaryActionStyle())
                    .disabled(viewModel.isScanning)
                    .keyboardShortcut("r", modifiers: .command)
                }
            }
            .panePadding()

            searchBar
                .padding(.horizontal, 24)
                .padding(.bottom, 12)

            Table(rows, selection: $viewModel.selectedID, sortOrder: $sortOrder) {
                TableColumn("Network", value: \.ssid) { accessPoint in
                    HStack(spacing: 7) {
                        Image(systemName: accessPoint.isHidden ? "eye.slash" : "wifi")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.color(for: accessPoint.security))
                        VStack(alignment: .leading, spacing: 0) {
                            Text(accessPoint.displayName)
                                .font(.system(size: 12, weight: .medium))
                                .lineLimit(1)
                            if let vendor = accessPoint.vendorHint {
                                Text(vendor)
                                    .font(.system(size: 9))
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) {
                        app.adoptTarget(accessPoint, changeStage: true)
                    }
                    .contextMenu {
                        Button("Open target details") { app.adoptTarget(accessPoint, changeStage: true) }
                        Button("Copy BSSID") { copy(accessPoint.bssid) }
                        Button("Add to queue") {
                            viewModel.selectedID = accessPoint.id
                            app.queue.selectedIDs.insert(accessPoint.id)
                            app.showQueue = true
                        }
                    }
                }
                .width(min: 150, ideal: 210)

                TableColumn("BSSID", value: \.bssid) { accessPoint in
                    Text(accessPoint.displayBSSID)
                        .font(Theme.monoSmall)
                        .foregroundStyle(.secondary)
                }
                .width(min: 130, ideal: 145)

                TableColumn("Channel", value: \.channel) { accessPoint in
                    HStack(spacing: 4) {
                        Text(accessPoint.channelLabel)
                            .font(.system(size: 11, design: .monospaced))
                        if accessPoint.widthMHz > 0 {
                            Text("\(accessPoint.widthMHz)MHz")
                                .font(.system(size: 8.5))
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                .width(min: 76, ideal: 92)

                TableColumn("Band", value: \.band.rawValue) { accessPoint in
                    Text(accessPoint.band.shortLabel + " GHz")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                }
                .width(min: 58, ideal: 68)

                TableColumn("Security") { accessPoint in
                    SecurityBadge(security: accessPoint.security)
                }
                .width(min: 74, ideal: 86)

                TableColumn("Signal", value: \.rssi) { accessPoint in
                    SignalCell(accessPoint: accessPoint)
                }
                .width(min: 104, ideal: 116)

                TableColumn("PHY", value: \.phy) { accessPoint in
                    Text(accessPoint.phy)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                .width(min: 62, ideal: 76)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            footer
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear {
            if viewModel.networks.isEmpty {
                Task { await app.scanNow() }
            }
        }
    }

    private var searchBar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                TextField("Search SSID, BSSID, vendor, channel…", text: $viewModel.searchText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                if !viewModel.searchText.isEmpty {
                    Button {
                        viewModel.searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.primary.opacity(0.05))
            )
            .frame(maxWidth: 380)

            sortMenu

            Spacer()

            HStack(spacing: 6) {
                Chip(text: "\(viewModel.networks.count) APs", systemImage: "dot.radiowaves.left.and.right", color: Theme.accent)
                Chip(text: "\(viewModel.crackableCount) crackable", systemImage: "lock.fill", color: Theme.warning)
                if let strongest = viewModel.strongest {
                    Chip(text: strongest.rssiQuality, systemImage: "antenna.radiowaves.left.and.right", color: Theme.success)
                }
            }
        }
    }

    private var sortMenu: some View {
        Menu {
            ForEach(ScanViewModel.SortKey.allCases) { key in
                Button {
                    viewModel.toggleSort(key)
                } label: {
                    if viewModel.sortKey == key {
                        Label("\(key.rawValue) \(viewModel.ascending ? "↑" : "↓")", systemImage: "checkmark")
                    } else {
                        Text(key.rawValue)
                    }
                }
            }
            Divider()
            Button("Reset to signal strength") {
                viewModel.sortKey = .signal
                viewModel.ascending = false
                sortOrder = []
            }
        } label: {
            Label("Sort: \(viewModel.sortKey.rawValue)", systemImage: "arrow.up.arrow.down")
                .font(.system(size: 11.5))
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Image(systemName: viewModel.interface.isPoweredOn ? "wifi" : "wifi.slash")
                .font(.system(size: 10))
                .foregroundStyle(viewModel.interface.isPoweredOn ? Theme.success : Theme.danger)
            Text(viewModel.interface.statusLine)
                .font(Theme.monoSmall)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            if let error = viewModel.error, !error.isEmpty {
                Text("· \(error)")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.warning)
                    .lineLimit(1)
            }

            Spacer()

            if let scannedAt = viewModel.lastScan {
                Text("scanned \(scannedAt.formatted(date: .omitted, time: .standard))")
                    .font(.system(size: 9.5))
                    .foregroundStyle(.tertiary)
            }

            Button {
                app.adoptTarget(viewModel.selectedAccessPoint, changeStage: true)
            } label: {
                Label("Target details", systemImage: "scope")
            }
            .buttonStyle(PrimaryActionStyle(filled: false))
            .disabled(viewModel.selectedAccessPoint == nil)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
        .overlay(alignment: .top) { Divider().opacity(0.5) }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
