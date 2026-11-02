import SwiftUI
import AppKit

/// Single window: a compact stage list on the left, the active pane on the
/// right, setup and queue as sheets.
struct RootView: View {
    @EnvironmentObject private var app: AppModel

    private var stageBinding: Binding<AppModel.Stage> { $app.stage }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(spacing: 0) {
                if let banner = app.missingToolBanner {
                    missingToolsBanner(banner)
                }
                if !app.canSeeSSIDs {
                    locationBanner
                }
                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 1_040, minHeight: 700)
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $app.showSetup) {
            SetupView(viewModel: app.setup, app: app)
                .frame(width: 760, height: 660)
        }
        .sheet(isPresented: $app.showQueue) {
            QueueView(viewModel: app.queue, app: app)
                .frame(width: 980, height: 720)
        }
        .alert(item: $app.error) { error in
            Alert(
                title: Text(error.message),
                message: error.detail.map { Text($0) },
                dismissButton: .default(Text("OK"))
            )
        }
        .onAppear {
            if let delegate = NSApp.delegate as? AppDelegate {
                delegate.appModel = app
            }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Image(systemName: "wifi.router")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(Theme.accent)
                    Text("NetCrack")
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                }
                Text("Wi-Fi password recovery")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.top, 18)
            .padding(.bottom, 16)

            VStack(spacing: 4) {
                ForEach(AppModel.Stage.allCases) { stage in
                    stageButton(stage)
                }
            }
            .padding(.horizontal, 10)

            Spacer(minLength: 12)

            VStack(alignment: .leading, spacing: 10) {
                Divider().opacity(0.5)
                interfaceSummary
                toolSummary
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 14)
        }
        .frame(width: Theme.sidebarWidth)
        .background(
            LinearGradient(
                colors: [
                    Color(nsColor: .controlBackgroundColor),
                    Color(nsColor: .controlBackgroundColor).opacity(0.72)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
        )
    }

    private func stageButton(_ stage: AppModel.Stage) -> some View {
        Button {
            stageBinding.wrappedValue = stage
        } label: {
            HStack(spacing: 10) {
                Image(systemName: stage.symbol)
                    .font(.system(size: 13, weight: .medium))
                    .frame(width: 20)
                    .foregroundStyle(app.stage == stage ? Theme.accent : .secondary)
                VStack(alignment: .leading, spacing: 1) {
                    Text(stage.rawValue)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text(stage.tagline)
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                if stage == .capture, app.capture.isRunning {
                    Circle()
                        .fill(Theme.danger)
                        .frame(width: 6, height: 6)
                }
                if stage == .crack, app.crack.hasKey {
                    Image(systemName: "key.fill")
                        .font(.system(size: 9))
                        .foregroundStyle(Theme.success)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(app.stage == stage ? Theme.accent.opacity(0.13) : Color.clear)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(app.stage == stage ? Theme.accent.opacity(0.25) : Color.clear, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var interfaceSummary: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("RADIO")
                .font(.system(size: 9, weight: .bold))
                .kerning(1.0)
                .foregroundStyle(.tertiary)
            HStack(spacing: 6) {
                Image(systemName: app.scan.interface.isPoweredOn ? "wifi" : "wifi.slash")
                    .font(.system(size: 10))
                    .foregroundStyle(app.scan.interface.isPoweredOn ? Theme.success : Theme.danger)
                Text(app.scan.interface.name)
                    .font(Theme.monoSmall)
                if let channel = app.scan.interface.channel, channel > 0 {
                    Text("ch \(channel)")
                        .font(Theme.monoSmall)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            if let ssid = app.scan.interface.ssid, !ssid.isEmpty {
                Text(ssid)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
    }

    private var toolSummary: some View {
        Button {
            app.showSetup = true
        } label: {
            HStack(spacing: 6) {
                Image(systemName: app.toolchain.hasRequiredTools ? "checkmark.shield" : "exclamationmark.shield")
                    .font(.system(size: 11))
                    .foregroundStyle(app.toolchain.hasRequiredTools ? Theme.success : Theme.warning)
                Text(app.toolchain.hasRequiredTools ? "Tools ready" : "Setup needed")
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 8, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.primary.opacity(0.04))
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Check and install hashcat, hcxtools, aircrack-ng and tcpdump")
    }

    // MARK: - Banners

    private func missingToolsBanner(_ summary: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "shippingbox.fill")
                .foregroundStyle(Theme.warning)
            VStack(alignment: .leading, spacing: 1) {
                Text("The crack toolchain is incomplete")
                    .font(.system(size: 11.5, weight: .semibold))
                Text(summary)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open setup") { app.showSetup = true }
                .buttonStyle(PrimaryActionStyle(tint: Theme.warning, filled: false))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 9)
        .background(Theme.warning.opacity(0.10))
        .overlay(alignment: .bottom) { Divider().opacity(0.4) }
    }

    private var locationBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "location.slash.fill")
                .foregroundStyle(Theme.info)
            Text(app.location.state.explanation ?? "Location access is needed to read network names.")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button("Open Settings") { app.location.openSettings() }
                .buttonStyle(PrimaryActionStyle(tint: Theme.info, filled: false))
            Button {
                app.location.refresh()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Re-check the authorisation state")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 9)
        .background(Theme.info.opacity(0.08))
        .overlay(alignment: .bottom) { Divider().opacity(0.4) }
    }

    // MARK: - Stage content

    @ViewBuilder
    private var content: some View {
        switch app.stage {
        case .scan:
            ScanView(viewModel: app.scan, app: app)
        case .target:
            TargetView(viewModel: app.target, app: app)
        case .capture:
            CaptureView(viewModel: app.capture, app: app)
        case .crack:
            CrackView(viewModel: app.crack, app: app)
        }
    }
}
