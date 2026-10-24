import SwiftUI

/// Queue sheet: pick N networks, run the whole pipeline unattended, get a
/// results table with the recovered keys.
struct QueueView: View {
    @ObservedObject var viewModel: QueueViewModel
    @ObservedObject var app: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().opacity(0.5)
            HStack(alignment: .top, spacing: 0) {
                networkColumn
                    .frame(width: 330)
                Divider().opacity(0.5)
                optionsColumn
                    .frame(maxWidth: .infinity)
            }
            .frame(maxHeight: .infinity)
            Divider().opacity(0.5)
            footer
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .fill(Theme.violet.opacity(0.16))
                    Image(systemName: "square.stack.3d.up.fill")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.violet)
                }
                .frame(width: 42, height: 42)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Queue mode")
                        .font(.system(size: 19, weight: .semibold, design: .rounded))
                    Text("Select networks and NetCrack runs Keychain → capture → dictionary → rules → mask → incremental → WPS, unattended.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(.borderless)
                .help("Close")
            }

            if viewModel.isRunning || viewModel.progress != nil {
                HStack(spacing: 8) {
                    ProgressView(value: viewModel.progressFraction)
                        .progressViewStyle(.linear)
                        .tint(Theme.violet)
                    Text(viewModel.progressText)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(maxWidth: 360, alignment: .trailing)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    // MARK: - Networks

    private var networkColumn: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("NETWORKS")
                    .font(.system(size: 9.5, weight: .bold))
                    .kerning(0.9)
                    .foregroundStyle(.tertiary)
                Spacer()
                Button("Crackable") { viewModel.selectAllCrackable() }
                    .buttonStyle(.link)
                    .font(.system(size: 10))
                Button("Clear") { viewModel.clearSelection() }
                    .buttonStyle(.link)
                    .font(.system(size: 10))
            }
            .padding(.horizontal, 16)

            ScrollView {
                LazyVStack(spacing: 2) {
                    if viewModel.networks.isEmpty {
                        Text("No networks scanned yet. Close this sheet and scan first.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .padding(16)
                    }
                    ForEach(viewModel.networks) { accessPoint in
                        networkRow(accessPoint)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 10)
            }
        }
        .padding(.top, 14)
    }

    private func networkRow(_ accessPoint: AccessPoint) -> some View {
        let selected = viewModel.isSelected(accessPoint)
        let crackable = accessPoint.security.isCrackable
        return Button {
            viewModel.toggle(accessPoint)
        } label: {
            HStack(spacing: 8) {
                Image(systemName: selected ? "checkmark.square.fill" : "square")
                    .font(.system(size: 12))
                    .foregroundStyle(selected ? Theme.violet : .secondary)
                VStack(alignment: .leading, spacing: 1) {
                    Text(accessPoint.displayName)
                        .font(.system(size: 11.5, weight: .medium))
                        .lineLimit(1)
                    Text("\(accessPoint.channelLabel) · \(accessPoint.securityLabel)")
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                SignalBars(rssi: accessPoint.rssi)
                if !crackable {
                    Image(systemName: "minus.circle")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                        .help("No PSK to recover (open, OWE or 802.1X)")
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(selected ? Theme.violet.opacity(0.10) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(crackable ? 1 : 0.55)
    }

    // MARK: - Options + results

    private var optionsColumn: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                optionsCard
                resultsCard
                LogConsole(
                    lines: viewModel.logs,
                    title: "Queue log",
                    emptyText: "No run yet.",
                    onClear: { viewModel.clearResults() },
                    onCopy: nil
                )
                .frame(height: 170)
            }
            .padding(16)
        }
    }

    private var optionsCard: some View {
        Card(title: "Run options", systemImage: "slider.horizontal.3", tint: Theme.violet, padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("CAPTURE PER NETWORK")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.8)
                            .foregroundStyle(.tertiary)
                        HStack(spacing: 6) {
                            Stepper(value: $viewModel.captureSeconds, in: 10...300, step: 5) {
                                Text("\(Int(viewModel.captureSeconds)) s")
                                    .font(Theme.mono)
                            }
                            .frame(width: 150)
                        }
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("RADIO")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.8)
                            .foregroundStyle(.tertiary)
                        Text("\(app.capture.mode.shortTitle) · \(app.capture.effectiveInterface(defaultName: app.scan.interface.name))")
                            .font(Theme.monoSmall)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                Divider().opacity(0.4)

                HStack(alignment: .top, spacing: 26) {
                    VStack(alignment: .leading, spacing: 6) {
                        toggle("Keychain lookup first", isOn: $viewModel.tryKeychain, help: "Try the saved password before touching the radio.")
                        toggle("Mask attack after dictionary", isOn: $viewModel.runMask, help: "8-digit and similar masks. Bounded to 10 minutes per target.")
                        toggle("Incremental after mask", isOn: $viewModel.runIncremental, help: "Growing masks. Slower; off by default.")
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        toggle("WEP path (aircrack -a 1)", isOn: $viewModel.runWEP, help: "Collect IVs and let aircrack-ng recover the key.")
                        Toggle("WPS (external adapter)", isOn: $viewModel.runWPS)
                            .toggleStyle(.checkbox)
                            .disabled(app.capture.mode == .builtin)
                            .help(app.capture.mode == .builtin ? "The built-in radio cannot transmit, so WPS is impossible." : "wash + reaver, PixieWPS first.")
                        Toggle("Deauth before capture (external)", isOn: $viewModel.deauthFirst)
                            .toggleStyle(.checkbox)
                            .disabled(app.capture.mode == .builtin)
                            .help("Force a client to reconnect so a handshake appears quickly.")
                    }
                }

                if app.capture.mode == .builtin {
                    Text("Built-in radio: passive capture only. No deauth, no WPS. Queue mode works, it just has to wait for natural handshakes.")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func toggle(_ title: String, isOn: Binding<Bool>, help: String) -> some View {
        Toggle(title, isOn: isOn)
            .toggleStyle(.checkbox)
            .help(help)
    }

    private var resultsCard: some View {
        Card(title: "Results", systemImage: "tablecells", tint: Theme.success, padding: 14) {
            VStack(alignment: .leading, spacing: 8) {
                if viewModel.results.isEmpty {
                    Text("Results appear here as each network finishes. Queue mode prints the whole table at the end too.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                } else {
                    HStack(spacing: 8) {
                        Chip(text: "\(viewModel.results.count) targets", systemImage: "square.stack.3d.up", color: Theme.info)
                        Chip(text: "\(viewModel.recoveredCount) recovered", systemImage: "checkmark.seal", color: Theme.success)
                        Spacer()
                        Button {
                            viewModel.exportCSV()
                        } label: {
                            Label("Export CSV", systemImage: "square.and.arrow.up")
                        }
                        .buttonStyle(PrimaryActionStyle(filled: false))
                    }
                    ForEach(viewModel.results) { result in
                        resultRow(result)
                        Divider().opacity(0.3)
                    }
                }
            }
        }
    }

    private func resultRow(_ result: PipelineResult) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Image(systemName: result.status.symbol)
                .font(.system(size: 11))
                .foregroundStyle(Theme.color(for: result.status))
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 1) {
                Text(result.ssid)
                    .font(.system(size: 11.5, weight: .semibold))
                    .lineLimit(1)
                Text(result.detail)
                    .font(.system(size: 9.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer(minLength: 8)
            if let key = result.key {
                Text(key)
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(1)
                Button {
                    viewModel.copyKey(for: result)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 9))
                }
                .buttonStyle(.borderless)
                .help("Copy the key")
            } else {
                Text(result.status.rawValue)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Theme.color(for: result.status))
            }
            Text(Formatters.clock(result.duration))
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.tertiary)
                .frame(width: 56, alignment: .trailing)
        }
        .padding(.vertical, 3)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: 10) {
            Text("\(viewModel.selectedNetworks.count) selected")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)

            Spacer()

            if let error = viewModel.error {
                Text(error.message)
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.danger)
                    .lineLimit(1)
            }

            if viewModel.isRunning {
                Button {
                    Task { await viewModel.cancel() }
                } label: {
                    Label("Stop queue", systemImage: "stop.fill")
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.danger))
            } else {
                Button {
                    Task { await app.runQueue() }
                } label: {
                    Label("Run queue", systemImage: "play.fill")
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.violet))
                .disabled(!viewModel.canRun)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }
}
