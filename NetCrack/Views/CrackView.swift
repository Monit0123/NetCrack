import SwiftUI
import AppKit

/// Crack stage: wordlist, attack shape, live hashcat status and the recovered
/// key in a size that is impossible to miss.
struct CrackView: View {
    @ObservedObject var viewModel: CrackViewModel
    @ObservedObject var app: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            HStack(alignment: .top, spacing: 14) {
                configurationColumn
                    .frame(width: 340)
                statusColumn
                    .frame(maxWidth: .infinity)
            }
            LogConsole(
                lines: viewModel.logs,
                title: "Cracker log",
                emptyText: "Run an attack to see hashcat output here.",
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
            title: "Crack",
            subtitle: subtitle,
            systemImage: AppModel.Stage.crack.symbol
        ) {
            HStack(spacing: 8) {
                Button {
                    Task { await viewModel.convertPcap() }
                } label: {
                    Label("Convert pcap…", systemImage: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(PrimaryActionStyle(filled: false))

                Button {
                    viewModel.loadHashFile()
                } label: {
                    Label("Load hashes…", systemImage: "tray.and.arrow.down")
                }
                .buttonStyle(PrimaryActionStyle(filled: false))

                if viewModel.isRunning {
                    Button {
                        Task { await viewModel.cancel() }
                    } label: {
                        Label("Stop", systemImage: "stop.fill")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.danger))
                } else {
                    Button {
                        Task { await viewModel.run() }
                    } label: {
                        Label("Run attack", systemImage: "play.fill")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.success))
                    .disabled(!viewModel.canRun)
                    .keyboardShortcut(.return, modifiers: [.command, .shift])
                }
            }
        }
    }

    private var subtitle: String {
        var parts: [String] = []
        if let target = viewModel.target {
            parts.append(target.displayName)
        }
        parts.append(viewModel.hashSummary)
        if !viewModel.sourceDescription.isEmpty {
            parts.append("from \(viewModel.sourceDescription)")
        }
        return parts.joined(separator: " · ")
    }

    // MARK: - Configuration

    private var configurationColumn: some View {
        VStack(spacing: 12) {
            wordlistCard
            attackCard
            engineCard
        }
    }

    private var wordlistCard: some View {
        Card(title: "Wordlist", systemImage: "text.book.closed", tint: Theme.accent, padding: 14) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: viewModel.wordlistIsBundled ? "shippingbox" : "doc.text")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.accent)
                    Text(viewModel.wordlistDisplayName)
                        .font(.system(size: 11.5, weight: .medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 0)
                }
                if let url = viewModel.effectiveWordlist {
                    Text(url.path)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                HStack(spacing: 8) {
                    Button {
                        viewModel.chooseWordlist()
                    } label: {
                        Label("Choose…", systemImage: "folder")
                    }
                    .buttonStyle(PrimaryActionStyle(filled: false))

                    Button {
                        viewModel.useBundledWordlist()
                    } label: {
                        Label("Bundled top-10k", systemImage: "shippingbox")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.info, filled: false))
                    .disabled(viewModel.wordlistIsBundled)
                }
                if viewModel.attackMode.needsWordlist && viewModel.effectiveWordlist == nil {
                    Text("No wordlist available. The bundled list should ship inside the app; pick another file if it is missing.")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.warning)
                }
            }
        }
    }

    private var attackCard: some View {
        Card(title: "Attack", systemImage: "square.stack.3d.up", tint: Theme.violet, padding: 14) {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(AttackMode.allCases) { mode in
                    Button {
                        viewModel.attackMode = mode
                    } label: {
                        HStack(alignment: .top, spacing: 9) {
                            Image(systemName: mode.symbol)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(viewModel.attackMode == mode ? Theme.violet : .secondary)
                                .frame(width: 16)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(mode.title)
                                    .font(.system(size: 11.5, weight: .semibold))
                                Text(mode.subtitle)
                                    .font(.system(size: 9.5))
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                            if viewModel.attackMode == mode {
                                Image(systemName: "checkmark.circle.fill")
                                    .font(.system(size: 11))
                                    .foregroundStyle(Theme.violet)
                            }
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 7)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .fill(viewModel.attackMode == mode ? Theme.violet.opacity(0.12) : Color.primary.opacity(0.03))
                        )
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(viewModel.isRunning)
                }

                if viewModel.attackMode == .dictionaryRules {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("RULE FILE")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.8)
                            .foregroundStyle(.tertiary)
                        TextField("best64.rule", text: $viewModel.ruleFile)
                            .textFieldStyle(.roundedBorder)
                            .font(Theme.monoSmall)
                            .disabled(viewModel.isRunning)
                    }
                }

                if viewModel.attackMode == .mask || viewModel.attackMode == .incremental {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("MASK")
                            .font(.system(size: 9, weight: .bold))
                            .kerning(0.8)
                            .foregroundStyle(.tertiary)
                        TextField("?d?d?d?d?d?d?d?d", text: $viewModel.mask)
                            .textFieldStyle(.roundedBorder)
                            .font(Theme.mono)
                            .disabled(viewModel.isRunning)
                        Text(viewModel.maskKeyspaceText)
                            .font(.system(size: 9.5))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var engineCard: some View {
        Card(title: "Engine", systemImage: "cpu", tint: Theme.info, padding: 14) {
            VStack(alignment: .leading, spacing: 9) {
                Picker("", selection: $viewModel.engine) {
                    ForEach(CrackEngineKind.allCases) { engine in
                        Text(engine.title).tag(engine)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .disabled(viewModel.isRunning)

                Text(viewModel.engine.detail)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Toggle("Force hashcat (--force)", isOn: $viewModel.force)
                    .toggleStyle(.checkbox)
                    .disabled(viewModel.isRunning)
                    .help("Ignore hashcat's self-test warnings. Useful in VMs; normally leave this off.")

                if viewModel.engine == .aircrack && viewModel.pcapFile == nil {
                    Text("aircrack-ng needs the original pcap for these hashes. Load one with “Convert pcap…” or switch to hashcat.")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.warning)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: - Status

    private var statusColumn: some View {
        VStack(spacing: 12) {
            if let key = viewModel.recoveredKey {
                KeyReveal(
                    key: key,
                    label: "Recovered key",
                    subtitle: keySubtitle,
                    onCopy: { viewModel.copyKey() }
                )
            } else if viewModel.hashFile == nil {
                emptyHashState
            } else {
                progressCard
            }

            if let reason = viewModel.exhaustedReason, viewModel.recoveredKey == nil {
                NoticeBanner(
                    level: .warning,
                    title: "No match",
                    message: reason + " Try the next attack shape: dictionary + rules, then a mask or incremental run."
                )
            }

            if viewModel.isRunning || viewModel.status.speedPerSecond > 0 {
                HStack(spacing: 10) {
                    MetricTile(label: "Speed", value: viewModel.speedText, caption: "hashcat -w 3", tint: Theme.accent, systemImage: "speedometer")
                    MetricTile(label: "Progress", value: viewModel.progressText, caption: "\(viewModel.elapsedText) elapsed", tint: Theme.info, systemImage: "chart.bar")
                    MetricTile(label: "ETA", value: viewModel.etaText, caption: "estimate", tint: Theme.violet, systemImage: "clock")
                    MetricTile(label: "Recovered", value: "\(viewModel.status.recovered)", caption: "of \(viewModel.hashCount)", tint: Theme.success, systemImage: "checkmark.seal")
                }
            }
        }
    }

    private var keySubtitle: String {
        guard let outcome = viewModel.outcome else { return "Imported hash — verify before use." }
        return "\(outcome.engine.title) · \(outcome.mode.title) · \(Formatters.duration(outcome.duration))\(outcome.deviceName.map { " · \($0)" } ?? "")"
    }

    private var progressCard: some View {
        Card(title: "Attack status", systemImage: "waveform.path.ecg", tint: Theme.accent) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(viewModel.isRunning ? Theme.accent : Color.secondary)
                        .frame(width: 7, height: 7)
                    Text(viewModel.isRunning ? "Running" : "Ready")
                        .font(.system(size: 12, weight: .semibold))
                    Spacer()
                    if viewModel.isRunning {
                        Text(Formatters.clock(viewModel.elapsed))
                            .font(Theme.mono)
                            .foregroundStyle(.secondary)
                    }
                }

                if viewModel.progressIsDeterminate {
                    ProgressView(value: viewModel.progressFraction)
                        .progressViewStyle(.linear)
                        .tint(Theme.accent)
                    HStack {
                        Text(viewModel.progressText)
                            .font(Theme.mono)
                        Spacer()
                        Text("ETA \(viewModel.etaText)")
                            .font(Theme.mono)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    ProgressView()
                        .progressViewStyle(.linear)
                        .tint(Theme.accent)
                    Text(viewModel.isRunning
                         ? "hashcat has not reported a percentage for this keyspace yet. Speed and elapsed time are live."
                         : "Pick an attack and press Run attack.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 6) {
                    Chip(text: viewModel.hashSummary, systemImage: "number", color: Theme.violet)
                    if let url = viewModel.hashFile {
                        Chip(text: url.lastPathComponent, systemImage: "doc", color: Theme.info)
                    }
                }
            }
        }
    }

    private var emptyHashState: some View {
        Card(title: "No hashes yet", systemImage: "tray", tint: Theme.warning) {
            VStack(alignment: .leading, spacing: 10) {
                Text("A crack needs a hash. Capture a handshake on the Capture pane, or convert a pcap you already have.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button {
                        app.stage = .capture
                    } label: {
                        Label("Go to Capture", systemImage: "record.circle")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.accent, filled: false))

                    Button {
                        Task { await viewModel.convertPcap() }
                    } label: {
                        Label("Convert a pcap", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(PrimaryActionStyle(tint: Theme.info, filled: false))
                }
            }
        }
    }
}
