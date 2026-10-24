import SwiftUI
import AppKit

/// Setup sheet: toolchain status and the one-click Homebrew installer.
struct SetupView: View {
    @ObservedObject var viewModel: SetupViewModel
    @ObservedObject var app: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().opacity(0.5)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    toolList
                    if !viewModel.report.hasBrew {
                        NoticeBanner(
                            level: .danger,
                            title: "Homebrew is missing",
                            message: "Everything else is installed through Homebrew. NetCrack can run the official installer for you — it asks for your administrator password once.",
                            actionTitle: nil,
                            action: nil
                        )
                    }
                    aircrackWarning
                    commandSheet
                    if viewModel.isInstalling || !viewModel.logs.isEmpty {
                        LogConsole(
                            lines: viewModel.logs,
                            title: "Installer log",
                            emptyText: "Waiting for Homebrew…",
                            onClear: { viewModel.clearLogs() },
                            onCopy: nil
                        )
                        .frame(height: 170)
                    }
                }
                .padding(20)
            }

            Divider().opacity(0.5)
            footer
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            if viewModel.report.statuses.isEmpty {
                await viewModel.refresh()
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(Theme.accent.opacity(0.15))
                Image(systemName: "shippingbox.fill")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Theme.accent)
            }
            .frame(width: 42, height: 42)

            VStack(alignment: .leading, spacing: 2) {
                Text("Setup")
                    .font(.system(size: 19, weight: .semibold, design: .rounded))
                Text("NetCrack is a GUI over proven CLI tools. Nothing here reimplements 802.11 crypto.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if viewModel.isInstalling {
                HStack(spacing: 7) {
                    ProgressView().controlSize(.small)
                    Text(viewModel.phase)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(maxWidth: 220, alignment: .trailing)
                }
            }
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 11, weight: .semibold))
            }
            .buttonStyle(.borderless)
            .help("Close")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var toolList: some View {
        VStack(spacing: 1) {
            ForEach(ExternalTool.allCases) { tool in
                toolRow(tool)
                if tool != ExternalTool.allCases.last {
                    Divider().opacity(0.3)
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
        )
    }

    private func toolRow(_ tool: ExternalTool) -> some View {
        let status = viewModel.report.statuses[tool]
        let available = status?.isAvailable == true
        return HStack(alignment: .center, spacing: 10) {
            Image(systemName: available ? "checkmark.circle.fill" : (tool.isRequired ? "exclamationmark.circle.fill" : "circle.dashed"))
                .font(.system(size: 13))
                .foregroundStyle(available ? Theme.success : (tool.isRequired ? Theme.danger : .secondary))
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(tool.displayName)
                        .font(.system(size: 12, weight: .semibold))
                    if !tool.isRequired {
                        Text("OPTIONAL")
                            .font(.system(size: 8, weight: .bold))
                            .kerning(0.6)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.primary.opacity(0.07)))
                    }
                }
                Text(tool.purpose)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 1) {
                Text(status?.shortVersion ?? "not found")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundStyle(available ? .secondary : Theme.danger)
                if let path = status?.path {
                    Text(path)
                        .font(.system(size: 8.5, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .frame(maxWidth: 300, alignment: .trailing)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var aircrackWarning: some View {
        NoticeBanner(
            level: .warning,
            title: "aircrack-ng has no Apple Silicon bottle",
            message: "Homebrew has to compile it, which takes 5–15 minutes and uses a lot of CPU. It provides aireplay-ng (deauth), wash (WPS scan), the WPS engine and the fallback cracker. You can skip it and still use hashcat + hcxtools with the built-in radio."
        )
    }

    private var commandSheet: some View {
        Card(title: "Commands, if you prefer Terminal", systemImage: "terminal", tint: Theme.info, padding: 14) {
            HStack(alignment: .top, spacing: 10) {
                Text(viewModel.brewInstallCommands)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(viewModel.brewInstallCommands, forType: .string)
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(PrimaryActionStyle(filled: false))
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Toggle("Include optional tools (reaver)", isOn: $viewModel.includeOptional)
                .toggleStyle(.checkbox)

            if SetupManager.isAppleSilicon() {
                Toggle("Build aircrack-ng from source", isOn: $viewModel.buildFromSource)
                    .toggleStyle(.checkbox)
                    .help("Required on Apple Silicon: there is no bottle. Slow but necessary for deauth and WPS.")
            }

            Spacer()

            Button {
                Task { await viewModel.refresh() }
            } label: {
                Label("Check again", systemImage: "arrow.clockwise")
            }
            .buttonStyle(PrimaryActionStyle(filled: false))
            .disabled(viewModel.isInstalling)

            if viewModel.isInstalling {
                Button {
                    Task { await viewModel.cancel() }
                } label: {
                    Label("Cancel install", systemImage: "stop.fill")
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.danger, filled: false))
            }

            if !viewModel.report.hasBrew {
                Button {
                    Task { await viewModel.installHomebrew() }
                } label: {
                    Label("Install Homebrew", systemImage: "shippingbox")
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.warning))
                .disabled(viewModel.isInstalling)
            }

            Button {
                Task {
                    await viewModel.install()
                    await app.checkTools()
                }
            } label: {
                Label("Install missing tools", systemImage: "arrow.down.circle")
            }
            .buttonStyle(PrimaryActionStyle(tint: Theme.accent))
            .disabled(!viewModel.canInstall)
            .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }
}
