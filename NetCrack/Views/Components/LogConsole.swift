import SwiftUI

/// Monospace, auto-scrolling console. Every tool NetCrack drives writes here.
struct LogConsole: View {
    var lines: [LogLine]
    var title: String = "Live log"
    var emptyText: String = "Nothing yet."
    var onClear: (() -> Void)?
    var onCopy: (() -> Void)?

    @State private var follow = true

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Circle()
                    .fill(Theme.accent)
                    .frame(width: 5, height: 5)
                Text(title.uppercased())
                    .font(.system(size: 9.5, weight: .bold))
                    .kerning(1.0)
                    .foregroundStyle(.secondary)
                Text("\(lines.count) lines")
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
                Spacer()
                Toggle("Follow", isOn: $follow)
                    .toggleStyle(.switch)
                    .controlSize(.mini)
                    .labelsHidden()
                    .help("Scroll to the newest line automatically")
                Text("Follow")
                    .font(.system(size: 9.5))
                    .foregroundStyle(.secondary)
                if let onCopy {
                    Button(action: onCopy) {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy the whole log")
                }
                if let onClear {
                    Button(action: onClear) {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .help("Clear the log")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)

            Divider().opacity(0.5)

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        if lines.isEmpty {
                            Text(emptyText)
                                .font(Theme.mono)
                                .foregroundStyle(.tertiary)
                                .padding(.top, 6)
                        }
                        ForEach(lines) { line in
                            HStack(alignment: .top, spacing: 8) {
                                Text(line.timeString)
                                    .font(Theme.monoSmall)
                                    .foregroundStyle(.tertiary)
                                Text(line.text)
                                    .font(Theme.mono)
                                    .foregroundStyle(Theme.color(for: line.kind))
                                    .fixedSize(horizontal: false, vertical: true)
                                    .textSelection(.enabled)
                            }
                            .id(line.id)
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .onChange(of: lines.count) { _, _ in
                    guard follow, let last = lines.last else { return }
                    withAnimation(.easeOut(duration: 0.12)) {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .textBackgroundColor).opacity(0.65))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
        )
    }
}
