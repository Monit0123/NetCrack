import SwiftUI

/// One place for colours, type and card styling so the panes look related.
enum Theme {
    static let accent = Color(red: 0.22, green: 0.80, blue: 0.72)
    static let accentDeep = Color(red: 0.10, green: 0.55, blue: 0.50)
    static let success = Color(red: 0.36, green: 0.83, blue: 0.53)
    static let warning = Color(red: 0.98, green: 0.68, blue: 0.25)
    static let danger = Color(red: 0.95, green: 0.36, blue: 0.38)
    static let info = Color(red: 0.45, green: 0.66, blue: 1.0)
    static let violet = Color(red: 0.66, green: 0.56, blue: 1.0)

    static let cornerRadius: CGFloat = 14
    static let mono = Font.system(size: 11.5, design: .monospaced)
    static let monoSmall = Font.system(size: 10.5, design: .monospaced)
    static let monoLarge = Font.system(size: 30, weight: .semibold, design: .monospaced)

    static let sidebarWidth: CGFloat = 214

    static func color(for security: AccessPoint.Security) -> Color {
        switch security {
        case .open: return .secondary
        case .owe: return Theme.info
        case .wep: return Theme.warning
        case .wpa: return Theme.warning
        case .wpa2: return Theme.accent
        case .wpa3: return Theme.success
        case .wpa2wpa3: return Theme.violet
        case .enterprise: return Theme.danger
        case .unknown: return .secondary
        }
    }

    static func color(for kind: LogLine.Kind) -> Color {
        switch kind {
        case .info: return .secondary
        case .command: return Theme.violet
        case .output: return .primary
        case .warning: return Theme.warning
        case .error: return Theme.danger
        case .success: return Theme.success
        case .progress: return Theme.info
        case .system: return Theme.accent
        }
    }

    static func color(for status: CaptureStatus) -> Color {
        switch status {
        case .idle: return .secondary
        case .starting: return Theme.info
        case .capturing: return Theme.accent
        case .handshakeFound: return Theme.success
        case .pmkidFound: return Theme.violet
        case .noSignal: return Theme.warning
        case .failed: return Theme.danger
        }
    }

    static func color(for status: PipelineResult.Status) -> Color {
        switch status {
        case .recovered, .keychain: return Theme.success
        case .exhausted, .noHandshake: return Theme.warning
        case .skipped: return .secondary
        case .failed: return Theme.danger
        case .cancelled: return .secondary
        }
    }
}

/// Rounded card used throughout the panes.
struct Card<Content: View>: View {
    var title: String?
    var systemImage: String?
    var tint: Color
    var padding: CGFloat
    private let content: () -> Content

    init(
        title: String? = nil,
        systemImage: String? = nil,
        tint: Color = Theme.accent,
        padding: CGFloat = 16,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self.systemImage = systemImage
        self.tint = tint
        self.padding = padding
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let title {
                HStack(spacing: 8) {
                    if let systemImage {
                        Image(systemName: systemImage)
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(tint)
                    }
                    Text(title.uppercased())
                        .font(.system(size: 10.5, weight: .semibold))
                        .kerning(1.1)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                }
            }
            content()
        }
        .padding(padding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
        )
    }
}

/// Page-level heading with optional trailing controls.
struct PaneHeader<Trailing: View>: View {
    var title: String
    var subtitle: String
    var systemImage: String
    private let trailing: () -> Trailing

    init(
        title: String,
        subtitle: String,
        systemImage: String,
        @ViewBuilder trailing: @escaping () -> Trailing
    ) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.trailing = trailing
    }

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [Theme.accent.opacity(0.28), Theme.accentDeep.opacity(0.18)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                Image(systemName: systemImage)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Theme.accent)
            }
            .frame(width: 40, height: 40)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 22, weight: .semibold, design: .rounded))
                Text(subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            trailing()
        }
    }
}

extension PaneHeader where Trailing == EmptyView {
    init(title: String, subtitle: String, systemImage: String) {
        self.init(title: title, subtitle: subtitle, systemImage: systemImage) { EmptyView() }
    }
}

/// Small uppercase caption with a monospaced value.
struct InfoRow: View {
    var label: String
    var value: String
    var monospaced: Bool
    var tint: Color?

    init(label: String, value: String, monospaced: Bool = true, tint: Color? = nil) {
        self.label = label
        self.value = value
        self.monospaced = monospaced
        self.tint = tint
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label.uppercased())
                .font(.system(size: 9.5, weight: .semibold))
                .kerning(0.8)
                .foregroundStyle(.tertiary)
                .frame(width: 108, alignment: .leading)
            Text(value)
                .font(monospaced ? Theme.mono : .system(size: 12))
                .foregroundStyle(tint ?? .primary)
                .textSelection(.enabled)
                .lineLimit(3)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
    }
}

struct MetricTile: View {
    var label: String
    var value: String
    var caption: String?
    var tint: Color
    var systemImage: String?

    init(
        label: String,
        value: String,
        caption: String? = nil,
        tint: Color = Theme.accent,
        systemImage: String? = nil
    ) {
        self.label = label
        self.value = value
        self.caption = caption
        self.tint = tint
        self.systemImage = systemImage
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                if let systemImage {
                    Image(systemName: systemImage)
                        .font(.system(size: 9, weight: .bold))
                }
                Text(label.uppercased())
                    .font(.system(size: 9.5, weight: .semibold))
                    .kerning(0.9)
            }
            .foregroundStyle(tint)
            Text(value)
                .font(.system(size: 20, weight: .semibold, design: .rounded))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            if let caption {
                Text(caption)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(tint.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(tint.opacity(0.18), lineWidth: 1)
        )
    }
}

/// Dismissible explanatory banner.
struct NoticeBanner: View {
    enum Level {
        case info
        case warning
        case danger
        case success

        var color: Color {
            switch self {
            case .info: return Theme.info
            case .warning: return Theme.warning
            case .danger: return Theme.danger
            case .success: return Theme.success
            }
        }

        var symbol: String {
            switch self {
            case .info: return "info.circle.fill"
            case .warning: return "exclamationmark.triangle.fill"
            case .danger: return "xmark.octagon.fill"
            case .success: return "checkmark.circle.fill"
            }
        }
    }

    var level: Level
    var title: String
    var message: String
    var actionTitle: String?
    var action: (() -> Void)?

    init(
        level: Level,
        title: String,
        message: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil
    ) {
        self.level = level
        self.title = title
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: level.symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(level.color)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                Text(message)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.link)
                    .font(.system(size: 11.5, weight: .semibold))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(level.color.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(level.color.opacity(0.22), lineWidth: 1)
        )
    }
}

extension View {
    /// Consistent page padding for the detail panes.
    func panePadding() -> some View {
        padding(.horizontal, 24).padding(.vertical, 20)
    }
}

/// A labelled button used for the primary actions on each pane.
struct PrimaryActionStyle: ButtonStyle {
    var tint: Color = Theme.accent
    var filled: Bool = true

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12.5, weight: .semibold))
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(filled ? tint.opacity(configuration.isPressed ? 0.75 : 1.0) : tint.opacity(0.10))
            )
            .foregroundStyle(filled ? Color.black.opacity(0.82) : tint)
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(filled ? Color.clear : tint.opacity(0.35), lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}
