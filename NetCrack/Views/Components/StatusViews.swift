import SwiftUI

/// The big status pill on the Capture pane.
struct StatusPill: View {
    var status: CaptureStatus

    private var color: Color { Theme.color(for: status) }

    var body: some View {
        HStack(spacing: 9) {
            Circle()
                .fill(color)
                .frame(width: 9, height: 9)
                .overlay(
                    Circle()
                        .stroke(color.opacity(0.4), lineWidth: 5)
                        .scaleEffect(status.isCapturing ? 1.5 : 1.0)
                        .opacity(status.isCapturing ? 0.0 : 0.6)
                )
                .shadow(color: color.opacity(status.isCapturing ? 0.7 : 0), radius: 6)
            Text(status.title.uppercased())
                .font(.system(size: 11.5, weight: .bold))
                .kerning(1.0)
                .foregroundStyle(color)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 7)
        .background(
            Capsule(style: .continuous)
                .fill(color.opacity(0.12))
        )
        .overlay(
            Capsule(style: .continuous)
                .strokeBorder(color.opacity(0.35), lineWidth: 1)
        )
    }
}

/// Four bars plus the dBm reading.
struct SignalBars: View {
    var rssi: Int
    var activeBars: Int
    var color: Color

    init(rssi: Int) {
        self.rssi = rssi
        let bars: Int
        switch rssi {
        case _ where rssi >= -55: bars = 4
        case _ where rssi >= -67: bars = 3
        case _ where rssi >= -76: bars = 2
        case _ where rssi >= -86: bars = 1
        default: bars = 0
        }
        self.activeBars = bars
        switch bars {
        case 4: self.color = Theme.success
        case 3: self.color = Theme.accent
        case 2: self.color = Theme.warning
        default: self.color = Theme.danger
        }
    }

    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<4, id: \.self) { index in
                RoundedRectangle(cornerRadius: 1, style: .continuous)
                    .fill(index < activeBars ? color : Color.secondary.opacity(0.22))
                    .frame(width: 3, height: CGFloat(4 + index * 3))
            }
        }
        .frame(height: 13, alignment: .bottom)
    }
}

struct SignalCell: View {
    var accessPoint: AccessPoint

    var body: some View {
        HStack(spacing: 6) {
            SignalBars(rssi: accessPoint.rssi)
            Text("\(accessPoint.rssi) dBm")
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}

struct SecurityBadge: View {
    var security: AccessPoint.Security
    var compact: Bool

    init(security: AccessPoint.Security, compact: Bool = false) {
        self.security = security
        self.compact = compact
    }

    private var color: Color { Theme.color(for: security) }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 8.5, weight: .bold))
            if !compact {
                Text(security.shortCode)
                    .font(.system(size: 9.5, weight: .bold))
                    .kerning(0.4)
            }
        }
        .foregroundStyle(color)
        .padding(.horizontal, compact ? 5 : 7)
        .padding(.vertical, 3)
        .background(Capsule().fill(color.opacity(0.12)))
        .overlay(Capsule().strokeBorder(color.opacity(0.3), lineWidth: 0.8))
        .help(security.rawValue)
    }

    private var icon: String {
        switch security {
        case .open, .owe: return "lock.open"
        case .enterprise: return "building.2"
        default: return "lock.fill"
        }
    }
}

/// The recovered key, shown as large as it deserves.
struct KeyReveal: View {
    var key: String
    var label: String
    var subtitle: String?
    var onCopy: () -> Void

    init(
        key: String,
        label: String = "Recovered key",
        subtitle: String? = nil,
        onCopy: @escaping () -> Void
    ) {
        self.key = key
        self.label = label
        self.subtitle = subtitle
        self.onCopy = onCopy
    }

    @State private var revealed = true
    @State private var didCopy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "key.fill")
                    .foregroundStyle(Theme.success)
                Text(label.uppercased())
                    .font(.system(size: 10, weight: .bold))
                    .kerning(1.1)
                    .foregroundStyle(Theme.success)
                Spacer()
                Button {
                    revealed.toggle()
                } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(revealed ? "Hide the key" : "Show the key")
            }

            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(revealed ? key : String(repeating: "•", count: min(key.count, 24)))
                    .font(.system(size: key.count > 28 ? 22 : 30, weight: .bold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                    .lineLimit(2)
                    .minimumScaleFactor(0.5)
                    .blur(radius: revealed ? 0 : 5)
                Spacer(minLength: 0)
                Button {
                    onCopy()
                    didCopy = true
                    Task {
                        try? await Task.sleep(nanoseconds: 1_400_000_000)
                        didCopy = false
                    }
                } label: {
                    Label(didCopy ? "Copied" : "Copy", systemImage: didCopy ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                .buttonStyle(PrimaryActionStyle(tint: Theme.success, filled: false))
            }

            if let subtitle {
                Text(subtitle)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [Theme.success.opacity(0.16), Theme.accent.opacity(0.06)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(Theme.success.opacity(0.35), lineWidth: 1)
        )
    }
}

/// A tiny chip used for hashes and metadata.
struct Chip: View {
    var text: String
    var systemImage: String?
    var color: Color

    init(text: String, systemImage: String? = nil, color: Color = Theme.accent) {
        self.text = text
        self.systemImage = systemImage
        self.color = color
    }

    var body: some View {
        HStack(spacing: 4) {
            if let systemImage {
                Image(systemName: systemImage).font(.system(size: 8.5, weight: .bold))
            }
            Text(text)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Capsule().fill(color.opacity(0.10)))
        .overlay(Capsule().strokeBorder(color.opacity(0.25), lineWidth: 0.8))
    }
}
