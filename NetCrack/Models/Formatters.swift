import Foundation

/// Presentation helpers shared by views and view models. Kept free of SwiftUI
/// so the models stay testable.
enum Formatters {
    // MARK: - Time

    static func clock(_ seconds: TimeInterval) -> String {
        guard seconds.isFinite, seconds >= 0 else { return "00:00:00" }
        let total = Int(seconds.rounded(.down))
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, secs)
    }

    static func shortClock(_ seconds: TimeInterval) -> String {
        guard seconds.isFinite, seconds >= 0 else { return "0:00" }
        let total = Int(seconds.rounded(.down))
        let minutes = total / 60
        let secs = total % 60
        return String(format: "%d:%02d", minutes, secs)
    }

    static func duration(_ seconds: TimeInterval) -> String {
        guard seconds.isFinite, seconds > 0 else { return "—" }
        if seconds < 60 { return String(format: "%.1f s", seconds) }
        return clock(seconds)
    }

    static func eta(_ seconds: Double?) -> String {
        guard let seconds, seconds.isFinite, seconds >= 0 else { return "—" }
        if seconds < 60 { return String(format: "%.0f s", seconds) }
        if seconds < 3600 { return String(format: "%.0f min", seconds / 60) }
        if seconds < 86_400 { return String(format: "%.1f h", seconds / 3600) }
        return String(format: "%.1f d", seconds / 86_400)
    }

    /// Accepts "00:00:12" and "12" (seconds) and returns seconds.
    static func parseClockDuration(_ text: String) -> Double? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: ":").map(String.init)
        if parts.count == 1 { return Double(parts[0]) }
        guard parts.count <= 3 else { return nil }
        var seconds = 0.0
        for part in parts {
            guard let value = Double(part) else { return nil }
            seconds = seconds * 60 + value
        }
        return seconds
    }

    // MARK: - Speed

    static func speed(_ value: Double) -> String {
        guard value.isFinite, value > 0 else { return "—" }
        let units: [(threshold: Double, suffix: String)] = [
            (1_000_000_000, "GH/s"),
            (1_000_000, "MH/s"),
            (1_000, "kH/s")
        ]
        for unit in units where value >= unit.threshold {
            return String(format: "%.2f %@", value / unit.threshold, unit.suffix)
        }
        return String(format: "%.0f H/s", value)
    }

    /// Hashcat reports "1234.5 kH/s", "1.2 MH/s" and plain "950 H/s".
    static func parseSpeed(_ text: String) -> Double? {
        let cleaned = text
            .trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: ",", with: "")
        guard let match = firstNumber(in: cleaned), let value = Double(match) else { return nil }
        let lower = cleaned.lowercased()
        if lower.contains("gh/s") || lower.contains("ghz") { return value * 1_000_000_000 }
        if lower.contains("mh/s") || lower.contains("mhz") { return value * 1_000_000 }
        if lower.contains("kh/s") || lower.contains("khz") { return value * 1_000 }
        return value
    }

    private static func firstNumber(in text: String) -> String? {
        var digits = ""
        var started = false
        for character in text {
            if character.isNumber || character == "." {
                digits.append(character)
                started = true
            } else if started {
                break
            }
        }
        return digits.isEmpty ? nil : digits
    }

    static func percent(_ value: Double?) -> String {
        guard let value, value.isFinite else { return "—" }
        return String(format: "%.1f%%", value)
    }

    static func compactNumber(_ value: Double?) -> String {
        guard let value, value.isFinite else { return "—" }
        switch value {
        case 1_000_000_000...:
            return String(format: "%.2fB", value / 1_000_000_000)
        case 1_000_000...:
            return String(format: "%.2fM", value / 1_000_000)
        case 1_000...:
            return String(format: "%.1fk", value / 1_000)
        default:
            return String(format: "%.0f", value)
        }
    }

    static func integer(_ value: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }

    // MARK: - Data

    static func bytes(_ count: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(count)
        var index = 0
        while value >= 1024 && index < units.count - 1 {
            value /= 1024
            index += 1
        }
        if index == 0 { return "\(Int(value)) B" }
        return String(format: "%.1f %@", value, units[index])
    }

    static func fileSize(at url: URL) -> UInt64 {
        let values = try? url.resourceValues(forKeys: [.fileSizeKey])
        return UInt64(values?.fileSize ?? 0)
    }

    // MARK: - Masks

    /// Expands `?d?d?l` style masks into a candidate count. Only the
    /// unambiguous built-ins are counted; custom sets return nil.
    static func maskKeyspace(_ mask: String) -> Double? {
        guard !mask.isEmpty else { return nil }
        var total = 1.0
        var index = mask.startIndex
        while index < mask.endIndex {
            let character = mask[index]
            if character == "?" {
                let next = mask.index(after: index)
                guard next < mask.endIndex else { return nil }
                let token = mask[next]
                let size: Int
                switch token {
                case "d": size = 10
                case "l": size = 26
                case "u": size = 26
                case "s": size = 33
                case "a": size = 95
                case "b": size = 256
                case "?": size = 1
                case "1": return nil
                case "2": return nil
                case "3": return nil
                case "4": return nil
                case "h": size = 16
                case "H": size = 16
                default: return nil
                }
                total *= Double(size)
                index = mask.index(after: next)
            } else if character == "\\" {
                let next = mask.index(after: index)
                index = next < mask.endIndex ? mask.index(after: next) : next
            } else {
                index = mask.index(after: index)
            }
        }
        return total
    }

    /// The typical "unknown 8 hex" WPA password space: 16^8 = 4.3 billion.
    static let eightHexKeyspace: Double = pow(16, 8)

    // MARK: - Text

    static func hexToString(_ hex: String) -> String? {
        let cleaned = hex.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: ":", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// File names cannot contain "/" and we want a stable, human-readable
    /// per-target file name without shell metacharacters.
    static func safeFileName(_ input: String, fallback: String = "capture") -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let mapped = input.unicodeScalars.map { scalar -> Character in
            allowed.contains(scalar) ? Character(scalar) : "-"
        }
        var name = String(mapped)
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        // Collapse runs of dashes produced by spaces or punctuation.
        while name.contains("--") {
            name = name.replacingOccurrences(of: "--", with: "-")
        }
        if name.isEmpty { return fallback }
        return String(name.prefix(60))
    }

    static func timestamp(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }

    /// "a1:b2:c3..." -> "A1B2C3..." for the 22000 format.
    static func compactMAC(_ mac: String) -> String {
        mac.replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
            .uppercased()
    }

    /// Shell-quotes a path for the `do shell script` command line.
    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
