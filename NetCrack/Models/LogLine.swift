import Foundation

/// One line of process output, ready for display in a console view.
///
/// Raw tool output (hashcat, tcpdump, reaver, brew) is full of carriage
/// returns and ANSI colour escapes. Everything that reaches `LogLine` is
/// normalised here so the UI never has to think about it.
struct LogLine: Identifiable, Hashable, Sendable {
    enum Kind: String, Hashable, Sendable {
        /// Neutral narration produced by NetCrack itself.
        case info
        /// The command line that is about to run.
        case command
        /// Verbatim tool output.
        case output
        /// Something the user should look at but which is not fatal.
        case warning
        /// A hard failure.
        case error
        /// A positive result (key recovered, handshake captured).
        case success
        /// Machine generated progress (hashcat status, aircrack counters).
        case progress
        /// Lifecycle notes: started, stopped, exited.
        case system
    }

    let id: UUID
    let date: Date
    let text: String
    let kind: Kind

    init(_ text: String, kind: Kind = .output, date: Date = Date()) {
        self.id = UUID()
        self.date = date
        self.text = AnsiText.strip(text)
        self.kind = kind
    }

    var timeString: String {
        LogLine.formatter.string(from: date)
    }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss"
        return f
    }()
}

/// Minimal ANSI escape stripper. Tools such as hashcat and brew colour their
/// output even when stdout is a pipe; a `Text` view would render the escapes
/// as visible garbage.
enum AnsiText {
    static func strip(_ input: String) -> String {
        guard input.contains("\u{1B}") else {
            return input.replacingOccurrences(of: "\t", with: "    ")
        }

        var output = String()
        output.reserveCapacity(input.count)

        let scalars = Array(input.unicodeScalars)
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            if scalar == "\u{1B}" {
                index += 1
                guard index < scalars.count else { break }
                let next = scalars[index]
                if next == "[" {
                    // CSI sequence: ESC [ params... final-byte (0x40...0x7E)
                    index += 1
                    while index < scalars.count {
                        let value = scalars[index].value
                        index += 1
                        if value >= 0x40 && value <= 0x7E { break }
                    }
                    continue
                } else if next == "]" {
                    // OSC sequence, terminated by BEL or ST
                    index += 1
                    while index < scalars.count {
                        let value = scalars[index].value
                        index += 1
                        if value == 0x07 { break }
                        if value == 0x1B, index < scalars.count, scalars[index] == "\\" {
                            index += 1
                            break
                        }
                    }
                    continue
                } else {
                    index += 1
                    continue
                }
            }
            if scalar == "\r" {
                index += 1
                continue
            }
            output.unicodeScalars.append(scalar == "\t" ? " " : scalar)
            index += 1
        }
        return output.trimmingCharacters(in: .whitespaces)
    }
}
