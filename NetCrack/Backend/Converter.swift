import Foundation

/// Turns a raw 802.11 pcap into something a cracker understands.
///
/// Primary path: `hcxpcapngtool -o out.22000 in.pcap`, which emits modern
/// 22000 lines that carry both PMKID and EAPOL hashes.
/// Fallback path: `aircrack-ng -J` producing a legacy hccapx file that hashcat
/// still cracks in mode 2500. Both are reported honestly; a pcap without a
/// handshake is a *result*, not an error.
actor Converter {
    static let shared = Converter()

    enum HashFormat: String, Sendable, Equatable {
        case p22000 = "22000"
        case hccapx = "hccapx"

        var hashcatMode: String {
            switch self {
            case .p22000: return "22000"
            case .hccapx: return "2500"
            }
        }

        var displayName: String {
            switch self {
            case .p22000: return "hashcat 22000 (PMKID + EAPOL)"
            case .hccapx: return "aircrack hccapx (legacy, hashcat -m 2500)"
            }
        }
    }

    struct ConversionResult: Sendable {
        var hashes: [CaptureHash]
        var hashCount: Int
        var format: HashFormat
        var hashFile: URL?
        var tool: String
        var rawOutput: String
        var notes: [String]

        var isEmpty: Bool { hashCount == 0 }

        var eapolCount: Int { hashes.filter { $0.kind == .eapol }.count }

        var pmkidCount: Int { hashes.filter { $0.kind == .pmkid }.count }

        var statusLine: String {
            if isEmpty {
                return "No handshake yet — keep capturing."
            }
            var parts: [String] = []
            if pmkidCount > 0 { parts.append("\(pmkidCount) PMKID") }
            if eapolCount > 0 { parts.append("\(eapolCount) EAPOL") }
            if parts.isEmpty { parts.append("\(hashCount) hash") }
            return parts.joined(separator: " · ")
        }

        static func empty(format: HashFormat, note: String) -> ConversionResult {
            ConversionResult(
                hashes: [],
                hashCount: 0,
                format: format,
                hashFile: nil,
                tool: "—",
                rawOutput: "",
                notes: [note]
            )
        }
    }

    private let runner = ProcessRunner()

    /// Converts `pcap` into hashes.
    ///
    /// - Parameters:
    ///   - copyWhileWriting: true when the pcap is still being appended to by
    ///     tcpdump. The file is copied first so a partial final record cannot
    ///     derail the converter.
    ///   - destination: preferred output path (`.22000`).
    func convert(
        pcap: URL,
        destination: URL,
        copyWhileWriting: Bool = false
    ) async throws -> ConversionResult {
        guard FileManager.default.fileExists(atPath: pcap.path) else {
            throw NetCrackError.hashFileMissing(pcap.path)
        }

        var workingPcap = pcap
        var temporaryCopy: URL?
        if copyWhileWriting {
            let copy = FileManager.default.temporaryDirectory
                .appendingPathComponent("netcrack-\(UUID().uuidString).pcap")
            do {
                try FileManager.default.copyItem(at: pcap, to: copy)
                workingPcap = copy
                temporaryCopy = copy
            } catch {
                // Copying can fail if the root-owned pcap is still 0600 for a
                // fraction of a second; the original is good enough to read.
                workingPcap = pcap
            }
        }
        defer {
            if let temporaryCopy { try? FileManager.default.removeItem(at: temporaryCopy) }
        }

        var notes: [String] = []
        if let hcxTool = await ToolLocator.shared.executablePath(for: .hcxpcapngtool) {
            do {
                let result = try await convertWithHcxtools(
                    tool: hcxTool,
                    pcap: workingPcap,
                    destination: destination
                )
                return result
            } catch let error as NetCrackError {
                notes.append("hcxpcapngtool: \(error.errorDescription ?? "failed")")
            } catch {
                notes.append("hcxpcapngtool: \(error.localizedDescription)")
            }
        } else {
            notes.append("hcxpcapngtool is not installed.")
        }

        if let aircrack = await ToolLocator.shared.executablePath(for: .aircrack) {
            var result = try await convertWithAircrack(tool: aircrack, pcap: workingPcap, destination: destination)
            result.notes.insert(contentsOf: notes, at: 0)
            if result.isEmpty {
                result.notes.append("aircrack-ng found no handshake in this capture.")
            }
            return result
        }

        notes.append("aircrack-ng is not installed either.")
        throw NetCrackError.other(
            "Cannot convert the capture: hcxpcapngtool and aircrack-ng are both unavailable. Install them from the Setup pane.\n"
            + notes.joined(separator: "\n")
        )
    }

    // MARK: - hcxtools

    private func convertWithHcxtools(tool: String, pcap: URL, destination: URL) async throws -> ConversionResult {
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let command = ProcessRunner.Command(
            executable: tool,
            arguments: ["-o", destination.path, pcap.path]
        )
        let result = try await runner.run(command, timeout: 180)

        var hashes: [CaptureHash] = []
        if FileManager.default.fileExists(atPath: destination.path),
           let contents = try? String(contentsOf: destination, encoding: .utf8) {
            var seen = Set<String>()
            for line in contents.split(separator: "\n") {
                if let hash = CaptureLineParser.parseHashLine(String(line)), seen.insert(hash.raw).inserted {
                    hashes.append(hash)
                }
            }
        }

        let combined = result.combined
        let lower = combined.lowercased()
        let benignFailure = lower.contains("no eapol")
            || lower.contains("no pmkid")
            || lower.contains("no packets")
            || lower.contains("empty")
            || lower.contains("nothing to do")

        if hashes.isEmpty {
            if result.exitCode != 0 && !benignFailure {
                throw NetCrackError.converterFailed(code: result.exitCode, output: combined)
            }
            return ConversionResult(
                hashes: [],
                hashCount: 0,
                format: .p22000,
                hashFile: nil,
                tool: tool,
                rawOutput: combined,
                notes: ["hcxpcapngtool wrote no hashes: no handshake yet — keep capturing."]
            )
        }

        // hcxtools sorts by best quality; keep PMKID first for display.
        hashes.sort { lhs, rhs in
            if lhs.kind.sortIndex != rhs.kind.sortIndex { return lhs.kind.sortIndex < rhs.kind.sortIndex }
            return lhs.ssid < rhs.ssid
        }

        return ConversionResult(
            hashes: hashes,
            hashCount: hashes.count,
            format: .p22000,
            hashFile: destination,
            tool: tool,
            rawOutput: combined,
            notes: []
        )
    }

    // MARK: - aircrack-ng

    private func convertWithAircrack(tool: String, pcap: URL, destination: URL) async throws -> ConversionResult {
        let directory = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let base = directory.appendingPathComponent("netcrack-\(UUID().uuidString.prefix(8))")
        let expected = URL(fileURLWithPath: base.path + ".hccapx")
        try? FileManager.default.removeItem(at: expected)

        let command = ProcessRunner.Command(
            executable: tool,
            arguments: ["-J", base.path, pcap.path]
        )
        let result = try await runner.run(command, timeout: 180)
        let combined = result.combined
        let lower = combined.lowercased()

        // aircrack-ng exits 0 with "No handshakes found" when the capture has
        // nothing usable; that is not an error for us.
        let noHandshake = lower.contains("no handshake") || lower.contains("0 handshake")
        if noHandshake || !FileManager.default.fileExists(atPath: expected.path) {
            if result.exitCode != 0 && !noHandshake {
                throw NetCrackError.converterFailed(code: result.exitCode, output: combined)
            }
            return ConversionResult(
                hashes: [],
                hashCount: 0,
                format: .hccapx,
                hashFile: nil,
                tool: tool,
                rawOutput: combined,
                notes: ["aircrack-ng found no handshake yet — keep capturing."]
            )
        }

        // One hccapx record is exactly 393 bytes.
        let size = Formatters.fileSize(at: expected)
        let count = max(1, Int(size / 393))
        let hashes = (0..<count).map { index in
            CaptureHash(
                typeCode: "2500",
                kind: .eapol,
                mic: "",
                accessPoint: "",
                client: "",
                ssid: "",
                raw: "hccapx:\(expected.lastPathComponent)#\(index)"
            )
        }

        return ConversionResult(
            hashes: hashes,
            hashCount: count,
            format: .hccapx,
            hashFile: expected,
            tool: tool,
            rawOutput: combined,
            notes: ["hcxpcapngtool is unavailable, so this capture uses the legacy hccapx format (no PMKID support)."]
        )
    }

    // MARK: - Helpers

    /// Writes a filtered hash file. Used to crack exactly one target's hashes
    /// even when a capture contains several networks.
    nonisolated static func writeHashes(_ hashes: [CaptureHash], to url: URL) throws {
        let text = hashes.map(\.raw).joined(separator: "\n") + "\n"
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    nonisolated static func hashes(_ hashes: [CaptureHash], matching target: AccessPoint?) -> [CaptureHash] {
        guard let target else { return hashes }
        let targetBSSID = target.bssidCompact
        let targetSSID = target.ssid
        let filtered = hashes.filter { hash in
            if !hash.accessPoint.isEmpty && hash.accessPoint == targetBSSID { return true }
            if !hash.ssid.isEmpty && !targetSSID.isEmpty && hash.ssid == targetSSID { return true }
            // Some 22000 lines omit BSSID/SSID entirely; they are still ours.
            return hash.accessPoint.isEmpty && hash.ssid.isEmpty
        }
        return filtered
    }
}
