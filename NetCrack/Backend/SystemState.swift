import Foundation
import CoreGraphics
import IOKit.pwr_mgt

/// Facts about the login session that affect a capture.
enum SessionState {
    /// Monitor mode stops delivering frames when the Mac locks, and the
    /// problem is invisible unless the app says so.
    static func isScreenLocked() -> Bool {
        guard let dictionary = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            return false
        }
        if let locked = dictionary["CGSSessionScreenIsLocked"] as? Bool {
            return locked
        }
        if let locked = dictionary["kCGSSessionOnConsoleKey"] as? Bool {
            return !locked
        }
        return false
    }

    static func consoleUser() -> String? {
        guard let dictionary = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            return nil
        }
        return dictionary["kCGSSessionUserNameKey"] as? String
    }

}

/// Keeps the display (and the radio) awake while a capture runs.
///
/// Using an IOPM assertion rather than `caffeinate(8)` means there is no extra
/// process to clean up, and the assertion disappears with the app even after a
/// crash.
final class PowerAssertion {
    private var assertionID: IOPMAssertionID = 0
    private(set) var isHeld = false

    func acquire(reason: String = "NetCrack is capturing Wi-Fi frames") {
        guard !isHeld else { return }
        var id: IOPMAssertionID = 0
        let type = "PreventUserIdleDisplaySleep" as CFString
        let result = IOPMAssertionCreateWithName(
            type,
            IOPMAssertionLevel(kIOPMAssertionLevelOn),
            reason as CFString,
            &id
        )
        if result == kIOReturnSuccess {
            assertionID = id
            isHeld = true
        }
    }

    func release() {
        guard isHeld else { return }
        IOPMAssertionRelease(assertionID)
        assertionID = 0
        isHeld = false
    }

    deinit {
        if isHeld {
            IOPMAssertionRelease(assertionID)
        }
    }
}

/// Reads the pcap that tcpdump is currently appending to and turns it into
/// frame counters, without needing libpcap or a second tcpdump process.
///
/// Only the bytes that arrived since the last call are parsed, so the cost per
/// poll stays flat even during a long capture.
struct PcapInspector {
    struct Counters: Equatable, Sendable {
        var packets: Int = 0
        var wireBytes: UInt64 = 0
        var beacons: Int = 0
        var management: Int = 0
        var dataFrames: Int = 0
        var eapolFrames: Int = 0
        var clients: [String: Int] = [:]

        var isEmpty: Bool { packets == 0 }
    }

    private var linkType: UInt32?
    private var bigEndianFile = false
    private var parseOffset: UInt64 = 0
    private var headerParsed = false
    private(set) var counters = Counters()

    mutating func reset() {
        linkType = nil
        bigEndianFile = false
        parseOffset = 0
        headerParsed = false
        counters = Counters()
    }

    /// Parses whatever is new in `url` and returns the running totals.
    mutating func ingest(url: URL) -> Counters {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return counters }
        defer { try? handle.close() }

        let fileSize = (try? handle.seekToEnd()) ?? 0
        if fileSize < parseOffset {
            // tcpdump was restarted and rewrote the file.
            reset()
        }

        if !headerParsed {
            guard fileSize >= 24 else { return counters }
            do {
                try handle.seek(toOffset: 0)
                guard let header = try handle.read(upToCount: 24), header.count == 24 else {
                    return counters
                }
                Self.parseGlobalHeader(header, linkType: &linkType, bigEndian: &bigEndianFile)
                headerParsed = true
                parseOffset = 24
            } catch {
                return counters
            }
        }

        guard fileSize > parseOffset else { return counters }
        // Bound the work per poll; the next poll continues where this stopped.
        let maximumChunk: UInt64 = 8 * 1024 * 1024
        let toRead = min(fileSize - parseOffset, maximumChunk)
        do {
            try handle.seek(toOffset: parseOffset)
            guard let data = try handle.read(upToCount: Int(toRead)), !data.isEmpty else {
                return counters
            }
            let consumed = Self.parseRecords(
                data,
                linkType: linkType ?? 105,
                bigEndian: bigEndianFile,
                counters: &counters
            )
            parseOffset += UInt64(consumed)
        } catch {
            return counters
        }
        return counters
    }

    // MARK: - Parsing

    private static func parseGlobalHeader(_ data: Data, linkType: inout UInt32?, bigEndian: inout Bool) {
        let bytes = [UInt8](data.prefix(4))
        if bytes == [0xd4, 0xc3, 0xb2, 0xa1] || bytes == [0x4d, 0x3c, 0xb2, 0xa1] {
            bigEndian = false
        } else if bytes == [0xa1, 0xb2, 0xc3, 0xd4] || bytes == [0xa1, 0xb2, 0x3c, 0x4d] {
            bigEndian = true
        } else {
            bigEndian = false
        }
        linkType = readUInt32(data, at: 20, bigEndian: bigEndian)
    }

    private static func parseRecords(
        _ data: Data,
        linkType: UInt32,
        bigEndian: Bool,
        counters: inout Counters
    ) -> Int {
        let bytes = [UInt8](data)
        var offset = 0
        while offset + 16 <= bytes.count {
            let inclLength = Int(readUInt32(bytes, at: offset + 8, bigEndian: bigEndian))
            let origLength = Int(readUInt32(bytes, at: offset + 12, bigEndian: bigEndian))
            guard inclLength >= 0, inclLength <= 4 * 1024 * 1024 else {
                // Corrupt record: stop here rather than spinning forever.
                return offset
            }
            let recordEnd = offset + 16 + inclLength
            guard recordEnd <= bytes.count else { break }

            counters.packets += 1
            counters.wireBytes += UInt64(max(origLength, inclLength))

            let frameStart = offset + 16
            inspectFrame(
                bytes,
                frameStart: frameStart,
                frameEnd: recordEnd,
                linkType: linkType,
                counters: &counters
            )
            offset = recordEnd
        }
        return offset
    }

    private static func inspectFrame(
        _ bytes: [UInt8],
        frameStart: Int,
        frameEnd: Int,
        linkType: UInt32,
        counters: inout Counters
    ) {
        var headerStart = frameStart
        if linkType == 127 {
            // Radiotap: it_length is the little-endian u16 at offset 2.
            guard frameStart + 4 <= frameEnd else { return }
            let radiotapLength = Int(bytes[frameStart + 2]) | (Int(bytes[frameStart + 3]) << 8)
            headerStart = frameStart + radiotapLength
        } else if linkType != 105 {
            // Ethernet or something else entirely; nothing to classify.
            return
        }
        guard headerStart + 24 <= frameEnd else { return }

        let frameControl = UInt16(bytes[headerStart]) | (UInt16(bytes[headerStart + 1]) << 8)
        let type = (frameControl >> 2) & 0x3
        let subtype = (frameControl >> 4) & 0xF

        switch type {
        case 0:
            counters.management += 1
            if subtype == 8 { counters.beacons += 1 }
        case 2:
            counters.dataFrames += 1
            var headerLength = 24
            let toDS = (frameControl >> 8) & 0x1 == 1
            let fromDS = (frameControl >> 9) & 0x1 == 1
            if toDS && fromDS { headerLength += 6 }
            if subtype & 0x8 != 0 { headerLength += 2 } // QoS data
            let address2Start = headerStart + 10
            if headerStart + headerLength <= frameEnd {
                let transmitter = macString(bytes, at: address2Start)
                if !transmitter.isEmpty, !isMulticast(bytes, at: address2Start) {
                    counters.clients[transmitter, default: 0] += 1
                }
            }
            let llcStart = headerStart + headerLength
            if llcStart + 8 <= frameEnd {
                if bytes[llcStart] == 0xAA, bytes[llcStart + 1] == 0xAA, bytes[llcStart + 2] == 0x03,
                   bytes[llcStart + 6] == 0x88, bytes[llcStart + 7] == 0x8E {
                    counters.eapolFrames += 1
                }
            }
        default:
            break
        }
    }

    private static func macString(_ bytes: [UInt8], at offset: Int) -> String {
        guard offset + 6 <= bytes.count else { return "" }
        return (0..<6).map { String(format: "%02x", bytes[offset + $0]) }.joined(separator: ":")
    }

    private static func isMulticast(_ bytes: [UInt8], at offset: Int) -> Bool {
        guard offset < bytes.count else { return false }
        return bytes[offset] & 0x01 == 1
    }

    private static func readUInt32(_ data: Data, at offset: Int, bigEndian: Bool) -> UInt32 {
        readUInt32([UInt8](data), at: offset, bigEndian: bigEndian)
    }

    private static func readUInt32(_ bytes: [UInt8], at offset: Int, bigEndian: Bool) -> UInt32 {
        guard offset + 4 <= bytes.count else { return 0 }
        let b0 = UInt32(bytes[offset])
        let b1 = UInt32(bytes[offset + 1])
        let b2 = UInt32(bytes[offset + 2])
        let b3 = UInt32(bytes[offset + 3])
        if bigEndian {
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }
        return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
    }
}
