import Foundation
import Combine

/// Persisted preferences. Everything the user picks in the UI lands here so a
/// relaunch resumes exactly where they left off.
@MainActor
final class SettingsStore: ObservableObject {
    enum Key: String {
        case lastWordlistPath
        case wordlistHistory
        case captureMode
        case captureChannel
        case externalInterface
        case attackMode
        case mask
        case crackEngine
        case ruleFile
        case lastTargetSSID
        case lastTargetBSSID
        case showAllNetworks
        case keepDisplayAwake
        case autoConvertAfterCapture
        case autoCrackAfterCapture
        case deauthClientMac
        case captureDirectoryPath
        case includeBundledWordlist
        case useRules
        case queueExtrasMask
        case queueExtrasIncremental
    }

    static let bundledWordlistName = "top10k"

    private let defaults: UserDefaults

    @Published var lastWordlistPath: String {
        didSet { defaults.set(lastWordlistPath, forKey: Key.lastWordlistPath.rawValue) }
    }

    @Published var captureMode: CaptureMode {
        didSet { defaults.set(captureMode.rawValue, forKey: Key.captureMode.rawValue) }
    }

    /// 0 means "do not change the adapter's channel".
    @Published var captureChannel: Int {
        didSet { defaults.set(captureChannel, forKey: Key.captureChannel.rawValue) }
    }

    @Published var externalInterface: String {
        didSet { defaults.set(externalInterface, forKey: Key.externalInterface.rawValue) }
    }

    @Published var attackMode: AttackMode {
        didSet { defaults.set(attackMode.rawValue, forKey: Key.attackMode.rawValue) }
    }

    @Published var mask: String {
        didSet { defaults.set(mask, forKey: Key.mask.rawValue) }
    }

    @Published var crackEngine: CrackEngineKind {
        didSet { defaults.set(crackEngine.rawValue, forKey: Key.crackEngine.rawValue) }
    }

    @Published var ruleFile: String {
        didSet { defaults.set(ruleFile, forKey: Key.ruleFile.rawValue) }
    }

    @Published var lastTargetSSID: String {
        didSet { defaults.set(lastTargetSSID, forKey: Key.lastTargetSSID.rawValue) }
    }

    @Published var lastTargetBSSID: String {
        didSet { defaults.set(lastTargetBSSID, forKey: Key.lastTargetBSSID.rawValue) }
    }

    @Published var showAllNetworks: Bool {
        didSet { defaults.set(showAllNetworks, forKey: Key.showAllNetworks.rawValue) }
    }

    @Published var keepDisplayAwake: Bool {
        didSet { defaults.set(keepDisplayAwake, forKey: Key.keepDisplayAwake.rawValue) }
    }

    @Published var autoConvertAfterCapture: Bool {
        didSet { defaults.set(autoConvertAfterCapture, forKey: Key.autoConvertAfterCapture.rawValue) }
    }

    @Published var autoCrackAfterCapture: Bool {
        didSet { defaults.set(autoCrackAfterCapture, forKey: Key.autoCrackAfterCapture.rawValue) }
    }

    @Published var deauthClientMac: String {
        didSet { defaults.set(deauthClientMac, forKey: Key.deauthClientMac.rawValue) }
    }

    @Published var captureDirectoryPath: String {
        didSet { defaults.set(captureDirectoryPath, forKey: Key.captureDirectoryPath.rawValue) }
    }

    @Published var includeBundledWordlist: Bool {
        didSet { defaults.set(includeBundledWordlist, forKey: Key.includeBundledWordlist.rawValue) }
    }

    @Published var queueExtrasMask: Bool {
        didSet { defaults.set(queueExtrasMask, forKey: Key.queueExtrasMask.rawValue) }
    }

    @Published var queueExtrasIncremental: Bool {
        didSet { defaults.set(queueExtrasIncremental, forKey: Key.queueExtrasIncremental.rawValue) }
    }

    @Published private(set) var wordlistHistory: [String] {
        didSet { defaults.set(wordlistHistory, forKey: Key.wordlistHistory.rawValue) }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults

        lastWordlistPath = defaults.string(forKey: Key.lastWordlistPath.rawValue) ?? ""
        captureMode = CaptureMode(rawValue: defaults.string(forKey: Key.captureMode.rawValue) ?? "") ?? .builtin
        captureChannel = defaults.object(forKey: Key.captureChannel.rawValue) as? Int ?? 0
        externalInterface = defaults.string(forKey: Key.externalInterface.rawValue) ?? ""
        attackMode = AttackMode(rawValue: defaults.string(forKey: Key.attackMode.rawValue) ?? "") ?? .dictionary
        mask = defaults.string(forKey: Key.mask.rawValue) ?? "?d?d?d?d?d?d?d?d"
        crackEngine = CrackEngineKind(rawValue: defaults.string(forKey: Key.crackEngine.rawValue) ?? "") ?? .hashcat
        ruleFile = defaults.string(forKey: Key.ruleFile.rawValue) ?? "best64.rule"
        lastTargetSSID = defaults.string(forKey: Key.lastTargetSSID.rawValue) ?? ""
        lastTargetBSSID = defaults.string(forKey: Key.lastTargetBSSID.rawValue) ?? ""
        showAllNetworks = defaults.object(forKey: Key.showAllNetworks.rawValue) as? Bool ?? true
        keepDisplayAwake = defaults.object(forKey: Key.keepDisplayAwake.rawValue) as? Bool ?? true
        autoConvertAfterCapture = defaults.object(forKey: Key.autoConvertAfterCapture.rawValue) as? Bool ?? true
        autoCrackAfterCapture = defaults.object(forKey: Key.autoCrackAfterCapture.rawValue) as? Bool ?? false
        deauthClientMac = defaults.string(forKey: Key.deauthClientMac.rawValue) ?? ""
        captureDirectoryPath = defaults.string(forKey: Key.captureDirectoryPath.rawValue)
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("NetCrack", isDirectory: true).path
        includeBundledWordlist = defaults.object(forKey: Key.includeBundledWordlist.rawValue) as? Bool ?? true
        queueExtrasMask = defaults.object(forKey: Key.queueExtrasMask.rawValue) as? Bool ?? true
        queueExtrasIncremental = defaults.object(forKey: Key.queueExtrasIncremental.rawValue) as? Bool ?? false
        wordlistHistory = defaults.stringArray(forKey: Key.wordlistHistory.rawValue) ?? []
    }

    // MARK: - Derived paths

    var captureDirectory: URL {
        URL(fileURLWithPath: captureDirectoryPath, isDirectory: true)
    }

    var bundledWordlistURL: URL? {
        Bundle.main.url(forResource: Self.bundledWordlistName, withExtension: "txt")
    }

    /// The list the Crack pane will actually use: the user's pick if it is
    /// still readable, otherwise the bundled top-10k.
    var effectiveWordlist: URL? {
        if !lastWordlistPath.isEmpty {
            let url = URL(fileURLWithPath: lastWordlistPath)
            if FileManager.default.isReadableFile(atPath: url.path) { return url }
        }
        return bundledWordlistURL
    }

    var effectiveWordlistIsBundled: Bool {
        guard let effective = effectiveWordlist, let bundled = bundledWordlistURL else { return false }
        return effective.standardizedFileURL == bundled.standardizedFileURL
    }

    // MARK: - Mutations

    func rememberWordlist(_ url: URL) {
        lastWordlistPath = url.path
        var history = wordlistHistory.filter { $0 != url.path }
        history.insert(url.path, at: 0)
        wordlistHistory = Array(history.prefix(10))
    }

    func rememberTarget(_ accessPoint: AccessPoint) {
        lastTargetSSID = accessPoint.ssid
        lastTargetBSSID = accessPoint.bssid
    }

    func ensureCaptureDirectory() throws {
        let url = captureDirectory
        if !FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
    }

    var ruleFilePath: String? {
        let trimmed = ruleFile.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.contains("/") { return trimmed }
        // Bare names resolve against hashcat's rules directory.
        let candidates = [
            "/opt/homebrew/share/hashcat/rules/\(trimmed)",
            "/usr/local/share/hashcat/rules/\(trimmed)",
            "\(NSHomeDirectory())/hashcat/rules/\(trimmed)"
        ]
        return candidates.first { FileManager.default.fileExists(atPath: $0) } ?? trimmed
    }
}
