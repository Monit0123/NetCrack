# NetCrack

A single-window macOS app that recovers Wi-Fi passwords by every available
means, in order of how fast the means usually is.

NetCrack is a thin SwiftUI GUI over tools that already work: **CoreWLAN** for
scanning, **tcpdump** for monitor-mode capture, **hcxtools** for turning frames
into hashes, **hashcat** for cracking, **aircrack-ng** for deauth/WPS/WEP and
`security(1)` for the passwords macOS has already saved. It deliberately does
**not** reimplement 802.11 crypto in Swift.

```
┌─ Scan ──────┬─ Target ────┬─ Capture ─────────┬─ Crack ───────────────┐
│ nearby APs  │ details     │ tcpdump + counters │ hashcat + key display │
│ CoreWLAN    │ Keychain    │ EAPOL/PMKID detect │ live speed/%/ETA      │
└─────────────┴─────────────┴───────────────────┴───────────────────────┘
```

---

## Read this first (the honest version)

| Claim | Reality in NetCrack |
|---|---|
| "Recover any Wi-Fi password" | True only within what the hardware allows. A WPA2 key is recovered by cracking a captured handshake — that means a dictionary/mask attack. If the passphrase is long and random, no amount of GUI will find it. |
| Built-in Mac radio | Can be put in monitor mode with `sudo tcpdump -I`, but **cannot transmit** there. No deauth, no WPS, no active attacks. Built-in capture is passive: it waits for a handshake that happens anyway. |
| External USB adapter | Unlocks `aireplay-ng` (deauth), `wash` + `reaver` (WPS) and channel pinning. |
| `airport` binary | Deleted by Apple in **macOS 14.4**. Channel locking therefore degrades to "leave the radio on its current channel"; the UI says so instead of pretending. |
| macOS 26 on some Apple Silicon Macs | Monitor mode reports success and delivers **0 frames**. NetCrack detects it and shows a diagnostic; the fix is an external adapter. |
| Open / OWE / 802.1X networks | No PSK exists. The app says so and skips them instead of pretending to try. |
| Legal | Use this on networks you own or have written permission to test. Reading your own network's saved password out of your own Keychain is a feature; doing it to someone else's network is an offence in most jurisdictions. |

---

## Download a prebuilt DMG (no Xcode needed)

The repo builds the app on GitHub's macOS runners and publishes a universal
(Apple Silicon + Intel) disk image, so you do not need a developer account:

**<https://github.com/Monit0123/NetCrack/releases/latest>** → `NetCrack.dmg`

1. Open the DMG and drag **NetCrack** into *Applications*.
2. The build is ad-hoc signed and **not notarised**, so Gatekeeper blocks the
   first launch. Right-click the app → **Open** → **Open**, or use
   **System Settings → Privacy & Security → Open Anyway**.
3. If macOS still refuses (common on macOS 15+ for quarantined downloads):

   ```bash
   xattr -dr com.apple.quarantine /Applications/NetCrack.app
   open /Applications/NetCrack.app
   ```

The same page carries `NetCrack.dmg.sha256`; check it with
`shasum -a 256 NetCrack.dmg`. Every push also uploads the DMG as a workflow
artifact (Actions → *Build DMG* → *NetCrack-dmg*), and `Scripts/make-dmg.sh`
produces the identical layout locally.

---

## Requirements

- macOS **14 Sonoma** … **26 Tahoe** (deployment target 14.0), Apple Silicon or Intel.
- Xcode 15+ (or the Command Line Tools; the project builds with `xcodebuild`).
- Swift 5.9+ (the toolchain that ships with Xcode 15 already is).
- No paid Apple Developer account. The project signs with `CODE_SIGN_IDENTITY = "-"` ("Sign to Run Locally").
- Homebrew + `hashcat`, `hcxtools`, `aircrack-ng` for the cracking paths. **tcpdump is already on every Mac** (`/usr/bin/tcpdump`).

---

## Build & run

### Xcode

```bash
open NetCrack.xcodeproj
```

1. Select the **NetCrack** scheme and the **My Mac** destination.
2. Target → Signing & Capabilities → *Team*: **None**. *Signing Certificate*:
   **Sign to Run Locally**. (That is what the project is already set to; Xcode
   may still show a warning — it builds and runs unsigned/ad-hoc fine.)
3. ⌘R.

The app is intentionally **not sandboxed**: it execs Homebrew binaries, reads
pcaps that root wrote, and asks for administrator rights. There is no Mac App
Store path for this kind of tool. See `NetCrack/Resources/NetCrack.entitlements`.

### Command line

```bash
./Scripts/build.sh run          # Debug, then launch
./Scripts/build.sh release      # Release build into ./build
# or by hand:
xcodebuild -project NetCrack.xcodeproj -scheme NetCrack -configuration Debug \
  -derivedDataPath build CODE_SIGN_IDENTITY="-" build
open build/Build/Products/Debug/NetCrack.app
```

If you copy the built `.app` to another Mac and Gatekeeper objects:

```bash
xattr -dr com.apple.quarantine /Applications/NetCrack.app
```

Build products (`build/`, `DerivedData`, `xcuserdata`) are git-ignored.

---

## Toolchain: exact Homebrew commands

Apple Silicon installs into `/opt/homebrew`, Intel into `/usr/local`; NetCrack
searches both, plus `/usr/bin` and `/usr/sbin`.

```bash
# 1. Homebrew (skip if `brew --version` already works)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Required
brew install hashcat        # cracker, mode 22000 (PMKID/EAPOL)
brew install hcxtools       # hcxpcapngtool + hcxdumptool: pcap -> hash
brew install tcpdump        # optional: macOS ships /usr/bin/tcpdump already

# 3. Required for deauth + WPS + the aircrack engine.
#    aircrack-ng has NO Apple Silicon bottle, so Homebrew compiles it.
#    Expect 5–15 minutes and a busy CPU. This is not a NetCrack bug.
brew install --build-from-source aircrack-ng

# 4. Optional: full WPS PIN brute force (reaver). wash ships with aircrack-ng.
brew install reaver
```

Verify:

```bash
hashcat --version          # v6.2.6 or newer for the 22000 format
hcxpcapngtool --version
aircrack-ng --help | head -3
aircrack-ng --version
tcpdump --version          # /usr/bin/tcpdump is fine
```

In the app: **⌘,** opens **Setup**, which probes every binary, shows the exact
path and version it found, and can run the same installs with streamed output
(`brew install hashcat hcxtools`, then
`brew install --build-from-source aircrack-ng` on Apple Silicon). If Homebrew
is missing it offers to run the official installer, which needs your password
once.

---

## How the administrator prompt works

Capturing needs root. NetCrack asks **exactly once per session**, then reuses
that authorisation for every privileged command.

```
first privileged action
        │
        ▼
osascript -e 'do shell script "…" with administrator privileges'
        │            (one native macOS password dialog)
        ▼
root-side supervisor: ~/Library/Application\ Support/NetCrack/rootsession/
        │   daemon.sh — POSIX sh, writes an `alive` heartbeat every 2 s
        ▼
app drops `<id>.cmd` files into the folder, reads `<id>.out` / `<id>.code`
        │
        └─► tcpdump -I, airport channel lock, aireplay-ng, wash, reaver,
            sudo-capable Homebrew installs — all without another prompt
```

Properties of that design:

- **One prompt.** There is no sudoers edit, no setuid binary, no launch daemon,
  no helper in `/Library/PrivilegedHelperTools`.
- **No password anywhere.** The password never enters NetCrack; `osascript`
  hands it to macOS's own authorisation machinery. Commands run as root, so
  no `sudo -S`, no password on a command line, nothing in shell history.
- **Bounded lifetime.** The supervisor exits after **30 minutes idle** or
  **6 hours total**, and immediately when the app quits (it removes the
  heartbeat, and the app also removes it on termination).
- **User-scoped.** The session folder is `0700` and owned by you; the
  supervisor accepts commands only from files in that folder.
- **Cancellable.** Stopping a capture writes a `<id>.kill` request (SIGINT first,
  so `tcpdump` flushes the pcap and the file stays valid).
- **Revoke now:** quit the app, or `rm ~/Library/Application\ Support/NetCrack/rootsession/alive`.

If you refuse the dialog, nothing is changed and the app says so.

---

## The four panes

### 1. Scan
CoreWLAN (`CWWiFiClient.shared().interface().scanForNetworks(withSSID:)`),
native, no sudo, no `airport` — that binary no longer exists on macOS 14.4+.
Columns: SSID (+OUI vendor hint), BSSID, channel/width, band, security badge,
RSSI with a four-bar visual, PHY. Searchable, sortable, ⌘R to rescan.
Security classification uses the *base* `CWSecurity` modes only, because
`supportsSecurity(.wpa3Transition)` answers "could a profile for this mode join
this AP?" and would label every WPA2 network "WPA2+WPA3".

macOS 14+ hides SSIDs from apps without Location permission, so the app asks
for it once and explains the banner if you decline.

### 2. Target
Everything about the selected AP, the clients observed so far, the captured
hashes for this BSSID, and the **instant win**:

```bash
security find-generic-password -D "AirPort network password" -a "<ssid>" -w
```

If this Mac has ever joined the network, the password is shown immediately,
in large type, copyable. No radio involved. (A second lookup keyed by service
name covers macOS versions that store the item differently.)

### 3. Capture
Start/Stop, live monospace log, big status pill (**Idle / Capturing /
Handshake found / PMKID found / No signal**), running EAPOL and PMKID counters,
elapsed timer, pcap path, frame count, byte count, beacon count.

```
Capture mode:  Built-in (passive)  |  External adapter (active)
Built-in:  sudo tcpdump -i en0 -I -y IEEE802_11 -w capture.pcap -U -n
External:  same tcpdump path on the adapter iface, plus aireplay-ng for deauth
```

While capturing, NetCrack parses the growing pcap itself (only the new bytes on
each poll) to count frames, EAPOL frames, beacons and client MACs, and every
few seconds it runs `hcxpcapngtool -o out.22000 capture.pcap` to see whether a
usable hash has appeared. A hash flips the pill and stops the capture early.

**Deauth is only enabled for an external adapter.** In built-in mode the button
is disabled with a tooltip that explains the radio cannot transmit — there is
no fake deauth button.

### 4. Crack
Wordlist picker (defaults to the bundled **top-10k**, line 621 is `password1`),
attack mode, engine, and live progress:

```
hashcat -m 22000 hash.22000 wordlist -w 3 --status --status-timer=1 \
        --machine-readable --potfile-path …/netcrack.potfile
```

- `-a 0` dictionary
- `-a 0 -r best64.rule` dictionary + rules
- `-a 3 ?d?d?d?d?d?d?d?d` mask
- `-a 3 <mask> -i` incremental (growing masks)

Speed, percentage and ETA are parsed from hashcat's own status stream, the key
is read back with `--show` (authoritative, works even if the run was stopped),
and displayed huge and copyable. `aircrack-ng -w` is available as an alternative
engine (dictionary only, needs the original pcap).

---

## "By any means", in priority order

| # | Method | Where | Notes |
|---|---|---|---|
| 1 | Keychain probe on the current network | Target | Instant, no radio, needs the Mac to have joined before |
| 2 | PMKID/EAPOL → `hashcat -m 22000` dictionary | Capture → Crack | The main path |
| 3 | Same hash → mask / incremental | Crack | For 8-digit and patterned keys |
| 4 | WPS PIN (`wash` + `reaver`, PixieWPS first) | Capture → Try WPS | External adapter only — it must transmit |
| 5 | WEP (`aircrack-ng -a 1`) | Capture → Crack | Legacy, still works when the AP is WEP |
| 6 | WPA3-SAE via hcxtools + `-m 22000` | Capture → Crack | WPA2/WPA3 transition APs still yield a crackable PMKID |
| 7 | Queue mode: N networks, unattended | Scan → Queue… | Walks 1→5 for every selected network, then prints the results table and exports CSV |

Queue mode writes one hash file per target so it can never crack the wrong
AP's hash, stops each capture as soon as a hash appears, and logs every phase.

---

## What actually works without an external adapter

| Capability | Built-in radio | External monitor adapter |
|---|---|---|
| Scan APs (CoreWLAN) | ✅ | — |
| Keychain password | ✅ | ✅ |
| Monitor-mode capture (`tcpdump -I`) | ✅ (passive) | ✅ |
| Record a natural handshake / PMKID | ✅ | ✅ |
| Channel pinning | ⚠️ only if `airport` exists (gone since 14.4) | ✅ |
| Deauth to force a handshake | ❌ cannot transmit | ✅ `aireplay-ng` |
| WPS scan / PIN | ❌ | ✅ `wash` / `reaver` |
| WEP IV collection | ⚠️ passive only, slow | ✅ |

---

## The macOS 26 Apple Silicon "0 frames" problem

On some Apple Silicon Macs running macOS 26, `tcpdump -I` reports success,
`ifconfig` may even show monitor mode, and then **nothing is captured**. NetCrack
notices: after ~10 s with zero frames it sets the pill to **No signal**, logs a
`MonitorDiagnostics.silent` verdict and tells you to continue on an external
adapter. It also detects:

- **not in monitor mode** — tcpdump rejected `-I` or the interface refused;
- **channel mismatch** — the radio reports channel X while the target is on Y
  (a monitor radio only hears its own channel);
- **zero frames** overall, with the usual causes (wrong channel, out of range,
  another tool holding the interface);
- **screen lock** — macOS suspends capture when the Mac locks; the app stops
  cleanly so the pcap stays valid and says why. "Keep display awake" holds an
  IOPM assertion while capturing.

---

## How to test it against your own network

### A. No radio needed — prove the toolchain (2 minutes)

The repo ships a synthetic capture whose PMKID is **genuinely computed**
(`Samples/netcrack-demo.pcap`, SSID `NetCrack-Demo`, passphrase `password1`):

```bash
./Scripts/test-sample.sh
# PASS: recovered 'password1' — the converter/cracker chain works.
```

Inside the app: **Crack → Load hashes… → `Samples/netcrack-demo.22000`**, leave
the wordlist on *Bundled top-10k*, press **Run attack**. The key `password1`
should appear in a couple of seconds. Or **Convert pcap… → the demo pcap** to
exercise `hcxpcapngtool` through the UI.

### B. Your own network, Keychain path (instant)

1. Join your own Wi-Fi from the menu bar.
2. App → **Scan** → select your SSID → **Target details**.
3. The "Password already known?" card shows the key immediately. Copy it,
   then change your password to something stronger — you just demonstrated why
   Keychain access is the fastest attack there is.

### C. Your own network, real capture + crack

1. Turn off "Auto-Join" on other networks, or pick a quiet channel.
2. **Target** → note the channel → **Capture**:
   - Built-in mode is fine and needs no adapter.
   - Set **Channel** to the target's channel (the radio cannot be pinned on
     14.4+, so the practical trick is to be associated with an AP on that
     channel, or use an external adapter).
   - **Start capture**. Needs the one administrator prompt.
3. On a phone, connect to your own SSID (that is the natural handshake). With an
   external adapter you can instead press **Deauth client** to force a reconnect.
4. Watch **EAPOL** tick up. The pill switches to **Handshake found** or
   **PMKID found**, the capture stops itself, and the hash is handed to Crack.
5. **Crack** → *Dictionary* with the bundled top-10k → **Run attack**.
   If your password is in the list it appears in seconds. If not:
   *Dictionary + rules*, then *Mask* (e.g. `?d?d?d?d?d?d?d?d` if it is eight
   digits), then *Incremental*.
6. Then go and fix your passphrase: 12+ random characters, WPA3 if the router
   supports it. Here is the honest math — an 8-digit numeric WPA2 key falls in
   seconds on a Mac GPU; a 20-character random one never falls.

### D. Queue mode

Scan → **Queue…** → tick several of your own APs → **Run queue**. Each target
runs Keychain → capture (up to N seconds) → dictionary → rules → mask →
(PMKID) → WPS if enabled, then the results table shows every key and
**Export CSV** writes it out.

---

## External adapter shopping list

The built-in radio is passive. For deauth, WPS and reliable channel pinning you
need a USB adapter whose chipset has a **maintained driver for your macOS
version**. macOS has no generic monitor-mode support for third-party USB Wi-Fi,
so the driver question matters more than the box art.

| Adapter | Chipset | Monitor/inject on macOS 14–26 | Notes |
|---|---|---|---|
| ALFA AWUS036ACH | Realtek RTL8812AU | ⚠️ needs a third-party driver build for your macOS version | Very popular; 2.4/5 GHz, external antenna |
| ALFA AWUS036ACHM | MediaTek MT7610U | ⚠️ community driver | Small, decent Linux support — fine if you dual-boot |
| TP-Link TL-WN722N **v1** | Atheros AR9271 | ❌ on recent macOS (driver removed); ✅ v1 only on Linux | Only the v1 has AR9271; v2/v3 are RTL8188EUS |
| Panda PAU09 | Ralink RT5572 | ⚠️ community driver | Good 5 GHz Linux card |
| ALFA AWUS036NHA | Atheros AR9271 | ❌ on recent macOS | Excellent on Linux |
| Alfa AWUS036AXML | MediaTek MT7921AU | ✅ with current MT7921AU drivers (best odds) | Wi-Fi 6, 2.4/5/6 GHz, the most future-proof bet |

Practical guidance, honestly stated:

- Before buying, search for the exact chipset plus your macOS version plus
  "monitor mode driver". Driver support for USB Wi-Fi on macOS is community
  maintained and moves; a card that worked on Big Sur may not work on Tahoe.
- Chipsets with the best current macOS odds: **MediaTek MT7921AU** and
  **Realtek RTL8812AU/8814AU**. Atheros AR9271 — the classic recommendation —
  is no longer supported on recent macOS, even though every older tutorial says
  otherwise.
- If adapter driver support is the blocker, the pragmatic setup is a small
  Linux VM or live USB running the same aircrack-ng suite, with NetCrack still
  useful for scanning, Keychain, and cracking the captured handshake.
- Whatever you buy, confirm `ifconfig <iface>` shows the adapter and that
  `sudo tcpdump -i <iface> -I -y IEEE802_11 -w t.pcap` produces a non-empty
  file before blaming the app.

Then in **Capture → Configuration**: switch to *External adapter*, enter the
interface name (`networksetup -listallhardwareports` shows it, e.g. `en5`),
and set the channel to the target's.

---

## Troubleshooting

Every message below is raised by the app with the same wording.

| Message | Meaning | Fix |
|---|---|---|
| *Wi-Fi is turned off* | `CWWiFiClient` reports power off | Turn Wi-Fi on in the menu bar |
| *… is not in monitor mode* | `tcpdump -I` was rejected or the iface refused | Stop other capture tools, retry, or use an external adapter |
| *Channel mismatch: wanted N, radio is on M* | Monitor radio only hears its own channel | Set the channel in Capture, or join an AP on that channel, or use an adapter that can be pinned |
| *Monitor mode reported success but only 0 frames arrived* | The macOS 26 Apple Silicon bug | External adapter (see above) |
| *Zero frames were captured* | Wrong channel, out of range, or iface held elsewhere | Move closer, check `sudo lsof | grep -i 802`, retry |
| *… is busy* | Another process holds the interface | Quit other capture apps / VPN Wi-Fi helpers |
| *The screen is locked, so macOS paused the capture* | Lock/sleep suspends capture | Unlock, keep display awake, restart capture |
| *hashcat is not installed* / *hcxpcapngtool is not installed* | Missing tool | **⌘,** Setup → *Install missing tools* |
| *The wordlist could not be read* | Path moved/deleted | Crack → *Bundled top-10k* |
| *No handshake yet — keep capturing* | 0 hashes in the pcap; **not an error** | Wait for a client to connect, or deauth on an external adapter |
| *hashcat found no compute device* | Metal backend unavailable (some VMs) | Enable *Force hashcat (--force)*, or run on the host |
| *The privileged helper did not start* | The root supervisor never heartbeated | Retry; test with `sudo tcpdump -i en0 -I` in Terminal |
| *Administrator authorisation was declined* | You pressed Cancel | Nothing was changed; retry when ready |
| *WPS … locked* | AP locked WPS after failures | Wait, or use the PMKID path |
| *This hashcat build does not support mode 22000* | hashcat older than 6.2.6 | `brew upgrade hashcat` |

Where things live:

```
~/Library/Application Support/NetCrack/
├── rootsession/     privileged-session inbox (0700, deleted on quit)
├── netcrack.potfile hashcat potfile for every crack
├── hashes/          per-target .22000 files
├── queue/           queue-mode pcaps + hashes
└── (captures)       set in Settings; default ~/NetCrack
```

Delete the folder (and quit the app) to reset everything. Preferences are a
handful of keys in `UserDefaults` (`defaults read com.netcrack.app`).

---

## Project layout

```
NetCrack/
├── App/            NetCrackApp (Window + commands), AppDelegate (clean shutdown)
├── Models/         AccessPoint, CaptureModels, CrackModels, ToolModels,
│                   AppError (every human-readable failure), LogLine, Formatters,
│                   SettingsStore (UserDefaults)
├── Backend/        one actor per concern
│   ├── Scanner.swift        CoreWLAN scan + LocationAuthorizer
│   ├── KeychainProbe.swift  security(1) → instant win
│   ├── CaptureEngine.swift  tcpdump -I, pcap polling, diagnostics, deauth, WPS
│   ├── Converter.swift      hcxpcapngtool → 22000, aircrack-ng fallback
│   ├── Cracker.swift        hashcat / aircrack, status parsing
│   ├── PipelineEngine.swift "by any means" queue orchestration
│   ├── ProcessRunner.swift  Process ↔ AsyncStream, never blocks main
│   ├── RootExecutor.swift   one authorisation, root supervisor, file protocol
│   ├── SetupManager.swift   Homebrew installs with streamed output
│   ├── ToolLocator.swift    binary discovery + version probe
│   └── SystemState.swift    screen-lock detection, IOPM assertion, pcap inspector
├── ViewModels/     AppModel + one per pane (MVVM, @MainActor)
├── Views/          RootView (sidebar), Scan/Target/Capture/Crack, Setup, Queue,
│                   Theme + shared components (StatusPill, LogConsole, KeyReveal…)
└── Resources/      Info.plist, entitlements, Assets.xcassets, top10k.txt
Samples/            synthetic pcap + 22000 hash for the pipeline test
Scripts/            build.sh, test-sample.sh, generate_project.py, make_sample_capture.py
```

Concurrency rules the code follows: every backend is an `actor`; every long
command is wrapped in `AsyncStream` over `Process` stdout/stderr; the main
thread only touches view models; `@MainActor` is on every view model, and the
engines hand results across actor boundaries as `Sendable` values.

Regenerate the Xcode project after adding/removing files:

```bash
python3 Scripts/generate_project.py     # stdlib only, writes NetCrack.xcodeproj
```

Rebuild the synthetic sample (also regenerates its genuine PMKID):

```bash
python3 Scripts/make_sample_capture.py
```

---

## Known limitations

- **Cracking is only as good as the wordlist or mask.** No GUI can invent a
  passphrase that is not in the search space.
- **Channel pinning is unavailable for the built-in radio** on macOS 14.4+.
- **WPS** only on an external adapter, and many modern APs disable or lock it.
- **WPA3-SAE** goes through the hcxtools path; `hashcat -m 22000` handles SAE,
  but a capture needs either a transition-mode PMKID or a client SAE exchange.
- **Screen lock stops capture** — that is macOS, not the app.
- **Enterprise/802.1X** is out of scope: there is no PSK to recover.
- **Not sandboxed, ad-hoc signed.** Expect Gatekeeper prompts if you move the
  binary between machines.

---

## License & third-party notices

NetCrack's own source is provided as-is for authorised security testing.
Bundled data and invoked tools keep their own licences — see
`THIRD-PARTY-NOTICES.md` (the top-10k wordlist is MIT, from SecLists).
