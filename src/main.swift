import AppKit
import Foundation
import SystemConfiguration
import Network

// ClaudeGuard menu bar daemon.
//
// State machine: compute one GuardState, touch the system only on transitions
// (blocking/unblocking domains, killing the app, alerting) — never on every
// poll. Owns two enforcement surfaces: the Claude Desktop app (force-quit +
// alert) and the claude/anthropic domains (/etc/hosts + pf). The `claude` CLI
// enforces itself from src/cli_wrapper.py — a background daemon has no terminal.

enum GuardState: Equatable {
    case disabled              // protection off
    case offline               // no internet — can't verify
    case allowed(ip: String)   // public IP is whitelisted
    case blocked(ip: String)   // online, IP not whitelisted

    // Fail closed: domains open only on a confirmed good IP; offline blocks too.
    var domainsShouldBeBlocked: Bool {
        switch self {
        case .allowed, .disabled: return false
        case .blocked, .offline:  return true
        }
    }
}

// Diagnostics only: no user data, endpoints, IPs or exception text in labels.
private enum SwitchTrace {
    static var enabled = ProcessInfo.processInfo.environment["CLAUDEGUARD_TRACE"] == "1"
    static let path = NSString(string: "~/.config/claudeguard/trace.log").expandingTildeInPath
    static func begin() -> TimeInterval? { enabled ? ProcessInfo.processInfo.systemUptime : nil }
    static func end(_ start: TimeInterval?, _ stage: String, _ result: String = "completed") {
        guard let start = start else { return }
        let duration = (ProcessInfo.processInfo.systemUptime - start) * 1000
        let line = "\(ISO8601DateFormatter().string(from: Date())) stage=\(stage) duration_ms=\(String(format: "%.3f", duration)) result=\(result)\n"
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return }
        line.withCString { bytes in _ = write(fd, bytes, strlen(bytes)) }
    }
}

// Shared native input window for IPs, model IDs and proxy profiles.
final class SettingsInputWindow: NSWindow, NSWindowDelegate {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.intersection(.deviceIndependentFlagsMask).contains(.command),
           let editor = firstResponder as? NSTextView {
            // Physical-key fallback keeps editing shortcuts working with Russian layouts.
            let key = event.charactersIgnoringModifiers?.lowercased() ?? ""
            let shortcut = ["c", "v", "x", "a", "z"].contains(key) ? key
                : ([UInt16(8): "c", 9: "v", 7: "x", 0: "a", 6: "z"][event.keyCode] ?? key)
            switch shortcut {
            case "c": editor.copy(nil)
            case "v": editor.paste(nil)
            case "x": editor.cut(nil)
            case "a": editor.selectAll(nil)
            case "z":
                if event.modifierFlags.contains(.shift) { editor.undoManager?.redo() }
                else { editor.undoManager?.undo() }
            default: return super.performKeyEquivalent(with: event)
            }
            return true
        }
        return super.performKeyEquivalent(with: event)
    }
    @objc func acceptInput() { NSApp.stopModal(withCode: .OK) }
    @objc func cancelInput() { NSApp.abortModal() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApp.abortModal(); return true }
}

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var statusItem: NSStatusItem!
    var menu: NSMenu!

    var state: GuardState = .offline
    var currentIP: String = "…"
    var protectionEnabled: Bool = true
    var modelOverrideEnabled: Bool = false
    var defaultModel: String = "claude-opus-4-8"
    var proxyEndpoint = "Not configured"
    var proxyEnabled = true
    var proxyProfileID = ""
    var proxyError = ""
    var connectionMode: ConnectionMode = .vpn
    var menuIsOpen = false
    var menuRows: [String: NSMenuItem] = [:]
    lazy var modeControl: ModeSegmentedControl = {
        let control = ModeSegmentedControl(selected: connectionMode)
        control.onChange = { [weak self] mode in self?.onModeChanged(mode) }
        return control
    }()
    lazy var modeMenuItem: NSMenuItem = {
        let item = NSMenuItem()
        item.view = modeControl
        return item
    }()
    func menuWillOpen(_ menu: NSMenu) { menuIsOpen = true }
    func menuDidClose(_ menu: NSMenu) { menuIsOpen = false; rebuildMenu() }
    private var switchTiming: (id: UUID, start: TimeInterval, stage: String)?
    func onModeChanged(_ mode: ConnectionMode) {
        if let started = SwitchTrace.begin() {
            if let previous = switchTiming { SwitchTrace.end(previous.start, previous.stage, "superseded") }
            switchTiming = (UUID(), started, "switch." + connectionMode.rawValue + "_to_" + mode.rawValue)
        }
        connectionMode = mode
        if mode == .proxy { proxyEnabled = true }
        proxyError = ""
        proxyProfileID = ""
        currentIP = "…"
        state = .offline
        saveConfig()
        writeStateFile()
        lastAppliedDomainsBlocked = nil
        rebuildMenu()
        recheckAsync()
    }

    var allowedIPs: [String] = []

    var dynamicStore: SCDynamicStore?
    var pathMonitor: NWPathMonitor?
    // Usable network route, from NWPathMonitor — lets us declare "offline" the
    // instant Wi-Fi drops instead of waiting for HTTP timeouts.
    var hasNetworkPath: Bool = true
    var blinkTimer: Timer?
    var blinkState: Bool = false
    // Serialize + coalesce rechecks. A plain "drop if busy" lock loses the
    // network event that arrives mid-check — the classic cause of a boot (or a
    // VPN handoff) that latches on offline/blocked until a reboot. Instead:
    // while a check runs, fold new requests into a flag and run one more pass
    // when it finishes, so the newest event is always acted on.
    let checkLock = NSLock()
    var checkRunning = false
    var recheckQueued = false
    let configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath

    // Last enforcement pushed to the system, to skip redundant work. nil = never
    // applied, force a first apply.
    var lastAppliedDomainsBlocked: Bool? = nil
    var enforcementError: String? = nil
    var lastEnforcementAt = Date.distantPast
    // Alerted once for the current blocked episode (reset on leaving blocked).
    var hasAlertedThisBlock: Bool = false

    // MARK: - Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single-instance guard. LaunchAgent runs the bare binary, Launchpad
        // runs the .app — match both names and the bundle id.
        let myPID = getpid()
        for app in NSWorkspace.shared.runningApplications where app.processIdentifier != myPID {
            let name = app.localizedName ?? ""
            if name == "ClaudeGuardMenuBar" || name == "ClaudeGuard" || app.bundleIdentifier == "com.claudeguard.app" {
                NSApplication.shared.terminate(nil)
                return
            }
        }

        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImage = NSImage(contentsOfFile: iconPath) {
            NSApplication.shared.applicationIconImage = iconImage
        }

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        updateStatusDisplay()
        menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        loadConfig()
        // Migrate the removed standalone Disconnect state. Mode + Protection now control access.
        if !proxyEnabled { proxyEnabled = true; saveConfig() }
        rebuildMenu()

        setupAppLaunchInterceptor()

        // Bring the network monitors up first so no early Wi-Fi/VPN transition
        // is missed, then verify. State is unknown until the first check returns.
        setupPathMonitor()      // connectivity up/down
        setupNetworkObserver()  // VPN/route/IP changes while online
        setupWakeObserver()     // re-verify after the Mac wakes from sleep

        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }

        // Fallback poll — catches a public-IP change with no local network event,
        // and (paired with the coalescing recheck) guarantees the daemon
        // self-heals from a bad boot within one interval instead of needing a
        // reboot. .utility so the OS won't suspend it the way it can .background.
        Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.recheck() }
        }

        // Hook self-heal. Separate from recheck() because it guards a different
        // failure: not a network change, but Claude being reinstalled underneath
        // us and quietly detaching the guard.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) { self.runIntegrityRepair() }
        Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.runIntegrityRepair() }
        }
    }

    func runIntegrityRepair() {
        runHelper("integrity", "", "")
    }

    /// True when /etc/hosts no longer matches what we last applied — an OS
    /// update, another tool or a manual edit reverted our block.
    func hostsDrifted() -> Bool {
        guard let wantDomains = lastAppliedDomainsBlocked,
              let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        else { return false }
        let hasDomains = content.contains("# BEGIN CLAUDEGUARD BLOCKS")
        let hasUpdates = content.contains("# BEGIN CLAUDEGUARD UPDATE BLOCKS")
        let expectHostsBlock = wantDomains && connectionMode != .vpn
        return hasDomains != expectHostsBlock || hasUpdates
    }

    /// Claude Desktop, matched by bundle-id *prefix* — the exact id has already
    /// changed once (claudefor-mac → claudefordesktop). The name is only a
    /// fallback: it's localized, so it can't be the primary test.
    static func isClaudeDesktop(_ app: NSRunningApplication) -> Bool {
        if let bundleID = app.bundleIdentifier {
            if bundleID.hasPrefix("com.claudeguard") { return false }   // never ourselves
            if bundleID.hasPrefix("com.anthropic.claude") { return true }
        }
        return (app.localizedName ?? "") == "Claude"
    }

    // MARK: - Connectivity monitor (Network framework)

    func setupPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let satisfied = (path.status == .satisfied)
            let changed = (self.hasNetworkPath != satisfied)
            self.hasNetworkPath = satisfied
            // Connectivity flipped — re-verify. Down → recheck() declares offline
            // instantly; up → recheck() runs the IP check.
            if changed { self.lastAppliedDomainsBlocked = nil; self.startBlinking() }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + (satisfied ? 0.4 : 0.0)) {
                self.recheck()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.claudeguard.path"))
        self.pathMonitor = monitor
    }

    // MARK: - Real-time network observer

    func setupNetworkObserver() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)

        let callback: SCDynamicStoreCallBack = { (_, _, info) in
            guard let info = info else { return }
            let me = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            // Network event fired — don't act blindly, just re-verify once it
            // settles; recheck() decides.
            me.lastAppliedDomainsBlocked = nil
            me.startBlinking()
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.3) { me.recheck() }
        }

        guard let store = SCDynamicStoreCreate(kCFAllocatorDefault, "com.claudeguard.app" as CFString, callback, &context) else { return }
        self.dynamicStore = store
        let patterns = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Interface/.*",
            "State:/Network/Service/.*"
        ] as CFArray
        SCDynamicStoreSetNotificationKeys(store, nil, patterns)
        if let src = SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), src, .defaultMode)
        }
    }

    // MARK: - Wake-from-sleep

    /// After the Mac wakes, the route and VPN re-establish over several seconds
    /// and NWPathMonitor may not emit a clean transition. Fire a few staggered
    /// rechecks so we never sit on a stale pre-sleep verdict.
    func setupWakeObserver() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lastAppliedDomainsBlocked = nil
            self.startBlinking()
            for delay in [0.5, 3.0, 8.0] {
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) {
                    self.recheck()
                }
            }
        }
    }

    // MARK: - Desktop app launch interceptor

    func setupAppLaunchInterceptor() {
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] note in
            guard let self = self else { return }
            guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            if Self.isClaudeDesktop(app) {
                guard self.protectionEnabled else { return }
                // Fail closed on a fresh launch, even offline: an unverified
                // session must not start.
                if case .allowed = self.state, self.enforcementError == nil { return }
                app.forceTerminate()
                self.runPkill(target: "Claude.app")
                let reason: String
                switch self.state {
                case .offline: reason = "No internet connection — your IP can't be verified."
                default:       reason = "Your public IP (\(self.currentIP)) is not in your allowed VPN whitelist."
                }
                self.showBlockedAlert(reason: self.connectionMode == .proxy ? "Proxy is disconnected or unavailable." : reason)
            }
        }
    }

    // MARK: - Core check

    func recheck() {
        // Coalescing gate: at most one check runs at a time; a request that
        // arrives while one is in flight sets a flag so exactly one more pass
        // runs afterwards. No network event is ever silently dropped, and two
        // quick config toggles can't leave enforcement out of sync.
        checkLock.lock()
        if checkRunning {
            recheckQueued = true
            checkLock.unlock()
            return
        }
        checkRunning = true
        checkLock.unlock()

        while true {
            checkLock.lock(); recheckQueued = false; checkLock.unlock()

            performCheck()

            checkLock.lock()
            if recheckQueued { checkLock.unlock(); continue }
            checkRunning = false
            checkLock.unlock()
            break
        }
        stopBlinking()
    }

    /// One verification pass: resolve the public IP, fold it into a GuardState,
    /// push enforcement on transitions, publish the verdict.
    func performCheck() {
        let timingID = switchTiming?.id
        let configurationSnapshot = try? Data(contentsOf: URL(fileURLWithPath: configPath))
        loadConfig()

        // Install the VPN denial before the first network verification.
        if protectionEnabled && connectionMode == .vpn && lastAppliedDomainsBlocked == nil {
            if runHelper("sync_hosts", "true", "") {
                lastAppliedDomainsBlocked = true
                lastEnforcementAt = Date()
            }
        }
        let newState: GuardState
        // Keep results local until the configuration snapshot is validated.
        // A completed proxy probe must not overwrite the IP of a new VPN mode.
        var checkedIP = currentIP
        var checkedError = proxyError
        var checkedProfileID = proxyProfileID
        var preparedProxy = false
        if !protectionEnabled {
            newState = .disabled
        } else if connectionMode == .proxy && proxyEndpoint == "Not configured" {
            checkedIP = "Unavailable"
            checkedError = "Proxy is not configured"
            checkedProfileID = ""
            newState = .blocked(ip: "Unavailable")
        } else if connectionMode == .proxy {
            let result = checkProxy()
            checkedIP = result.ip ?? "Unavailable"
            checkedError = result.error
            checkedProfileID = result.profileID
            preparedProxy = result.prepared
            newState = result.ip.map { .allowed(ip: $0) } ?? .blocked(ip: "Unavailable")
        } else {
            // `hasNetworkPath` is only a *hint* for snappy offline detection —
            // never a latch. Even when it says "no route" we still attempt a
            // short resolve, because that flag can go stale across a Wi-Fi/VPN
            // handoff and would otherwise pin us to offline until a reboot. A
            // resolved IP always overrides the hint (and repairs it).
            let ip = hasNetworkPath ? resolvePublicIPWithRetry()
                                    : resolvePublicIP(deadline: 1.5)
            if let ip = ip {
                checkedIP = ip
                if !hasNetworkPath { hasNetworkPath = true }   // hint was stale
                let ok = Self.isIPAllowed(ip, allowedList: allowedIPs)
                newState = ok ? .allowed(ip: ip) : .blocked(ip: ip)
            } else {
                checkedIP = "No Internet"
                newState = .offline
            }
        }

        // Discard a network result obtained for settings changed during the check.
        // In particular, a late VPN result must never approve a newly selected proxy.
        guard configurationSnapshot == (try? Data(contentsOf: URL(fileURLWithPath: configPath))) else {
            checkLock.lock(); recheckQueued = true; checkLock.unlock()
            return
        }
        currentIP = checkedIP
        proxyError = checkedError
        proxyProfileID = checkedProfileID
        if preparedProxy {
            // proxy_check already received the privileged helper's acknowledgement.
            // Avoid resolving DNS and applying the identical rules a second time.
            lastAppliedDomainsBlocked = false
            lastEnforcementAt = Date()
            enforcementError = nil
        }
        let previous = state
        state = newState
        // Publish a denial before waiting for the privileged helper, so CLI
        // sessions stop promptly even if applying network rules is slow.
        if newState.domainsShouldBeBlocked { writeStateFile() }
        apply(from: previous, to: newState)
        if protectionEnabled && enforcementError != nil { state = .blocked(ip: currentIP) }
        writeStateFile()  // publish verdict for the CLI wrapper

        DispatchQueue.main.async {
            self.updateStatusDisplay(); self.rebuildMenu()
            if let timing = self.switchTiming, timing.id == timingID {
                SwitchTrace.end(timing.start, timing.stage, self.enforcementError == nil ? "completed" : "error")
                self.switchTiming = nil
            }
        }
    }

    /// Publishes the verdict to state.json (single source of truth for the CLI
    /// wrapper). Written atomically each recheck; a stale file signals the
    /// daemon is down and the wrapper should fall back to its own check.
    func writeStateFile() {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "state_json.write") }
        let stateStr: String
        switch state {
        case .allowed:  stateStr = "allowed"
        case .blocked:  stateStr = "blocked"
        case .offline:  stateStr = "offline"
        case .disabled: stateStr = "disabled"
        }
        var dict: [String: Any] = [
            "state": stateStr,
            "mode": connectionMode.rawValue,
            "proxy_profile_id": proxyProfileID,
            "ip": currentIP,
            "protection_enabled": protectionEnabled,
            "updated_at": Date().timeIntervalSince1970
        ]
        if let error = enforcementError { dict["enforcement_error"] = error }
        let path = NSString(string: "~/.config/claudeguard/state.json").expandingTildeInPath
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    /// The only place that touches the system. Each piece runs only when its
    /// input actually changed.
    func apply(from previous: GuardState, to new: GuardState) {
        // Transition-only enforcement assumes nothing else edits /etc/hosts;
        // drift means "pretend we never applied anything" and re-apply.
        if hostsDrifted() {
            lastAppliedDomainsBlocked = nil
        }

        // Desktop app kill + alert.
        switch new {
        case .blocked:
            let killed = killDesktopIfRunning()
            if killed && !hasAlertedThisBlock {   // alert once per blocked episode
                hasAlertedThisBlock = true
                showBlockedAlert(reason: connectionMode == .proxy ? "Proxy connection could not be verified. Check Configure Proxy and connection status." : "Your public IP (\(currentIP)) is not in your allowed VPN whitelist.")
            }
        case .allowed, .disabled, .offline:
            // offline: don't kill a running app — nothing to protect against.
            hasAlertedThisBlock = false
        }
        let wantBlocked = new.domainsShouldBeBlocked
        // Also refresh an active block periodically: another firewall can
        // reload PF without touching hosts, or DNS targets can change.
        let refreshBlock = (wantBlocked || protectionEnabled) && Date().timeIntervalSince(lastEnforcementAt) >= 60
        if lastAppliedDomainsBlocked != wantBlocked || refreshBlock {
            if runHelper("sync_hosts", wantBlocked ? "true" : "false", "") {
                lastAppliedDomainsBlocked = wantBlocked
                lastEnforcementAt = Date()
                enforcementError = nil
            } else {
                lastAppliedDomainsBlocked = nil
                enforcementError = "Network rules could not be applied; check /tmp/claudeguard.err"
            }
        }
        _ = previous
    }

    // MARK: - IP fetch (STUN-first, HTTP fallback, raced)

    let stunServers: [(String, UInt16)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]
    let httpServices = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://api.myip.com"
    ]

    /// Resolves the public IP with a brief retry — right after a VPN/Wi-Fi
    /// handshake the route is momentarily unstable, and a single failed lookup
    /// used to falsely flash "offline".
    func resolvePublicIPWithRetry(attempts: Int = 2, deadline: TimeInterval = 2.0) -> String? {
        for attempt in 0..<attempts {
            if let ip = resolvePublicIP(deadline: deadline) { return ip }
            if attempt < attempts - 1 { Thread.sleep(forTimeInterval: 0.5) }
        }
        return nil
    }

    /// Races a STUN query against the HTTP IP services in parallel; first valid
    /// answer wins. STUN wins instantly when online; HTTP covers networks that
    /// block UDP/STUN. A single ~2s deadline bounds the offline case.
    func resolvePublicIP(deadline: TimeInterval = 2.0) -> String? {
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String? = nil
        func offer(_ ip: String?) {
            guard let ip = ip, !ip.isEmpty else { return }
            lock.lock()
            let first = (result == nil)
            if first { result = ip }
            lock.unlock()
            if first { sem.signal() }
        }

        // STUN (fast path)
        var conns: [NWConnection] = []
        for (host, port) in stunServers {
            if let c = stunQuery(host: host, port: port, completion: { offer($0) }) {
                conns.append(c)
            }
        }

        // HTTP (fallback, in parallel)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = deadline
        cfg.timeoutIntervalForResource = deadline
        let session = URLSession(configuration: cfg)
        for service in httpServices {
            guard let url = URL(string: service) else { continue }
            var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: deadline)
            req.setValue("ClaudeGuard/1.0", forHTTPHeaderField: "User-Agent")
            session.dataTask(with: req) { data, _, err in
                guard err == nil else { return }
                offer(Self.parseHTTPIP(data))
            }.resume()
        }

        _ = sem.wait(timeout: .now() + deadline)
        conns.forEach { $0.cancel() }
        session.invalidateAndCancel()

        lock.lock(); let ip = result; lock.unlock()
        return ip
    }

    static func parseHTTPIP(_ data: Data?) -> String? {
        guard let data = data,
              let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !str.isEmpty else { return nil }
        if str.contains("{"), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let ip = json["ip"] as? String {
            return ip.trimmingCharacters(in: .whitespacesAndNewlines)
        } else if !str.contains("<") {
            return str
        }
        return nil
    }

    /// Fires one STUN Binding Request over UDP and calls `completion` with the
    /// mapped public IP (or nil). Returns the live connection so the caller can
    /// cancel it. Non-blocking.
    func stunQuery(host: String, port: UInt16, completion: @escaping (String?) -> Void) -> NWConnection? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { completion(nil); return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)

        // STUN Binding Request: type 0x0001, length 0, magic cookie, 12-byte txid.
        var req = Data([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42])
        for _ in 0..<12 { req.append(UInt8.random(in: 0...255)) }

        let lock = NSLock()
        var done = false
        func finish(_ ip: String?) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            completion(ip)
        }

        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                conn.send(content: req, completion: .contentProcessed { err in
                    if err != nil { finish(nil) }
                })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.flatMap { Self.parseStun([UInt8]($0)) })
                }
            case .failed, .cancelled:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "com.claudeguard.stun"))
        return conn
    }

    /// Parses a STUN Binding Success Response, returning the IPv4 from the
    /// XOR-MAPPED-ADDRESS (0x0020) or plain MAPPED-ADDRESS (0x0001) attribute.
    static func parseStun(_ b: [UInt8]) -> String? {
        guard b.count >= 20, b[0] == 0x01, b[1] == 0x01 else { return nil } // 0x0101 success
        let msgLen = Int(b[2]) << 8 | Int(b[3])
        let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        var i = 20
        let end = min(20 + msgLen, b.count)
        while i + 4 <= end {
            let attrType = Int(b[i]) << 8 | Int(b[i + 1])
            let attrLen = Int(b[i + 2]) << 8 | Int(b[i + 3])
            let vs = i + 4
            if vs + attrLen > b.count { break }
            if (attrType == 0x0020 || attrType == 0x0001), attrLen >= 8, b[vs + 1] == 0x01 {
                let a0, a1, a2, a3: UInt8
                if attrType == 0x0020 { // XOR-MAPPED: address XOR'd with the magic cookie
                    a0 = b[vs + 4] ^ cookie[0]
                    a1 = b[vs + 5] ^ cookie[1]
                    a2 = b[vs + 6] ^ cookie[2]
                    a3 = b[vs + 7] ^ cookie[3]
                } else {
                    a0 = b[vs + 4]; a1 = b[vs + 5]; a2 = b[vs + 6]; a3 = b[vs + 7]
                }
                return "\(a0).\(a1).\(a2).\(a3)"
            }
            i = vs + attrLen
            if attrLen % 4 != 0 { i += 4 - (attrLen % 4) } // pad to 4-byte boundary
        }
        return nil
    }

    /// Matches an IP against exact entries or IPv4 CIDR ranges — mirrors
    /// ip_checker.py so the daemon and the CLI agree on what's whitelisted.
    static func isIPAllowed(_ ip: String, allowedList: [String]) -> Bool {
        for raw in allowedList {
            let entry = raw.trimmingCharacters(in: .whitespaces)
            if entry.isEmpty { continue }
            if entry == ip { return true }
            if entry.contains("/"), let ipv = ipv4ToUInt32(ip) {
                let parts = entry.split(separator: "/")
                if parts.count == 2, let net = ipv4ToUInt32(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits) {
                    let mask: UInt32 = bits == 0 ? 0 : (~UInt32(0)) << (32 - bits)
                    if (ipv & mask) == (net & mask) { return true }
                }
            }
        }
        return false
    }

    static func ipv4ToUInt32(_ ip: String) -> UInt32? {
        let p = ip.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 <= 255 }) else { return nil }
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    }

    // MARK: - Process control

    func runPkill(target: String) {
        let t1 = Process()
        t1.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        t1.arguments = ["-15", "-f", target]
        try? t1.run()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) {
            let t2 = Process()
            t2.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            t2.arguments = ["-9", "-f", target]
            try? t2.run()
        }
    }

    @discardableResult
    func killDesktopIfRunning() -> Bool {
        let victims = NSWorkspace.shared.runningApplications.filter { Self.isClaudeDesktop($0) }
        guard !victims.isEmpty else { return false }
        // Terminate the matched processes directly (precise wherever the app was
        // installed); pkill is the second pass for helpers it spawns.
        victims.forEach { $0.forceTerminate() }
        runPkill(target: "Claude.app")
        return true
    }

    func showBlockedAlert(reason: String) {
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "ClaudeGuard 🚫 Blocked"
            alert.informativeText = "Claude Desktop was closed.\n\n\(reason)"
            alert.addButton(withTitle: "OK")
            alert.window.level = .floating
            alert.runModal()
        }
    }

    @discardableResult
    func runHelper(_ cmd: String, _ a1: String, _ a2: String) -> Bool {
        let timing = SwitchTrace.begin()
        var traceResult = "error"
        defer { SwitchTrace.end(timing, "helper." + (["sync_hosts", "integrity"].contains(cmd) ? cmd : "other"), traceResult) }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let script = NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath
        task.arguments = [script, cmd, a1, a2]
        do {
            try task.run()
            task.waitUntilExit()
            traceResult = task.terminationStatus == 0 ? "ok" : "error"
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: - Config

    func loadConfig() {
        guard secureConfigPermissions() else { return }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        SwitchTrace.enabled = ProcessInfo.processInfo.environment["CLAUDEGUARD_TRACE"] == "1" || json["trace"] as? Bool == true
        proxyEnabled = json["proxy_enabled"] as? Bool ?? true
        if let profile = json["proxy_profile"] as? [String: Any],
           let host = profile["server"] as? String, let port = profile["server_port"] as? Int {
            proxyEndpoint = "\(profile["type"] as? String ?? "proxy")://\(host):\(port)"
        } else { proxyEndpoint = "Not configured" }
        let loadedMode = ConnectionMode(rawValue: json["connection_mode"] as? String ?? "vpn") ?? .vpn
        if loadedMode != connectionMode {
            lastAppliedDomainsBlocked = nil
            currentIP = "…"
            proxyProfileID = ""
            proxyError = ""
            state = protectionEnabled ? .offline : .disabled
        }
        connectionMode = loadedMode
        if let ips = json["allowed_ips"] as? [String] { allowedIPs = ips }
        if let p = json["protection_enabled"] as? Bool { protectionEnabled = p }
        if let m = json["model_override_enabled"] as? Bool { modelOverrideEnabled = m }
        if let d = json["default_model"] as? String { defaultModel = d }
    }

    func saveConfig() {
        guard secureConfigPermissions() else { return }
        var json: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { json = existing }
        json["proxy_enabled"] = proxyEnabled
        json["connection_mode"] = connectionMode.rawValue
        json["allowed_ips"] = allowedIPs
        json["protection_enabled"] = protectionEnabled
        json["model_override_enabled"] = modelOverrideEnabled
        json["default_model"] = defaultModel
        if let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) {
            let fd = open(configPath, O_WRONLY | O_CREAT | O_NOFOLLOW, mode_t(0o600))
            guard fd >= 0 else { return }
            defer { close(fd) }
            guard fchmod(fd, mode_t(0o600)) == 0, ftruncate(fd, 0) == 0 else { return }
            data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { return }
                    offset += count
                }
            }
        }
    }

    private func secureConfigPermissions() -> Bool {
        let directory = (configPath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return false }
        guard chmod(directory, mode_t(0o700)) == 0 else { return false }
        if !FileManager.default.fileExists(atPath: configPath) { return true }
        let fd = open(configPath, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        return fchmod(fd, mode_t(0o600)) == 0
    }

    // MARK: - UI

    func statusText() -> String {
        if protectionEnabled && connectionMode == .proxy && proxyEndpoint == "Not configured" {
            return "Status: 🔴 Proxy not configured"
        }
        switch state {
        case .offline:  return "Status: ⚪ Offline (no connection)"
        case .disabled: return "Status: 🟡 Protection Disabled"
        case .allowed:  return connectionMode == .proxy ? "Status: 🟢 Protected (Proxy OK)" : "Status: 🟢 Protected (VPN OK)"
        case .blocked:  return connectionMode == .proxy ? "Status: 🔴 Proxy unavailable" : "Status: 🔴 BLOCKED (unallowed network)"
        }
    }

    func updateStatusDisplay(isDimmed: Bool = false) {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "ui.status.update") }
        guard let button = statusItem.button else { return }
        button.title = ""
        button.attributedTitle = NSAttributedString(string: "")

        let symbol: String
        switch state {
        case .offline:  symbol = "shield.slash.fill"   // crossed-out shield: nothing to verify against
        case .disabled: symbol = "shield"
        case .allowed:  symbol = "lock.shield.fill"
        case .blocked:  symbol = "xmark.shield.fill"
        }

        if let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "ClaudeGuard")?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)) {
            image.isTemplate = true
            button.image = image
            button.image?.accessibilityDescription = statusText()
            button.alphaValue = isDimmed ? 0.35 : 1.0
        }
    }

    func startBlinking() {
        DispatchQueue.main.async { [self] in
            guard blinkTimer == nil else { return }
            blinkState = false
            // Quick, smooth opacity pulse that fades in/out (like the system's
            // menu-bar input-source switcher) instead of a slow hard blink.
            blinkTimer = Timer.scheduledTimer(withTimeInterval: 0.16, repeats: true) { [weak self] _ in
                guard let self = self, let button = self.statusItem.button else { return }
                self.blinkState.toggle()
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = self.blinkState ? 0.45 : 1.0
                }
            }
        }
    }

    func stopBlinking() {
        DispatchQueue.main.async { [self] in
            blinkTimer?.invalidate()
            blinkTimer = nil
            updateStatusDisplay()
            if let button = statusItem.button {
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = 1.0
                }
            }
            rebuildMenu()
        }
    }

    func rebuildMenu() {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "ui.menu.update") }
        // Keep the segmented control and menu rows alive during menu tracking.
        // Updating titles/visibility avoids dropping the control's mouseUp event.
        if menuRows.isEmpty {
            func row(_ key: String, _ action: Selector? = nil) {
                let item = NSMenuItem(title: "", action: action, keyEquivalent: "")
                item.target = action == nil ? nil : self
                item.isEnabled = action != nil
                menuRows[key] = item
                menu.addItem(item)
            }
            row("status")
            menu.addItem(modeMenuItem)
            row("endpoint")
            menu.addItem(.separator())
            row("recheck", #selector(onRecheck))
            menu.addItem(.separator())
            row("protection", #selector(onToggleProtection))
            menu.addItem(.separator())
            row("model", #selector(onToggleModelOverride))
            row("changeModel", #selector(onChangeModel))
            menu.addItem(.separator())
            row("addIP", #selector(onAddCurrentIP))
            row("manageIPs", #selector(onManageIPs))
            row("proxy", #selector(onConfigureProxy))
            menu.addItem(.separator())
            row("quit", #selector(onQuit))
        }
        let isProxy = connectionMode == .proxy
        menuRows["status"]?.title = statusText()
        modeControl.setSelectedMode(connectionMode, animated: false)
        modeControl.isEnabled = protectionEnabled
        menuRows["endpoint"]?.title = isProxy ? "Proxy: \(proxyEndpoint)" : "Current IP: \(currentIP)"
        menuRows["recheck"]?.title = "🔄 Re-check Now"
        menuRows["protection"]?.title = protectionEnabled ? "✓ Protection Active" : "Protection Disabled"
        menuRows["model"]?.title = modelOverrideEnabled ? "✓ Default Model: \(defaultModel)" : "Default Model Override (off)"
        menuRows["changeModel"]?.title = "    Change Model…"
        menuRows["changeModel"]?.isHidden = !modelOverrideEnabled
        menuRows["addIP"]?.title = "➕ Whitelist Current IP (\(currentIP))"
        menuRows["addIP"]?.isHidden = isProxy || currentIP.isEmpty || ["No Internet", "…", "Unavailable"].contains(currentIP) || allowedIPs.contains(currentIP)
        menuRows["manageIPs"]?.title = "⚙️ Manage Whitelisted IPs…"
        menuRows["manageIPs"]?.isHidden = isProxy
        menuRows["proxy"]?.title = "⚙️ Configure Proxy…"
        menuRows["proxy"]?.isHidden = !isProxy
        menuRows["quit"]?.title = "Quit ClaudeGuard"
        menu.update()
    }

    func checkProxy() -> (ip: String?, error: String, profileID: String, prepared: Bool) {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "helper.proxy_check") }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        task.arguments = [NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath, "proxy_check"]
        let pipe = Pipe(); task.standardOutput = pipe
        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return (nil, "Invalid proxy check response", "", false)
            }
            let ok = json["ok"] as? Bool == true
            return (ok ? json["ip"] as? String : nil, json["error"] as? String ?? "",
                    json["profile_id"] as? String ?? "", ok && json["prepared"] as? Bool == true)
        } catch { return (nil, "Proxy check failed", "", false) }
    }

    func promptText(title: String, prompt: String, value: String) -> String? {
        let window = SettingsInputWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 210),
                                         styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title
        window.isReleasedWhenClosed = false
        window.delegate = window
        let label = NSTextField(wrappingLabelWithString: prompt)
        label.frame = NSRect(x: 24, y: 124, width: 472, height: 56)
        label.font = .systemFont(ofSize: 14)
        let field = NSTextField(frame: NSRect(x: 24, y: 78, width: 472, height: 28))
        field.font = .systemFont(ofSize: 14)
        field.stringValue = value
        let cancel = NSButton(title: "Cancel", target: window, action: #selector(SettingsInputWindow.cancelInput))
        cancel.frame = NSRect(x: 302, y: 22, width: 94, height: 32)
        cancel.bezelStyle = .rounded; cancel.keyEquivalent = "\u{1b}"
        let okay = NSButton(title: "OK", target: window, action: #selector(SettingsInputWindow.acceptInput))
        okay.frame = NSRect(x: 402, y: 22, width: 94, height: 32)
        okay.bezelStyle = .rounded; okay.keyEquivalent = "\r"
        [label, field, cancel, okay].forEach { window.contentView?.addSubview($0) }
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(field)
        field.selectText(nil)
        let response = NSApp.runModal(for: window)
        let entered = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        window.orderOut(nil); window.close()
        return response == .OK ? entered : nil
    }

    func currentProxyInput() -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let config = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = config["proxy_profile"] as? [String: Any] else { return "" }
        // Keep advanced profiles intact; simple HTTP/SOCKS profiles are easier to edit as URLs.
        let urlFields: Set<String> = ["type", "server", "server_port", "username", "password", "version"]
        if Set(profile.keys).isSubset(of: urlFields),
           let type = profile["type"] as? String, ["http", "socks"].contains(type),
           let host = profile["server"] as? String, let port = profile["server_port"] as? Int {
            var url = URLComponents()
            url.scheme = type == "socks" ? "socks\(profile["version"] as? String ?? "5")" : "http"
            url.host = host; url.port = port
            url.user = profile["username"] as? String
            url.password = profile["password"] as? String
            if let value = url.string { return value }
        }
        guard let encoded = try? JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys]),
              let value = String(data: encoded, encoding: .utf8) else { return "" }
        return value
    }

    @objc func onConfigureProxy() {
        guard let entered = promptText(title: "ClaudeGuard Proxy",
            prompt: "Enter proxy URL or outbound JSON. Leave empty to remove the profile:", value: currentProxyInput()) else { return }
        proxySettingsQueue.async {
            let task = Process(); task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            task.arguments = [NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath, "proxy_save"]
            let input = Pipe(); let errors = Pipe()
            task.standardInput = input; task.standardError = errors
            var failureMessage: String?
            do {
                try task.run()
                input.fileHandleForWriting.write(Data(entered.utf8))
                try input.fileHandleForWriting.close()
                let errorData = errors.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                if task.terminationStatus != 0 {
                    failureMessage = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                        ?? "Check the proxy URL or JSON profile."
                }
            } catch { failureMessage = "Could not save proxy settings. Please try again." }
            let message = failureMessage
            DispatchQueue.main.async {
                if let message = message {
                    let failure = NSAlert(); failure.messageText = "Proxy settings were not saved"
                    failure.informativeText = message
                    failure.runModal()
                    return
                }
                self.loadConfig()
                self.proxyEnabled = true; self.connectionMode = .proxy; self.proxyError = ""
                self.currentIP = "…"; self.proxyProfileID = ""
                self.state = entered.isEmpty && self.protectionEnabled ? .blocked(ip: "Unavailable") : .offline
                self.saveConfig(); self.writeStateFile(); self.lastAppliedDomainsBlocked = nil
                self.rebuildMenu(); self.recheckAsync()
            }
        }
    }

    private let proxySettingsQueue = DispatchQueue(label: "com.claudeguard.proxy-settings", qos: .userInitiated)

    private func recheckAsync() {
        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }
    }

    @objc func onRecheck() { recheckAsync() }

    @objc func onToggleProtection() {
        protectionEnabled.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleModelOverride() {
        modelOverrideEnabled.toggle()
        saveConfig()
        rebuildMenu()
    }

    @objc func onChangeModel() {
        guard let entered = promptText(title: "ClaudeGuard Default Model",
            prompt: "Enter Claude model ID (e.g. claude-opus-4-8):", value: defaultModel), !entered.isEmpty else { return }
        defaultModel = entered
        saveConfig(); rebuildMenu()
    }

    func validWhitelistEntry(_ entry: String) -> Bool {
        let parts = entry.components(separatedBy: "/")
        guard parts.count <= 2, !parts[0].isEmpty,
              parts[0].utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...70).contains(byte)
                      || (97...102).contains(byte) || byte == 46 || byte == 58
              }) else { return false }
        // Darwin accepts leading-zero IPv4 octets; Python/root validation does not.
        if parts[0].contains(".") {
            let dotted = parts[0].components(separatedBy: ":").last!
            let octets = dotted.components(separatedBy: ".")
            guard octets.count == 4, octets.allSatisfy({
                !$0.isEmpty && ($0.count == 1 || !$0.hasPrefix("0"))
                    && $0.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
            }) else { return false }
        }
        var v4 = in_addr()
        var v6 = in6_addr()
        let maxPrefix: Int
        if inet_pton(AF_INET, parts[0], &v4) == 1 { maxPrefix = 32 }
        else if inet_pton(AF_INET6, parts[0], &v6) == 1 { maxPrefix = 128 }
        else { return false }
        if parts.count == 1 { return true }
        let prefix = parts[1]
        return !prefix.isEmpty && prefix.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
            && Int(prefix).map { $0 <= maxPrefix } == true
    }

    @objc func onAddCurrentIP() {
        if validWhitelistEntry(currentIP), !allowedIPs.contains(currentIP) {
            allowedIPs.append(currentIP)
            saveConfig()
            recheckAsync()
        }
    }

    @objc func onManageIPs() {
        guard let entered = promptText(title: "ClaudeGuard IP Whitelist",
            prompt: "Enter Whitelisted VPN IPs (comma separated):", value: allowedIPs.joined(separator: ", ")) else { return }
        let entries = entered.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? [] :
            entered.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard entries.allSatisfy({ validWhitelistEntry($0) }) else {
            let alert = NSAlert()
            alert.messageText = "Invalid IP/CIDR"
            alert.informativeText = "Enter IPv4/IPv6 addresses or CIDR ranges, separated by commas. No changes saved."
            alert.alertStyle = .warning
            alert.runModal()
            return
        }
        allowedIPs = entries
        saveConfig(); rebuildMenu(); recheckAsync()
    }

    @objc func onQuit() { NSApplication.shared.terminate(nil) }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
