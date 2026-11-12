#!/usr/bin/env python3
"""Native regression of real menu mode handling; no UI or real settings touched."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/main.swift').read_text().split('let app = NSApplication.shared\n')[0]
source = source.replace(
    'let configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath',
    'var configPath = ""')
harness = r'''
final class ModeHarness: AppDelegate {
    var changeModeDuringProbe = false
    var prepared = true
    var syncCalls = 0
    var probeCalls = 0
    var syncArguments: [String] = []
    var failAllow = false
    override func resolvePublicIPWithRetry(attempts: Int = 2, deadline: TimeInterval = 2.0) -> String? {
        precondition(syncArguments.last == "true", "VPN must be blocked before first IP lookup")
        return "192.0.2.1"
    }
    override func killDesktopIfRunning() -> Bool { false }
    override func checkProxy() -> (ip: String?, error: String, profileID: String, prepared: Bool) {
        probeCalls += 1
        if changeModeDuringProbe { onModeChanged(.vpn) }
        return ("192.0.2.2", "", "test-profile", prepared)
    }
    override func runHelper(_ command: String, _ a1: String, _ a2: String) -> Bool {
        syncCalls += 1
        syncArguments.append(a1)
        return !(failAllow && a1 == "false")
    }
    override func hostsDrifted() -> Bool { false }
    override func writeStateFile() {}
    override func rebuildMenu() {}
    override func updateStatusDisplay(isDimmed: Bool = false) {}
    override func startBlinking() {}
    override func recheck() {}
}
let check = ModeHarness()
for entry in ["192.0.2.1", "192.0.2.1/24", "0.0.0.0/0", "2001:db8::1", "2001:db8::1/64", "::/0", "::1/128"] {
    precondition(check.validWhitelistEntry(entry), entry)
}
for entry in ["", "example.com", "999.1.1.1", "127.1", "01.2.3.4", "192.0.2.1/33", "::1/129", "::1/-1", "::1/", "::1/1/2", "fe80::1%en0", "192.0.2.1/255.255.255.0"] {
    precondition(!check.validWhitelistEntry(entry), entry)
}
check.configPath = CommandLine.arguments[1]
let initial: [String: Any] = ["proxy_profile": ["type": "http", "server": "localhost", "server_port": 3128]]
try! JSONSerialization.data(withJSONObject: initial).write(to: URL(fileURLWithPath: check.configPath))
check.connectionMode = .proxy
check.currentIP = "192.0.2.2"
check.proxyProfileID = "old-profile"
check.saveConfig()
precondition((try! FileManager.default.attributesOfItem(atPath: check.configPath)[.posixPermissions] as! NSNumber).intValue == 0o600)
precondition((try! FileManager.default.attributesOfItem(atPath: (check.configPath as NSString).deletingLastPathComponent)[.posixPermissions] as! NSNumber).intValue == 0o700)
check.onModeChanged(.vpn)
precondition(check.currentIP == "…" && check.proxyProfileID.isEmpty)
precondition(check.state == .offline)

check.connectionMode = .proxy
check.saveConfig()
check.changeModeDuringProbe = true
check.performCheck()
precondition(check.connectionMode == .vpn && check.currentIP == "…")
precondition(check.proxyProfileID.isEmpty && check.state == .offline)
precondition(check.syncCalls == 0)

check.changeModeDuringProbe = false
check.connectionMode = .proxy
check.saveConfig()
check.performCheck()
precondition(check.currentIP == "192.0.2.2")
precondition(check.state == .allowed(ip: "192.0.2.2"))
precondition(check.syncCalls == 0, "A prepared proxy must not apply the same rules twice")

check.prepared = false
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.syncCalls == 1, "A health-only probe cannot skip enforcement")
let calls = check.probeCalls
try! JSONSerialization.data(withJSONObject: ["connection_mode": "proxy", "protection_enabled": true]).write(to: URL(fileURLWithPath: check.configPath))
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.probeCalls == calls, "An empty profile must never probe a connection")
precondition(check.state == .blocked(ip: "Unavailable"))
precondition(check.statusText().contains("Proxy not configured"))
precondition(check.syncCalls == 2, "Removal must apply blocking once")
check.performCheck()
precondition(check.syncCalls == 2, "An unchanged empty profile must not repeat enforcement")
check.connectionMode = .vpn
check.allowedIPs = ["192.0.2.1"]
check.saveConfig()
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.state == .allowed(ip: "192.0.2.1"))
precondition(Array(check.syncArguments.suffix(2)) == ["true", "false"])
check.failAllow = true
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.state == .blocked(ip: "192.0.2.1"))
precondition(!check.statusText().contains("Protected"))
print("PASS: mode reset, stale result discarded, no duplicate proxy sync, health-only probe enforces rules")
'''
with tempfile.TemporaryDirectory(prefix='cg-menu-mode-') as directory:
    path = Path(directory)
    (path / 'main.swift').write_text(source + harness)
    subprocess.run(['xcrun', 'swiftc', '-module-cache-path', str(path / 'modules'),
                    str(path / 'main.swift'), str(root / 'src/ModeSegmentedControl.swift'),
                    '-o', str(path / 'check')], check=True)
    subprocess.run([str(path / 'check'), str(path / 'config.json')], check=True)
