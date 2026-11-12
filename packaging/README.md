# macOS installer

Build without installing the app or changing the system firewall:

```bash
./build.sh
```

The result is `ClaudeGuard.pkg` in the project root. It is excluded from Git through `.gitignore` and can be attached to a GitHub Release. To set a different version, run `./build.sh 1.2.3`: the filename stays the same, while the version inside the package changes. The default version is `2.0.0`.

You can run the builder from any directory. It does not install anything. If the build fails, the previous `ClaudeGuard.pkg` remains in place. Temporary files are removed automatically.

Each build downloads SHA-256-pinned sing-box v1.14.4 binaries for both architectures. The resulting PKG contains the engine, the full GPLv3, project NOTICE and upstream license (including its naming condition); installation does not download the engine. Exact source: https://github.com/SagerNet/sing-box/tree/v1.14.4.

The package contains prebuilt arm64/x86_64 binaries and requires macOS 14 or later. Xcode Command Line Tools are required to build it.

The recipient's Mac also needs Xcode Command Line Tools: the app and privileged backend use `/usr/bin/python3`. If this dependency is missing, installation stops with instructions to run `xcode-select --install`. Python is not bundled with the package.

Open the PKG from the account that will use ClaudeGuard. The installer requires administrator privileges to install the app and system helper; user files and CLI hooks are created without root privileges. Automatic startup is configured for the current user. Installing on another disk or without an active user session is not supported. Network protection supports one user per Mac.

Upgrades preserve settings, proxy profiles and the whitelist. On first installation choose VPN and add its IP through Manage Whitelisted IPs…, or choose Proxy and configure a profile. An unconfigured mode blocks access. Your current IP is not added automatically.

Uninstall from Terminal:

```bash
~/.local/bin/claudeguard uninstall
```

By default, executables have ad hoc signatures; the PKG is not signed with an Apple certificate or notarized. Gatekeeper may block installation after a browser download. For a package you trust, you can allow it to open in System Settings → Privacy & Security. Do not disable Gatekeeper globally.

To create a signed build, specify certificates from your keychain:

```bash
CLAUDEGUARD_APP_SIGN_IDENTITY='Developer ID Application: NAME (TEAMID)' \
CLAUDEGUARD_INSTALLER_SIGN_IDENTITY='Developer ID Installer: NAME (TEAMID)' \
./build.sh 2.0.0
```

Then submit the package for notarization and staple the ticket separately:

```bash
xcrun notarytool submit ClaudeGuard.pkg --keychain-profile PROFILE --wait
xcrun stapler staple ClaudeGuard.pkg
```

This requires your own Developer ID certificates and a configured notarization profile. The builder does not create them or publish anything to GitHub.

## Compatibility limits

Including both architectures does not mean the package has been tested on every Mac. The full installation, blocking, upgrade, and uninstallation cycle has not yet been verified on physical Intel Macs or every macOS release from 14 onward.

- An active graphical user session, administrator privileges, and Python from Command Line Tools are required. Installing into another system or onto another disk is not supported.
- There is one system helper per Mac, tied to one user's configuration. The installer rejects upgrades from a different account; simultaneous protection for multiple users is not supported.
- The native PF helper uses saved definitions of Apple's private ABI. Targeting macOS 14 does not prove ABI compatibility with every kernel. Hosts fallback exists in some Proxy failure paths; VPN does not add hosts poisoning. A PF failure does not guarantee that direct connections or DNS over HTTPS are blocked.
- CLI discovery checks common installation paths and the saved custom path. An actual `claude` file that is not a symlink is not replaced. Paths without write access may also remain unguarded; `claudeguard doctor` reports this.
- Hosts and IP filtering are not a Network Extension: unknown domains, proxies, and service infrastructure changes require separate verification.
- The STUN check uses IPv4/UDP. An allowed result alone does not prove that TCP, IPv6, and individual apps use the same VPN route. Split tunneling and separate IPv4/IPv6 routes require additional network tests.
- Invalid JSON and incorrect whitelist/toggle types are rejected before services are stopped. This does not validate every app setting. Backing up `~/.config/claudeguard/config.json` before upgrading is useful.
- A configuration error after the PKG payload is extracted can leave partially updated files and stopped services. There is no automatic rollback of user settings or launchd changes.

Before claiming broad support, test on Intel and Apple Silicon: clean installation, upgrades, missing Claude/CLI installations, different CLI installation methods, VPN switching, IPv4/IPv6, coexistence with Internet Sharing and other PF tools, and uninstallation.
