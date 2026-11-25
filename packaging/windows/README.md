# ClaudeGuard for Windows

This preview targets 64-bit Windows 10 and 11 on x64 PCs. The ZIP includes Python, the tray app and the sing-box proxy engine.

1. Sign in with the Windows administrator account that will use ClaudeGuard. Run the release installer EXE, or extract the entire ZIP and open `Install.cmd` in the extracted `ClaudeGuard` folder and approve the administrator prompts.
2. Click the shield in the notification area to open the ClaudeGuard menu. Windows may put it under **Show hidden icons**.
3. Select **VPN** or **Proxy** in the menu. In **VPN** mode, connect your VPN and use **Manage Whitelisted IPs** to add its public IP or CIDR. In **Proxy** mode, use **Configure Proxy** to save your proxy URL or sing-box outbound JSON, then launch Claude through the tray.
4. Check the status at the top of the menu before using Claude. Setup starts with an empty whitelist and no proxy profile.

The executable is unsigned. Windows SmartScreen may show a warning. Verify the downloaded ZIP against its accompanying SHA-256 file.

```powershell
Get-FileHash .\ClaudeGuard.zip -Algorithm SHA256
```

## Coverage

ClaudeGuard manages Windows Defender Firewall rules for known Claude and Anthropic destination IPs. Its app-specific rules also cover recognized Claude Desktop and native Claude Code executable paths, including selected bundled Desktop helpers. Those rules restrict outbound traffic from the matching executables to verified VPN source addresses or, in verified Proxy mode, to loopback. A blocked or offline verdict applies full outbound blocking rules for those paths. The destination rules also apply to browsers and other programs.

Protection requires Windows Firewall and outbound local rules to be enabled on all profiles. Managed policy, split tunneling, a VPN with several interfaces, IPv4/IPv6 route changes, shared CDN addresses and newly resolved destinations can affect coverage. Shared-IP blocking can also affect unrelated sites. Existing connections can outlast a rule change.

VPN mode periodically verifies the public exit against the whitelist for IPv4 and IPv6 separately. A route change that keeps the same source address can take effect between checks. If the tray is force-terminated, its most recent rules can remain active until restart or cleanup, including any VPN source addresses already exempted.

Proxy mode uses a local HTTP proxy on `127.0.0.1:17943`. Launch Claude Desktop or Claude Code from the tray to pass proxy settings to those processes. For a browser, configure its HTTP and HTTPS proxy explicitly. Existing processes may need to be closed before using the tray launcher. The loopback exception also allows Claude to reach other local relays on the computer.

When a connection check confirms a block, ClaudeGuard closes recognized Claude Desktop and Claude Code processes for the signed-in user in the current Windows session. It continues checking for those processes while blocked, including when they are started outside the tray. After it confirms a Claude process exited, it shows one alert for that blocked period. A PowerShell or Command Prompt session that started Claude Code stays open.

Executable discovery covers paths for standard standalone and Microsoft Store Claude Desktop installations, the native Claude Code executable in `%USERPROFILE%\.local\bin`, and executable paths selected under **Configure Claude apps**. Claude Code running through npm or WSL, or on another computer, falls outside app-specific coverage. The tray refuses protected launches in **Offline**. Running Claude processes stay open while offline or while protection is disabled.

Standard per-user settings and runtime files are under `%APPDATA%\ClaudeGuard`. Windows Firewall rules apply to the computer. Use one ClaudeGuard configuration per PC.

## Startup, upgrades and removal

Setup installs ClaudeGuard into `%ProgramFiles%\ClaudeGuard-<user SID>` for the current user and adds Start menu and desktop shortcuts. Use either shortcut to reopen it. The extracted ZIP can be removed after setup.

Setup enables sign-in startup on the first install. Approve setup once. Task Scheduler starts the installed app with firewall permissions at sign-in. The tray menu lets you turn sign-in startup on or off. For an upgrade, quit ClaudeGuard and run `Install.cmd` from the newly extracted release. Upgrades keep settings and the existing sign-in preference.

Quitting with protection on leaves blocking rules for known destinations and identified executable paths in place. To uninstall, quit ClaudeGuard, select **Uninstall** in Windows **Installed apps** and approve the administrator prompt. You can also run `Uninstall.cmd` in the installation folder. The uninstaller clears ClaudeGuard's firewall rules and sign-in task before removing its files and shortcuts. Uninstall also deletes saved settings, IPs, proxy credentials, and runtime data from `%APPDATA%\ClaudeGuard`.

For portable use, run `ClaudeGuard.exe` directly from the extracted folder and keep its files together. Before deleting a portable copy, quit ClaudeGuard and run the following from an elevated PowerShell in its folder. Wait for a successful exit before deleting the folder.

```powershell
$cleanup = Start-Process -FilePath .\ClaudeGuard.exe -ArgumentList '--disable-protection' -Wait -PassThru
$cleanup.ExitCode
```

Delete `%APPDATA%\ClaudeGuard` only if you also want to remove saved settings and proxy credentials.

## Build from source

Build on Windows with **x64 CPython 3.14**, its Tcl/Tk and venv components, Windows PowerShell 5.1 or PowerShell 7, and internet access. Run from a checkout of ClaudeGuard.

```powershell
.\build-windows.ps1
```

The builder caches the engine archive in `%LOCALAPPDATA%\ClaudeGuardBuild` and creates a temporary virtual environment there, verifies the pinned sing-box archive SHA-256, and packages the GUI and the upstream sing-box files. It checks the bundled executable entry points and writes the ZIP and checksum to `dist/`. The build also creates an installer EXE and its SHA-256 checksum. Building requires no administrator privileges and creates no firewall rules or startup task.

For an unpackaged development run, install `requirements-windows.txt` in a virtual environment. Extract `sing-box.exe` and `libcronet.dll` from the same verified upstream archive into the checkout's `bin` folder, then run `python src/windows/windows_app.py`. You can also set `CLAUDEGUARD_SING_BOX` to the absolute path of a verified engine.

## Release validation

The build checks the packaged executable and engine on Windows. The workflow also runs the Windows unit tests, a loopback proxy test and the macOS test suite. Local checks exercised Windows Firewall rule creation, replacement and removal for documentation-only IP addresses. They also launched the installed Claude Code CLI with the signed-in user's Windows token and verified that Claude Desktop sent HTTPS proxy requests to a loopback test server. Live VPN and upstream proxy validation are still pending.

- Whitelist a real VPN exit. With protection on, verify allowed traffic on a matching exit and blocking after disconnect or a switch to an unlisted exit. Check IPv4 and IPv6 separately.
- In Proxy mode, start fresh Claude Desktop and Claude Code sessions through the tray. Verify the local proxy is used and direct outbound connections from recognized executables are blocked, then check that an invalid or unreachable proxy blocks launch.
- Start Claude Desktop and native Claude Code on an allowed connection, then switch to a confirmed blocked connection. Verify that both close, the shell that started Claude Code stays open, and ClaudeGuard shows one closure alert. Start Claude outside the tray again while blocked and verify that it closes without a second closure alert.
- Quit while protection is on and verify that blocking rules persist. Turn off protection and verify that only ClaudeGuard-owned rules are removed.
- Install with `Install.cmd` and verify ClaudeGuard opens from both shortcuts. Sign out and back in and verify automatic startup without a UAC prompt. Verify the tray and protection resume. Quit the tray and test removal from Windows Installed apps.
- Check that the macOS CI job passes and run the macOS tray, launch and protection smoke tests on a Mac.

## Source and notices

The release includes a copy of the GPLv3 and third-party notices. [ClaudeGuard source](https://github.com/ivblz/ClaudeGuard)

The package includes the upstream Windows x64 engine and its Cronet DLL. [Official sing-box 1.14.4 release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4), [sing-box source](https://github.com/SagerNet/sing-box/tree/v1.14.4), [upstream build instructions](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/installation/build-from-source.md), [Cronet Go source](https://github.com/SagerNet/cronet-go/tree/0d28acc44093)

The notification-area icon uses pystray. [pystray 0.19.5 source](https://pypi.org/project/pystray/0.19.5/#files)
