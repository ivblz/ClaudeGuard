"""Installer orchestration. Only root-owned payload is ever executed as root."""
import os
import plistlib
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HELPER = Path('/Library/Application Support/ClaudeGuard')
HELPER_PLIST = Path('/Library/LaunchDaemons/com.claudeguard.helper.plist')
APP = '/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar'

# Executed as the target user before stopping any services. Never import a
# user-writable module into the privileged installer process.
USER_PREFLIGHT = r'''
import json, os, stat
from pathlib import Path
path = Path.home() / '.config/claudeguard/config.json'
if path.exists():
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise RuntimeError('Invalid ClaudeGuard config file; installation stopped.')
        try:
            text = stream.read(1024 * 1024 + 1)
            if len(text) > 1024 * 1024:
                raise ValueError('Config too large')
            config = json.loads(text)
        except (ValueError, UnicodeError) as error:
            raise RuntimeError('Invalid ClaudeGuard config JSON; fix or back it up before installing.') from error
    if not isinstance(config, dict):
        raise RuntimeError('ClaudeGuard config must be a JSON object.')
    ips = config.get('allowed_ips', [])
    if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
        raise RuntimeError('ClaudeGuard allowed_ips must be a list of strings.')
    for key in ('protection_enabled', 'model_override_enabled'):
        if key in config and not isinstance(config[key], bool):
            raise RuntimeError('ClaudeGuard ' + key + ' must be true or false.')
'''


def console_account():
    account = pwd.getpwuid(os.stat('/dev/console').st_uid)
    if account.pw_uid < 501 or account.pw_name in ('root', 'loginwindow', '_mbsetupuser'):
        raise RuntimeError('Log in to the Mac as the intended ClaudeGuard user before installing.')
    if not Path(account.pw_dir).is_dir():
        raise RuntimeError('The logged-in user has no home directory.')
    return account


def run(*args, check=True):
    return subprocess.run(args, check=check)


def run_as_user(account, *args):
    return run('/bin/launchctl', 'asuser', str(account.pw_uid),
               '/usr/bin/sudo', '-H', '-u', account.pw_name,
               '/usr/bin/env', 'HOME=' + account.pw_dir,
               'PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin', *args)


def check_existing_owner(home):
    if not HELPER_PLIST.exists():
        return
    with HELPER_PLIST.open('rb') as stream:
        body = plistlib.load(stream)
    args = body.get('ProgramArguments', [])
    if len(args) != 2 or not isinstance(args[1], str):
        raise RuntimeError('Unrecognised existing ClaudeGuard helper configuration; installation stopped.')
    if os.path.realpath(args[1]) != os.path.realpath(home / '.config/claudeguard'):
        raise RuntimeError('ClaudeGuard is configured for another user. Update from that account, '
                           'or uninstall it there before switching users.')


def prepare_executables():
    # Installer may overwrite an existing Mach-O inode. Replace it before first
    # execution so macOS cannot reuse a cached signature for the old contents.
    for binary in (HELPER / 'sing-box', HELPER / 'hosts-helper',
                   HELPER / 'pf-anchor', Path(APP)):
        fd, temporary = tempfile.mkstemp(prefix='.' + binary.name + '.', dir=binary.parent)
        os.close(fd)
        try:
            shutil.copy2(binary, temporary)
            os.replace(temporary, binary)
        finally:
            Path(temporary).unlink(missing_ok=True)
        run('/usr/bin/codesign', '--verify', '--strict', str(binary))
    # This must succeed before starting either privileged helpers or the UI.
    run(str(HELPER / 'sing-box'), 'version')


def configure(phase):
    account = console_account()
    uid = str(account.pw_uid)
    home = Path(account.pw_dir)
    agent = home / 'Library/LaunchAgents/com.claudeguard.daemon.plist'
    if phase == 'preinstall':
        # Fail all prerequisite checks before stopping the previous version.
        check_existing_owner(home)
        run_as_user(account, '/usr/bin/python3', '-I', '-c', USER_PREFLIGHT)
        run('/bin/launchctl', 'bootout', 'gui/' + uid, str(agent), check=False)
        run('/usr/bin/pkill', '-u', uid, '-x', 'ClaudeGuardMenuBar', check=False)
        run('/bin/launchctl', 'bootout', 'system/com.claudeguard.proxy', check=False)
        run('/bin/launchctl', 'bootout', 'system', str(HELPER_PLIST), check=False)
        return
    # User-writable files and CLI hooks are created strictly as the user.
    check_existing_owner(home)
    prepare_executables()
    run_as_user(account, '/usr/bin/python3', '-I', '-c', USER_PREFLIGHT)
    run_as_user(account, '/usr/bin/python3', '-I', str(HELPER / 'Runtime/setup_user.py'))
    config = home / '.config/claudeguard'
    body = {
        'Label': 'com.claudeguard.helper',
        'ProgramArguments': [str(HELPER / 'hosts-helper'), str(config)],
        'WatchPaths': [str(config / 'pending/request')],
        'ThrottleInterval': 1,
        'StandardOutPath': '/tmp/claudeguard-helper.log',
        'StandardErrorPath': '/tmp/claudeguard-helper.err',
    }
    with HELPER_PLIST.open('wb') as stream:
        plistlib.dump(body, stream)
    HELPER_PLIST.chmod(0o644)
    legacy = Path('/etc/sudoers.d/claudeguard')
    if legacy.exists():
        legacy.unlink()
    run('/bin/launchctl', 'bootstrap', 'system', str(HELPER_PLIST))
    run('/bin/launchctl', 'bootstrap', 'gui/' + uid, str(agent))
    print('ClaudeGuard installed. Choose VPN and add its IP, or choose Proxy and configure a profile in the menu bar.')


if __name__ == '__main__':
    configure(sys.argv[1])
