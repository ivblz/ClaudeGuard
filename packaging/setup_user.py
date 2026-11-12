"""Runs without root privileges during PKG installation."""
import os
import plistlib
import shutil
import sys
from pathlib import Path

source = Path(__file__).resolve().parent
home = Path.home()
install = home / '.local/share/ClaudeGuard'
install.mkdir(parents=True, exist_ok=True)
shutil.copytree(source / 'src', install / 'src', dirs_exist_ok=True)
shutil.copytree(source / 'bin', install / 'bin', dirs_exist_ok=True)
shutil.copy2(source / 'uninstall.sh', install / 'uninstall.sh')
for name in ('LICENSE', 'NOTICE'):
    shutil.copy2(source / name, install / name)
sys.path.insert(0, str(install))
from src.config import ConfigManager
from src.integrity import repair

config = ConfigManager()
for key in ('block_auto_updates', 'update_domains'):
    config.config.pop(key, None)
config.save_config()
pending = home / '.config/claudeguard/pending'
pending.mkdir(mode=0o700, parents=True, exist_ok=True)
pending.chmod(0o700)
for name in ('proxy.json', 'proxy.json.new'):
    secret = pending / name
    if secret.exists():
        secret.chmod(0o600)
(pending / 'request').touch()
cli = home / '.local/bin/claudeguard'
cli.parent.mkdir(parents=True, exist_ok=True)
if cli.is_symlink():
    cli.unlink()
if not cli.exists():
    cli.symlink_to(install / 'bin/claudeguard')
print(repair(config))

# Retire legacy auto-update locks, just as the source installer does.
targets = list((home / 'Library/Caches').glob('com.anthropic.claude*.ShipIt'))
targets.append(home / 'Library/Application Support/Claude/app-update.yml')
import subprocess
for target in targets:
    if target.exists():
        subprocess.run(['/usr/bin/chflags', '-R', 'nouchg', str(target)], check=True)
        subprocess.run(['/bin/chmod', '-R', 'u+rwX', str(target)], check=True)
legacy = home / 'Applications/ClaudeGuard.app'
if legacy.is_symlink() and os.readlink(legacy) == str(install / 'ClaudeGuard.app'):
    legacy.unlink()
for name in ('hosts-helper', 'pf-anchor', 'ClaudeGuardMenuBar'):
    (install / 'bin' / name).unlink(missing_ok=True)
(install / 'src/update_guard.py').unlink(missing_ok=True)
agent = home / 'Library/LaunchAgents/com.claudeguard.daemon.plist'
agent.parent.mkdir(parents=True, exist_ok=True)
with agent.open('wb') as stream:
    plistlib.dump({
        'Label': 'com.claudeguard.daemon',
        'ProgramArguments': ['/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar'],
        'RunAtLoad': True,
        'KeepAlive': {'SuccessfulExit': False},
        'StandardOutPath': '/tmp/claudeguard.log',
        'StandardErrorPath': '/tmp/claudeguard.err',
    }, stream)
agent.chmod(0o644)
