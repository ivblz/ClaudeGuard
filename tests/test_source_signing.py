"""Exercise the source installer's actual bundle signing on macOS."""
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'Requires macOS codesign')
class SourceSigningTests(unittest.TestCase):
    def test_bundle_resources_remain_valid_after_repeated_source_builds(self):
        installer = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
        start = installer.index('cp "$INSTALL_DIR/bin/ClaudeGuardMenuBar"')
        commands = installer[start:installer.index('# --- 4.', start)]
        with tempfile.TemporaryDirectory(prefix='cg-signing-') as directory:
            root = Path(directory)
            executable = root / 'bin/ClaudeGuardMenuBar'
            executable.parent.mkdir()
            app = root / 'ClaudeGuard.app'
            contents = app / 'Contents'
            (contents / 'MacOS').mkdir(parents=True)
            (contents / 'Resources').mkdir()
            (contents / 'Info.plist').write_bytes(plistlib.dumps({
                'CFBundleExecutable': 'ClaudeGuardMenuBar',
                'CFBundleIdentifier': 'com.claudeguard.signing-test',
                'CFBundlePackageType': 'APPL',
            }))
            for revision in range(2):
                executable.unlink(missing_ok=True)
                shutil.copyfile('/usr/bin/true', executable)
                executable.chmod(0o755)
                subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(executable)],
                               check=True, capture_output=True)
                (contents / 'Resources/resource.txt').write_text(str(revision))
                subprocess.run(['/bin/bash', '-euc', commands], check=True, capture_output=True,
                               env={'PATH': '/usr/bin:/bin', 'INSTALL_DIR': str(root),
                                    'BUILD_APP_BUNDLE': str(app)})
                subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(app)],
                               check=True, capture_output=True)
                # Verify the signature seals resources, rather than merely the binary.
                (contents / 'Resources/resource.txt').write_text('tampered')
                invalid = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(app)],
                                         capture_output=True)
                self.assertNotEqual(invalid.returncode, 0)


if __name__ == '__main__':
    unittest.main()
