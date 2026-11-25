"""Exercise Windows Job Objects with a disposable child process."""

import subprocess
import sys
import unittest

from src.windows.windows_backend import _engine_job


@unittest.skipUnless(sys.platform == "win32", "Requires Windows Job Objects")
class WindowsEngineJobTests(unittest.TestCase):
    def test_closing_job_terminates_child_process(self):
        sleeper = "import time\nwhile True:\n    time.sleep(30)\n"
        with subprocess.Popen([sys.executable, "-I", "-c", sleeper]) as process:
            try:
                close_job = _engine_job(process)
                try:
                    self.assertIsNone(process.poll())
                finally:
                    close_job()
                process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()


if __name__ == "__main__":
    unittest.main()
