"""Windows configuration paths and atomic persistence."""
import copy
import json
import os
import tempfile

from src.config import ConfigManager as BaseConfigManager, DEFAULT_CONFIG as BASE_DEFAULTS, validate_whitelist_entry

CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~/AppData/Roaming")), "ClaudeGuard")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DEFAULT_CONFIG = {**BASE_DEFAULTS, "real_claude_cli_path": "", "real_claude_app_path": ""}


class ConfigManager(BaseConfigManager):
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.config = self.load_config()

    def load_config(self):
        self.ensure_dir()
        if not os.path.exists(self.path):
            self.ensure_dir()
            self.save_config(copy.deepcopy(DEFAULT_CONFIG))
            return self.config
        os.chmod(self.path, 0o600)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError('Expected a configuration object')
                # Fill missing default keys
                for k, v in DEFAULT_CONFIG.items():
                    if k not in data:
                        data[k] = copy.deepcopy(v)
                return data
        except Exception as e:
            print(f"[ClaudeGuard] Error reading config: {e}. Reverting to defaults.")
            return copy.deepcopy(DEFAULT_CONFIG)

    def save_config(self, data=None):
        if data is not None:
            self.config = data
        self.ensure_dir()
        fd, temporary = tempfile.mkstemp(prefix='.config-', suffix='.tmp',
                                         dir=os.path.dirname(os.path.abspath(self.path)))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
