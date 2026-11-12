import json
import ipaddress
import os
import sys

CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


def validate_whitelist_entry(value):
    value = value.strip()
    parts = value.split('/')
    try:
        if len(parts) > 2 or '%' in parts[0]:
            raise ValueError
        address = ipaddress.ip_address(parts[0])
        if len(parts) == 2:
            prefix = parts[1]
            if not prefix or any(c not in '0123456789' for c in prefix):
                raise ValueError
            if not 0 <= int(prefix) <= address.max_prefixlen:
                raise ValueError
            ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError('Invalid IP/CIDR. Use an IPv4/IPv6 address or CIDR prefix.') from None
    return value

DEFAULT_CONFIG = {
    "connection_mode": "vpn",
    "proxy_enabled": True,
    "proxy_profile": None,
    "allowed_ips": [],
    "protection_enabled": True,
    "model_override_enabled": False,
    "default_model": "claude-opus-4-8",
    "check_interval": 10,
    "blocked_domains": [
        "claude.com",
        "www.claude.com",
        "app.claude.com",
        "api.claude.com",
        "auth.claude.com",
        "claude.ai",
        "www.claude.ai",
        "app.claude.ai",
        "claude.usercontent.com",
        "anthropic.com",
        "www.anthropic.com",
        "console.anthropic.com",
        "api.anthropic.com",
        "stats.anthropic.com",
        "auth.anthropic.com",
        "assets-proxy.anthropic.com",
        "cdn.anthropic.com"
    ],
    "real_claude_cli_path": "/opt/homebrew/bin/claude",
    "real_claude_app_path": "/Applications/Claude.app"
}

class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.config = self.load_config()

    def load_config(self):
        self.ensure_dir()
        if not os.path.exists(self.path):
            self.ensure_dir()
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
        os.chmod(self.path, 0o600)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Fill missing default keys
                for k, v in DEFAULT_CONFIG.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception as e:
            print(f"[ClaudeGuard] Error reading config: {e}. Reverting to defaults.")
            return DEFAULT_CONFIG.copy()

    def save_config(self, data=None):
        if data is not None:
            self.config = data
        self.ensure_dir()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(self.config, f, indent=2, ensure_ascii=False)

    def ensure_dir(self):
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)

    @property
    def allowed_ips(self):
        return self.config.get("allowed_ips", [])

    @allowed_ips.setter
    def allowed_ips(self, ips):
        validated = [validate_whitelist_entry(ip) for ip in ips]
        self.config["allowed_ips"] = list(dict.fromkeys(validated))
        self.save_config()

    def add_ip(self, ip):
        ip = validate_whitelist_entry(ip)
        if ip and ip not in self.config["allowed_ips"]:
            self.config["allowed_ips"].append(ip)
            self.save_config()

    def remove_ip(self, ip):
        ip = ip.strip()
        if ip in self.config["allowed_ips"]:
            self.config["allowed_ips"].remove(ip)
            self.save_config()

    @property
    def protection_enabled(self):
        return self.config.get("protection_enabled", True)

    @protection_enabled.setter
    def protection_enabled(self, val):
        self.config["protection_enabled"] = bool(val)
        self.save_config()

    @property
    def check_interval(self):
        return self.config.get("check_interval", 10)

    @property
    def model_override_enabled(self):
        return self.config.get("model_override_enabled", False)

    @model_override_enabled.setter
    def model_override_enabled(self, val):
        self.config["model_override_enabled"] = bool(val)
        self.save_config()

    @property
    def default_model(self):
        return self.config.get("default_model", "claude-opus-4-8")

    @default_model.setter
    def default_model(self, val):
        self.config["default_model"] = str(val).strip()
        self.save_config()

    @property
    def real_claude_cli(self):
        return self.config.get("real_claude_cli_path", "/opt/homebrew/bin/claude")

    @property
    def real_claude_app(self):
        return self.config.get("real_claude_app_path", "/Applications/Claude.app")
