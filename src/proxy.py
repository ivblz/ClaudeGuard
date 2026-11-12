"""User-side proxy preparation, health check and CLI environment."""
import hashlib
import ipaddress
import json
import os
import subprocess
import time
from src import trace_timing as trace
from pathlib import Path
from src.proxy_config import parse_profile, validate, PORT


def profile_id(config):
    return hashlib.sha256(json.dumps(config.config.get('proxy_profile'), sort_keys=True).encode()).hexdigest()


def save_profile(config, text):
    # An empty settings field explicitly removes the saved profile.
    profile = parse_profile(text) if text.strip() else None
    config.config['proxy_profile'] = profile
    config.save_config()
    os.chmod(config.path, 0o600)
    return profile


def environment(env):
    env = dict(env)
    for key in list(env):
        if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
            del env[key]
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env[key] = f'http://127.0.0.1:{PORT}'
    env['NO_PROXY'] = env['no_proxy'] = ''
    return env


def probe(timeout=5):
    for attempt, endpoint in enumerate(('https://api.ipify.org', 'https://checkip.amazonaws.com'), 1):
        started = trace.begin() if trace.enabled else None
        outcome = "error"
        try:
            result = subprocess.run(['/usr/bin/curl', '-q', '--silent', '--fail', '--max-time', str(timeout),
                                     '--proxy', f'http://127.0.0.1:{PORT}', '--noproxy', '', endpoint],
                                    capture_output=True, text=True, timeout=timeout + 1,
                                    env=environment(os.environ))
            if result.returncode == 0:
                ip = str(ipaddress.ip_address(result.stdout.strip()))
                outcome = "ok"
                return ip
        except (ValueError, subprocess.TimeoutExpired):
            continue
        finally:
            if trace.enabled:
                trace.end(started, "proxy.exit_ip.attempt_" + str(attempt), outcome)
    raise RuntimeError('Proxy connection failed (authentication, server or network unavailable)')


@trace.stage("proxy.prepare.retry_3_sleep_300ms")
def prepare(config):
    from src.network_guard import sync_hosts_file
    validate(config.config.get('proxy_profile'))
    ok, error = sync_hosts_file(False, config)
    if not ok:
        raise RuntimeError(error)
    # launchd may need a moment to start the listeners.
    error = None
    for _ in range(3):
        try:
            return probe()
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            error = exc
            time.sleep(0.3)
    raise error
