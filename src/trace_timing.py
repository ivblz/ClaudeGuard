"""Opt-in timings; never record arguments, values, output or exception messages.
Disabled paths do not read clocks or write logs. Root records use a per-request
diagnostics tag and append as the config owner, never open a user-controlled file as root.
"""
import datetime
import functools
import hashlib
import os
from pathlib import Path
import time

enabled = os.environ.get('CLAUDEGUARD_TRACE') == '1'
directory = Path.home() / '.config/claudeguard'


def configure(config, path=None):
    global enabled, directory
    enabled = os.environ.get('CLAUDEGUARD_TRACE') == '1' or config.get('trace') is True
    if path is not None:
        directory = Path(path)


def begin():
    return time.monotonic() if enabled else None


def end(start, stage, result='ok'):
    if start is None:
        return
    emit(stage, (time.monotonic() - start) * 1000, result)


def emit(stage, duration, result='ok'):
    # All callers supply static labels/status, never user data or error text.
    if not enabled:
        return
    line = f'{datetime.datetime.now(datetime.timezone.utc).isoformat()} stage={stage} duration_ms={duration:.3f} result={result}\n'
    try:
        if os.geteuid() == 0:
            # Privileged helper is serialized. Drop credentials in a child so
            # symlinks in the user's config cannot redirect a root write.
            owner = directory.stat()
            pid = os.fork()
            if pid:
                os.waitpid(pid, 0)
                return
            try:
                os.setgroups([])
                os.setgid(owner.st_gid)
                os.setuid(owner.st_uid)
                _append(line)
            finally:
                os._exit(0)
        else:
            _append(line)
    except (OSError, ValueError):
        pass  # Diagnostics must never affect enforcement.


def _append(line):
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0) | os.O_NONBLOCK
    fd = os.open(str(directory / 'trace.log'), flags, 0o600)
    try:
        import stat
        if stat.S_ISREG(os.fstat(fd).st_mode):
            os.write(fd, line.encode())
    finally:
        os.close(fd)


def stage(name):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            if not enabled:
                return function(*args, **kwargs)
            start = begin()
            result = 'error'
            try:
                value = function(*args, **kwargs)
                result = 'ok'
                return value
            finally:
                end(start, name, result)
        return wrapped
    return decorate


def host_label(host):
    return 'host_' + hashlib.sha256(host.encode()).hexdigest()[:10]
