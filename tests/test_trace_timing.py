"""Diagnostics regressions; only temporary files and mocked subprocesses."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import trace_timing as trace
from src import proxy


class TraceTests(unittest.TestCase):
    def tearDown(self):
        trace.configure({})

    def test_disabled_reads_no_clock_and_creates_no_log(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'CLAUDEGUARD_TRACE': '0'}):
            trace.configure({}, directory)
            @trace.stage('test.disabled')
            def work():
                return 42
            with patch.object(trace.time, 'monotonic', side_effect=AssertionError('clock read')):
                self.assertEqual(work(), 42)
                self.assertIsNone(trace.begin())
                trace.end(None, 'test.disabled')
                trace.emit('test.disabled', 0)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_config_opt_in_logs_duration_and_only_static_error(self):
        with tempfile.TemporaryDirectory() as directory:
            trace.configure({'trace': True}, directory)
            @trace.stage('test.failure')
            def work():
                raise ValueError('http://secret:password@192.0.2.1:99')
            with self.assertRaises(ValueError):
                work()
            log = (Path(directory) / 'trace.log').read_text()
            self.assertIn('stage=test.failure duration_ms=', log)
            self.assertIn('result=error', log)
            for secret in ('secret', 'password', '192.0.2.1', 'http://'):
                self.assertNotIn(secret, log)

    def test_environment_opt_in_and_per_attempt_exit_ip_redaction(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'CLAUDEGUARD_TRACE': '1'}):
            trace.configure({}, directory)
            with patch.object(proxy.subprocess, 'run', side_effect=[
                    SimpleNamespace(returncode=1, stdout=''),
                    SimpleNamespace(returncode=0, stdout='192.0.2.1')]):
                self.assertEqual(proxy.probe(), '192.0.2.1')
            log = (Path(directory) / 'trace.log').read_text()
            self.assertIn('proxy.exit_ip.attempt_1', log)
            self.assertIn('proxy.exit_ip.attempt_2', log)
            self.assertNotIn('192.0.2.1', log)
            self.assertNotIn('ipify', log)
