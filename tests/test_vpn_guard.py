"""VPN fail-closed transitions using fake PF and subprocesses only."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import network_guard as guard
from src import pf_controller as backend
from test_pf_controller import FakePF, DEFAULT_ROOT


class VPNGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pending = self.root / 'pending'
        self.pending.mkdir()
        self.fake = FakePF()
        self.controller = backend.PFController(self.root, self.fake)
        self.hosts = self.root / 'hosts'
        self.hosts.write_text('127.0.0.1 localhost\n192.0.2.7 private.example\n')
        self.addresses = ['160.79.104.0/24', '2607:6bc0::/32']
        (self.pending / 'request').write_text('a' * 32)
        (self.pending / 'pf.rule').write_text(backend.make_rule(self.addresses))
        (self.pending / 'proxy.json').write_text('null')
        self.stage(True)

    def stage(self, allow):
        (self.pending / 'vpn.json').write_text(json.dumps({'allow': allow, 'allowed_ips': ['192.0.2.1']}))
        (self.pending / 'hosts.tmp').write_text('127.0.0.1 localhost\n')

    def apply(self, verifier=None):
        # No real root services, hosts, PF, network requests or desktop launch.
        with patch.object(backend, 'HOSTS_PATH', self.hosts), \
             patch.object(backend.subprocess, 'run'), \
             patch('proxy_service.stop') as stop, \
             patch.object(backend, 'verified_vpn_interface', side_effect=verifier or (lambda allowed: 'utun4')):
            backend.apply_request(self.root, self.controller)
        return stop

    def test_allow_installs_denial_before_verifying_and_preserves_foreign_rules(self):
        def verify(allowed):
            self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])
            self.assertIn('block drop', self.fake.anchors[backend.ANCHOR])
            return 'utun4'
        self.apply(verify)
        rule = self.fake.anchors[backend.ANCHOR]
        self.assertIn('on utun4 inet', rule)
        self.assertIn('keep state (if-bound)', rule)
        self.assertTrue(rule.endswith('block drop out quick proto { tcp, udp } to <claude_guard>\n'))
        self.assertNotIn('user != 0', rule)
        self.assertNotIn('pass out quick on utun4 inet6', rule)
        self.assertIn(DEFAULT_ROOT, self.fake.root)
        self.assertEqual(self.fake.anchors['com.apple/vpn'], 'pass quick all')
        self.assertIn('private.example', self.hosts.read_text())
        self.assertIn('777', self.fake.references)

    def test_verification_failure_leaves_unconditional_denial(self):
        self.apply()
        def fail(allowed):
            raise backend.PFError('verification failed')
        with self.assertRaises(backend.PFError):
            self.apply(fail)
        self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])
        status = json.loads((self.root / 'network-status.json').read_text())
        self.assertFalse(status['ok'])

    def test_same_tunnel_recheck_does_not_kill_existing_sessions(self):
        self.apply()
        self.fake.calls.clear()
        stop = self.apply()
        self.assertFalse(any(args[0] == '-k' for args, _ in self.fake.calls))
        stop.assert_not_called()

    def test_removed_whitelist_closes_existing_tunnel(self):
        self.apply()
        self.stage(False)
        self.apply(lambda allowed: self.fail('must not verify a denial'))
        self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])
        self.assertNotIn('claude.ai', self.hosts.read_text())

    def test_proxy_stop_failure_cannot_open_direct_traffic(self):
        with patch('proxy_service.stop', side_effect=RuntimeError('stop failed')), \
             patch.object(backend, 'verified_vpn_interface') as verify, \
             self.assertRaises(backend.PFError):
            backend.apply_request(self.root, self.controller)
        verify.assert_not_called()
        self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])

    def test_added_targets_have_old_states_removed_and_old_dns_stays_protected(self):
        self.apply()
        self.fake.calls.clear()
        (self.pending / 'pf.rule').write_text(backend.make_rule(['192.0.2.8']))
        self.apply()
        rule = self.fake.anchors[backend.ANCHOR]
        self.assertIn('160.79.104.0/24', rule)
        self.assertIn('192.0.2.8', rule)
        self.assertIn((('-k', '0.0.0.0/0', '-k', '192.0.2.8'), None), self.fake.calls)
        self.stage(False)
        (self.pending / 'pf.rule').write_text(backend.make_rule(['160.79.104.0/24']))
        self.apply()
        self.assertIn('192.0.2.8', self.fake.anchors[backend.ANCHOR])
        self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])

    def test_legacy_hosts_cleanup_follows_pf_and_preserves_foreign_entries(self):
        legacy = backend.HEADER + '::1 claude.ai\n' + backend.FOOTER
        self.hosts.write_text(self.hosts.read_text() + legacy)
        self.stage(False)
        (self.pending / 'hosts.tmp').write_text(legacy)
        self.apply()
        self.assertNotIn('claude.ai', self.hosts.read_text())
        self.assertIn('private.example', self.hosts.read_text())
        self.assertNotIn('pass out', self.fake.anchors[backend.ANCHOR])

    def test_failed_pf_install_does_not_remove_legacy_hosts_protection(self):
        legacy = backend.HEADER + '::1 claude.ai\n' + backend.FOOTER
        self.hosts.write_text(self.hosts.read_text() + legacy)
        self.fake.fail = ('-a', backend.ANCHOR, '-f', '-')
        with self.assertRaises(backend.PFError):
            self.apply()
        self.assertIn(legacy, self.hosts.read_text())

    def test_invalid_interface_cannot_inject_pf_rules(self):
        for interface in ('en0', 'utun199', 'utun4\npass all', '', None):
            with self.subTest(interface=interface), self.assertRaises(backend.PFError):
                backend.make_vpn_rule(self.addresses, interface)

    def test_request_generation_keeps_pf_for_allowed_and_blocked_vpn_without_hosts_poisoning(self):
        config = SimpleNamespace(protection_enabled=True, config={
            'connection_mode': 'vpn', 'allowed_ips': ['192.0.2.1'], 'blocked_domains': []})
        for blocked in (False, True):
            with self.subTest(blocked=blocked), patch.object(guard, 'HOSTS_PATH', str(self.hosts)), \
                 patch.object(guard, 'PENDING_DIR', str(self.pending)), \
                 patch.object(guard, 'PF_RULE_PATH', str(self.pending / 'pf.rule')), \
                 patch.object(guard, 'resolve_ips', return_value={'192.0.2.8'}), \
                 patch.object(guard, 'write_hosts') as write:
                ok, error = guard.sync_hosts_file(blocked, config)
            self.assertTrue(ok, error)
            self.assertIn('2607:6bc0::/32', (self.pending / 'pf.rule').read_text())
            self.assertEqual(json.loads((self.pending / 'vpn.json').read_text())['allow'], not blocked)
            self.assertNotIn(guard.BLOCK_HEADER, write.call_args.args[0])


class VPNProofTests(unittest.TestCase):
    def test_probe_is_interface_bound_and_route_rechecked(self):
        route = subprocess.CompletedProcess([], 0, ' interface: utun4\n', '')
        answer = subprocess.CompletedProcess([], 0, '192.0.2.1\n', '')
        with patch.object(backend.subprocess, 'run', side_effect=[route, answer, route]) as run:
            self.assertEqual(backend.verified_vpn_interface(['192.0.2.0/24']), 'utun4')
        cmd = run.call_args_list[1].args[0]
        self.assertEqual(cmd[cmd.index('--interface') + 1], 'utun4')
        self.assertEqual(cmd[cmd.index('--proxy') + 1], '')
        self.assertEqual(run.call_args_list[1].kwargs['env'], {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})

    def test_wrong_ip_physical_route_and_changed_route_fail_closed(self):
        route = subprocess.CompletedProcess([], 0, ' interface: utun4\n', '')
        wrong = subprocess.CompletedProcess([], 0, '203.0.113.1', '')
        correct = subprocess.CompletedProcess([], 0, '192.0.2.1', '')
        physical = subprocess.CompletedProcess([], 0, ' interface: en0\n', '')
        for answers in ([physical], [route, wrong], [route, correct, physical]):
            with self.subTest(answers=answers), patch.object(backend.subprocess, 'run', side_effect=answers), \
                 self.assertRaises(backend.PFError):
                backend.verified_vpn_interface(['192.0.2.1'])
