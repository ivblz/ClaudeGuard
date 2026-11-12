import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from src import brain, proxy_config, proxy
from src.config import ConfigManager
from src.pf_controller import parse_rule, make_rule


class ProxyTests(unittest.TestCase):
    def test_empty_profile_has_setup_message(self):
        with self.assertRaisesRegex(ValueError, 'not configured'):
            proxy_config.validate(None)
        with self.assertRaisesRegex(ValueError, 'Enter a proxy URL'):
            proxy_config.parse_profile('  ')

    def test_urls_credentials_and_ipv6(self):
        p = proxy_config.parse_profile('socks5://user:p%40ss@[::1]:1080')
        self.assertEqual((p['server'], p['password'], p['version']), ('::1', 'p@ss', '5'))
        p = proxy_config.parse_profile('https://user:pass@proxy.example:443')
        self.assertTrue(p['tls']['enabled'])
        self.assertEqual(p['type'], 'http')

    def test_profile_cannot_supply_privileged_engine_options(self):
        base = {'type': 'http', 'server': 'proxy.example', 'server_port': 443}
        for extra in [{'detour': 'direct'}, {'tls': {'enabled': True, 'insecure': True}},
                      {'tls': {'enabled': True, 'certificate_path': '/etc/shadow'}},
                      {'transport': {'type': 'ws', 'file': '/etc/passwd'}},
                      {'server_port': 65536}, {'server': 'localhost', 'server_port': proxy_config.PORT}, {'server': 'bad\nserver'}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                proxy_config.validate(dict(base, **extra))

    def test_engine_routes_are_scoped_and_local_listener_is_loopback(self):
        config = proxy_config.engine_config(proxy_config.parse_profile('socks5://localhost:1080'),
                                             ['192.0.2.1', '2001:db8::1'], ['claude.ai'])
        self.assertNotIn('0.0.0.0/0', config['inbounds'][0]['route_address'])
        self.assertEqual(config['inbounds'][1]['listen'], '127.0.0.1')
        self.assertNotIn('platform', config['inbounds'][0])
        self.assertEqual(config['outbounds'][0]['tag'], 'proxy')

    def test_environment_overrides_bypass_without_changing_parent(self):
        env = {'HTTPS_PROXY': 'http://old:1234', 'no_proxy': '*', 'PATH': '/bin'}
        result = proxy.environment(env)
        self.assertEqual(result['NO_PROXY'], '')
        self.assertEqual(result['no_proxy'], '')
        self.assertEqual(result['HTTPS_PROXY'], 'http://127.0.0.1:17943')
        self.assertEqual(env['no_proxy'], '*')

    def test_owned_quic_rejected_before_sniff_without_silent_drop(self):
        config = proxy_config.engine_config(proxy_config.parse_profile('http://localhost:1080'),
                                             ['192.0.2.1'], ['claude.ai'])
        rules = config['route']['rules']
        reject = rules[0]
        self.assertEqual(reject['network'], 'udp')
        self.assertEqual(reject['ip_cidr'], proxy_config.DEDICATED)
        self.assertEqual(reject['action'], 'reject')
        self.assertEqual(reject['method'], 'default')
        self.assertTrue(reject['no_drop'])
        self.assertEqual(rules[1]['action'], 'sniff')

    def test_proxy_never_accepts_vpn_or_old_profile_verdict(self):
        config = SimpleNamespace(protection_enabled=True, config={'connection_mode': 'proxy',
            'proxy_profile': proxy_config.parse_profile('http://localhost:3128')})
        for state in [None, {'mode': 'vpn', 'state': 'allowed'},
                      {'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': 'old'}]:
            with patch.object(brain, 'read_daemon_state', return_value=state):
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')
        state = {'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': proxy.profile_id(config), 'ip': '192.0.2.1'}
        with patch.object(brain, 'read_daemon_state', return_value=state):
            self.assertEqual(brain.get_verdict(config)[0], 'allowed')
            config.config['proxy_enabled'] = False
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_health_check_tolerates_one_echo_service_outage(self):
        responses = [SimpleNamespace(returncode=22, stdout=''), SimpleNamespace(returncode=0, stdout='192.0.2.1\n')]
        with patch.object(proxy.subprocess, 'run', side_effect=responses) as run:
            self.assertEqual(proxy.probe(), '192.0.2.1')
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all('--proxy' in call.args[0] for call in run.call_args_list))

    def test_credentials_saved_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(os.path.join(directory, 'config.json'))
            proxy.save_profile(config, 'http://user:secret@localhost:3128')
            self.assertEqual(os.stat(config.path).st_mode & 0o777, 0o600)

    def test_removing_profile_clears_credentials_and_denies_stale_allow(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(os.path.join(directory, 'config.json'))
            config.config.update(connection_mode='proxy', protection_enabled=True)
            proxy.save_profile(config, 'http://user:secret@localhost:3128')
            self.assertIsNone(proxy.save_profile(config, ' \n'))
            saved = json.loads(Path(config.path).read_text())
            self.assertIsNone(saved['proxy_profile'])
            self.assertNotIn('secret', Path(config.path).read_text())
            with patch.object(brain, 'read_daemon_state', return_value={
                    'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': proxy.profile_id(config)}):
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_pf_exempts_only_our_interface(self):
        rule = make_rule(['192.0.2.1'], proxy=True)
        self.assertIn('on ! utun199', rule)
        self.assertEqual(parse_rule(rule), ['192.0.2.1'])
        with self.assertRaises(Exception):
            parse_rule(rule.replace('utun199', 'en0'))

class ProxyBackendTests(unittest.TestCase):
    def test_only_owned_ranges_are_accepted_as_networks(self):
        self.assertEqual(parse_rule(make_rule(['160.79.104.0/24'], proxy=True)), ['160.79.104.0/24'])
        for value in ['0.0.0.0/0', '192.0.2.0/24', '::/0']:
            with self.assertRaises(Exception):
                parse_rule(make_rule([value], proxy=True))

    def test_refresh_keeps_established_connections(self):
        from src.pf_controller import PFController
        controller = PFController()
        with patch.object(controller, 'pf') as pf, patch.object(controller, 'ensure_attachment'), \
                patch.object(controller, 'enable'), patch.object(controller, 'clear_anchor'):
            controller.block(['192.0.2.1'], proxy=True, kill_states=False)
            self.assertFalse(any(call.args[0] == '-k' for call in pf.call_args_list))

    def test_vpn_default_is_transport_not_conflicting_route(self):
        from src.proxy_service import route_conflicts
        self.assertFalse(route_conflicts('destination: default\nmask: default\ninterface: utun4', '160.79.104.0/24'))
        self.assertFalse(route_conflicts('destination: 160.79.104.10\nflags: <HOST,WASCLONED>\ninterface: utun4', '160.79.104.10/32'))
        self.assertTrue(route_conflicts('destination: 160.79.104\nmask: 255.255.255.0\ninterface: utun4', '160.79.104.0/24'))
        self.assertTrue(route_conflicts('destination: 2607:6bc0::\nmask: ffff:ffff::\ninterface: utun4', '2607:6bc0::/32'))
        self.assertFalse(route_conflicts('destination: 0.0.0.0\nmask: 128.0.0.0\ninterface: utun4', '160.79.104.0/24'))
        self.assertTrue(route_conflicts('destination: 160.79.104.10\nflags: <HOST,STATIC>\ninterface: utun4', '160.79.104.10/32'))

    def test_tunnel_owner_conflict_stops_before_writing_config(self):
        from src import proxy_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def runner(*args, **kwargs):
                if args[0] == '/sbin/ifconfig':
                    return SimpleNamespace(returncode=0, stdout='utun199')
                return SimpleNamespace(returncode=1, stdout='')
            request = {'profile': proxy_config.parse_profile('http://localhost:3128'),
                       'addresses': ['192.0.2.1'], 'domains': ['claude.ai']}
            with patch.object(proxy_service, 'ROOT', root), patch.object(proxy_service, 'run', side_effect=runner):
                with self.assertRaisesRegex(RuntimeError, 'occupied'):
                    proxy_service.ensure(request)
            self.assertEqual(list(root.iterdir()), [])

    def test_terminated_engine_is_reported_as_installation_failure(self):
        from src import proxy_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sing-box').touch()
            def runner(*args, **kwargs):
                if args[0] == str(root / 'sing-box'):
                    return SimpleNamespace(returncode=-9, stdout='')
                return SimpleNamespace(returncode=1, stdout='')
            request = {'profile': proxy_config.parse_profile('http://localhost:3128'),
                       'addresses': [], 'domains': ['claude.ai']}
            with patch.object(proxy_service, 'ROOT', root), \
                    patch.object(proxy_service, 'run', side_effect=runner), \
                    patch.object(proxy_service, 'stop') as stop:
                with self.assertRaisesRegex(RuntimeError, 'terminated by macOS'):
                    proxy_service.ensure(request)
                stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
