"""Windows protection policy tests with the host firewall and processes mocked."""

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, call, patch

from src.windows.windows_config import ConfigManager
from src.proxy_config import DEDICATED, PORT
from src.windows import windows_backend as backend
from src.windows.windows_process_guard import ProcessReport, WindowsProcessGuard


class FirewallPolicyTests(unittest.TestCase):
    def test_proxy_transition_preserves_blanket_until_verified_scope_is_requested(self):
        firewall = backend.WindowsFirewall()
        programs = (r'C:\Program Files\Claude\Claude.exe',)
        with patch.object(backend, '_powershell') as powershell:
            firewall.apply(DEDICATED, {}, programs=programs, stage_proxy=True)
            staged = powershell.call_args.args[1]
            self.assertTrue(staged['preserveOlder'])
            self.assertFalse(staged['recentlyVerified'])
            firewall.apply(DEDICATED, {}, programs=programs, proxy=True)
            final = powershell.call_args.args[1]
            self.assertFalse(final['preserveOlder'])
            self.assertTrue(final['recentlyVerified'])
            self.assertLess({r['name'] for r in final['rules']}, {r['name'] for r in staged['rules']})

    def test_unchanged_rules_are_audited_and_changed_rules_apply_immediately(self):
        firewall = backend.WindowsFirewall()
        with patch.object(firewall, '_run') as run, patch.object(backend.time, 'monotonic') as clock:
            clock.return_value = 0
            firewall.apply(DEDICATED, {})
            firewall.apply(DEDICATED, {})
            self.assertEqual(run.call_count, 1)
            firewall.apply(DEDICATED, {4: '10.8.0.2'})
            self.assertEqual(run.call_count, 2)
            clock.return_value = 16
            firewall.apply(DEDICATED, {4: '10.8.0.2'})
            self.assertEqual(run.call_count, 3)

    def test_each_family_is_blocked_without_a_source_exception(self):
        rules = backend._rule_specs(DEDICATED, {})
        self.assertEqual([rule['local'] for rule in rules], [['Any'], ['Any']])
        self.assertEqual([rule['remote'] for rule in rules], [[DEDICATED[0]], [DEDICATED[1]]])

    def test_source_exception_covers_every_other_address(self):
        for source in ('10.8.0.14', 'fd00::83'):
            with self.subTest(source=source):
                value = ipaddress.ip_address(source)
                ranges = backend._address_complement(source)
                first, before = map(ipaddress.ip_address, ranges[0].split('-'))
                after, last = map(ipaddress.ip_address, ranges[1].split('-'))
                self.assertEqual(int(first), 0)
                self.assertEqual(before, value - 1)
                self.assertEqual(after, value + 1)
                self.assertEqual(int(last), 2 ** value.max_prefixlen - 1)

    def test_rule_identity_changes_with_scope_and_preserves_other_family(self):
        targets = [*DEDICATED, '160.79.104.81', '8.8.4.4']
        blanket = backend._rule_specs(targets, {})
        partial = backend._rule_specs(targets, {4: '10.8.0.14'})
        self.assertNotEqual(blanket[0]['name'], partial[0]['name'])
        self.assertEqual(blanket[1], partial[1])
        self.assertEqual(partial[0]['remote'], ['160.79.104.0/24', '8.8.4.4'])

    def test_firewall_only_addresses_owned_rule_group(self):
        with patch.object(backend, '_powershell') as powershell:
            firewall = backend.WindowsFirewall()
            firewall.apply(DEDICATED, {}, preserve_older=True)
            firewall.remove()
        apply, remove = [invocation.args[1] for invocation in powershell.call_args_list]
        self.assertTrue(apply['preserveOlder'])
        self.assertEqual(apply['group'], backend.RULE_GROUP)
        self.assertEqual(remove['group'], backend.RULE_GROUP)
        self.assertTrue(remove['remove'])
        self.assertRegex(apply['rules'][0]['name'], remove['pattern'])
        self.assertNotRegex('UnrelatedFirewallRule', remove['pattern'])


_MOCK_FIREWALL = r'''
$PSModuleAutoloadingPreference = 'None'
$script:mockRules = @($inputData.existing)
function Get-NetFirewallProfile($PolicyStore) {
    foreach ($profile in 'Domain', 'Private', 'Public') {
        [pscustomobject]@{ Enabled = 'True'; AllowLocalFirewallRules = 'True' }
    }
}
function Get-NetFirewallRule($PolicyStore, $Name) {
    if ($PolicyStore -eq 'ActiveStore') {
        $script:mockRules | Where-Object { $_.Name -in $Name }
    } else { $script:mockRules }
}
function New-NetFirewallRule($PolicyStore, $Name, $DisplayName, $Group, $Direction,
    $Action, $Enabled, $Profile, $LocalAddress, $RemoteAddress, $Program = 'Any') {
    $script:mockRules += [pscustomobject]@{
        Name = $Name; InstanceID = $Name; Group = $Group; Enabled = $Enabled; Action = $Action
        Direction = $Direction; Profile = $Profile; PrimaryStatus = 'OK'
        LocalAddress = $LocalAddress; RemoteAddress = $RemoteAddress; Program = $Program
    }
}
function Remove-NetFirewallRule {
    param([Parameter(ValueFromPipeline)]$Rule)
    process {
        if (!$inputData.failRemoval) {
            $script:mockRules = @($script:mockRules | Where-Object Name -ne $Rule.Name)
        }
    }
}
function Get-MockRuleFilters {
    param([Parameter(ValueFromPipeline)]$Rule)
    process {
        [pscustomobject]@{
            InstanceID = $Rule.InstanceID
            LocalAddress = $Rule.LocalAddress
            RemoteAddress = @($Rule.RemoteAddress | ForEach-Object { $_ -replace '/24$', '/255.255.255.0' })
            Protocol = 'Any'; LocalPort = 'Any'; RemotePort = 'Any'; IcmpType = 'Any'
            DynamicTarget = if ($inputData.narrowFilter) { 'ProximitySharing' } else { 'Any' }
            Program = if ($inputData.programFilter) { $inputData.programFilter } else { $Rule.Program.ToUpperInvariant() }
            Service = 'Any'; InterfaceAlias = 'Any'; InterfaceType = 'Any'
            Authentication = 'NotRequired'; Encryption = 'NotRequired'; LocalUser = 'Any'
            RemoteUser = 'Any'; RemoteMachine = 'Any'; OverrideBlockRules = $false
        }
    }
}
foreach ($filter in 'Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security') {
    Set-Alias -Name ('Get-NetFirewall' + $filter + 'Filter') -Value Get-MockRuleFilters
}
'''


@unittest.skipUnless(sys.platform == 'win32', 'Requires Windows PowerShell')
class NativeFirewallScriptTests(unittest.TestCase):
    def setUp(self):
        self.obsolete = backend._rule_specs(DEDICATED, {})[0]['name']
        self.specs = backend._rule_specs([*DEDICATED, '1.1.1.1'], {4: '10.8.0.14', 6: 'fd00::83'})
        self.unrelated = backend.RULE_PREFIX + '4-' + 'a' * 24
        self.existing = [
            {'Name': self.obsolete, 'Group': backend.RULE_GROUP},
            {'Name': self.unrelated, 'Group': 'Another application'},
        ]

    def run_firewall(self, **updates):
        payload = {
            'rules': self.specs, 'existing': self.existing, 'group': backend.RULE_GROUP,
            'pattern': '^' + backend.RULE_PREFIX + '[46]-[0-9a-f]{24}$', **updates,
        }
        script = _MOCK_FIREWALL + '\ntry {\n& {\n' + backend._FIREWALL + r'''
}
} catch { $failure = $_.Exception.Message }
ConvertTo-Json -Compress -Depth 6 -InputObject @{ rules = $script:mockRules; failure = $failure }
'''
        return json.loads(backend._powershell(script, payload, message='Mock firewall script failed.'))

    def test_replacement_and_cleanup_keep_unrelated_rules(self):
        updated = self.run_firewall()
        self.assertIsNone(updated['failure'])
        self.assertEqual({rule['Name'] for rule in updated['rules']},
                         {self.unrelated, *(rule['name'] for rule in self.specs)})
        removed = self.run_firewall(existing=updated['rules'], remove=True)
        self.assertIsNone(removed['failure'])
        self.assertEqual([rule['Name'] for rule in removed['rules']], [self.unrelated])

    def test_application_rules_verify_program_paths_before_removing_previous_rules(self):
        program = r'C:\Program Files\Claude\Claude.exe'
        specs = self.specs + backend._program_rule_specs([program], {}, proxy=True)
        verified = self.run_firewall(rules=specs)
        self.assertIsNone(verified['failure'])
        self.assertEqual({rule['Program'] for rule in verified['rules'] if 'Program' in rule},
                         {'Any', program.lower()})
        failed = self.run_firewall(rules=specs[len(self.specs):], programFilter=r'C:\Other\Claude.exe')
        self.assertEqual(failed['failure'], 'ClaudeGuard rule has unexpected filters')
        self.assertIn(self.obsolete, [rule['Name'] for rule in failed['rules']])

    def test_filter_and_cleanup_failures_leave_previous_rules(self):
        for options, expected in (
            ({'narrowFilter': True}, 'ClaudeGuard rule has unexpected filters'),
            ({'failRemoval': True}, 'Previous ClaudeGuard rules remain'),
            ({'remove': True, 'failRemoval': True}, 'ClaudeGuard rules remain'),
        ):
            with self.subTest(options=options):
                failed = self.run_firewall(**options)
                self.assertEqual(failed['failure'], expected)
                self.assertIn(self.obsolete, [rule['Name'] for rule in failed['rules']])


class EnginePathTests(unittest.TestCase):
    def test_frozen_engine_ignores_development_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            app = root / 'ClaudeGuard.exe'
            sibling = root / 'sing-box.exe'
            override = root / 'development.exe'
            sibling.touch()
            override.touch()
            with (patch.object(backend.sys, 'frozen', True, create=True),
                  patch.object(backend.sys, 'executable', str(app)),
                  patch.dict(os.environ, {'CLAUDEGUARD_SING_BOX': str(override)})):
                self.assertEqual(backend._engine_path(override), sibling)
                sibling.unlink()
                with self.assertRaisesRegex(backend.WindowsGuardError, 'missing from the ClaudeGuard installation'):
                    backend._engine_path(override)


class NetworkChecksTests(unittest.TestCase):
    def test_usable_family_can_finish_before_unneeded_family(self):
        checks = backend._NetworkChecks(2)
        release = threading.Event()

        def probe(family):
            if family == 6:
                release.wait(5)
            return family

        try:
            self.assertEqual(checks.run(probe, (4, 6), 3, enough=lambda results: 4 in results), {4: 4})
        finally:
            release.set()
            checks.close()

    def test_stalled_lookup_does_not_hold_the_process_open(self):
        script = '''
from threading import Event
from src.windows.windows_backend import _NetworkChecks

started = Event()

def lookup(host):
    started.set()
    Event().wait()

checks = _NetworkChecks(1)
if checks.run(lookup, ['stalled.example'], timeout=1) != {} or not started.is_set():
    raise RuntimeError('Expected an active lookup to exceed the deadline.')
checks.close()
'''
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1], timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


class WindowsGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'config.json'
        self.config = ConfigManager(self.path)
        self.process_guard = Mock(spec=WindowsProcessGuard)
        self.process_guard.approved_program_paths.return_value = ()
        self.process_guard.enforce.return_value = ProcessReport()
        self.guard = backend.WindowsGuard(self.path, process_guard=self.process_guard)
        self.guard._firewall = Mock(spec=backend.WindowsFirewall)
        self.guard._dns_checks = Mock()
        self.guard._dns_checks.run.side_effect = lambda fn, hosts, timeout: dict.fromkeys(hosts, set())
        self.guard._ip_checks = Mock()
        self.guard._ip_checks.run.return_value = {4: ('1.1.1.1', '10.8.0.14'), 6: None}
        self.acl = patch.object(backend, '_private_paths').start()
        self.addCleanup(patch.stopall)
        patch.object(backend, '_strong_host_families', return_value={4, 6}).start()

    def save(self, **update):
        self.config.config.update(update)
        self.config.save_config()

    def test_empty_whitelist_reports_observed_ip_and_keeps_blanket_blocks(self):
        result = self.guard.tick()
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(result['ip'], '1.1.1.1')
        self.assertTrue(result['protected'])
        self.assertEqual(result['verified_families'], ())
        self.guard._firewall.apply.assert_called_once_with(set(DEDICATED), {})
        self.process_guard.enforce.assert_called_once()

    def test_whitelisted_vpn_scopes_to_each_verified_source(self):
        self.save(allowed_ips=['1.1.1.0/24', '2606:4700::1234'])
        self.guard._ip_checks.run.return_value = {
            4: ('1.1.1.1', '10.8.0.14'), 6: ('2606:4700::1234', 'fd00::83'),
        }
        with patch.object(backend, '_strong_host_families', return_value={4}):
            result = self.guard.tick()
        self.assertEqual(result['state'], 'allowed')
        self.assertEqual(result['verified_families'], (4,))
        self.process_guard.enforce.assert_not_called()
        self.assertEqual(self.guard._firewall.apply.call_args_list, [
            call(set(DEDICATED), {}), call(set(DEDICATED), {4: '10.8.0.14'}),
        ])

        self.guard._ip_checks.run.return_value = {4: ('9.9.9.9', '192.168.1.8'), 6: None}
        retry = self.guard.tick()
        self.assertEqual(retry['state'], 'blocked')
        self.assertTrue(retry['protected'])
        self.guard._firewall.apply.assert_called_with(set(DEDICATED), {})
        self.process_guard.enforce.assert_called_once()

    def test_offline_start_preserves_last_resolved_snapshot_and_adds_fresh_answers(self):
        self.guard.runtime.mkdir()
        self.guard._ip_checks.run.return_value = {}
        cache = self.guard.runtime / 'dns.json'
        cache.write_text(json.dumps({'claude.ai': ['1.1.1.1', '::1']}), encoding='utf-8')
        status = self.guard.tick()
        self.assertEqual(status['state'], 'offline')
        self.assertTrue(status['protected'])
        self.guard._firewall.apply.assert_called_once_with({*DEDICATED, '1.1.1.1'}, {})
        self.guard._dns_checks.run.side_effect = lambda fn, hosts, timeout: {
            host: {'9.9.9.9'} if host == 'claude.ai' else set() for host in hosts}
        self.guard.tick()
        self.guard._firewall.apply.assert_called_with({*DEDICATED, '1.1.1.1', '9.9.9.9'}, {})
        self.assertEqual(json.loads(cache.read_text(encoding='utf-8'))['claude.ai'], ['1.1.1.1', '9.9.9.9'])
        self.process_guard.enforce.assert_not_called()

    def test_warm_cache_never_allows_an_incomplete_dns_check(self):
        self.save(allowed_ips=['1.1.1.1'])
        self.assertEqual(self.guard.tick()['state'], 'allowed')
        self.guard._dns_checks.run.side_effect = lambda *args: {'claude.ai': {'9.9.9.9'}}
        result = self.guard.tick()
        self.assertEqual(self.guard._dns_checks.run.call_count, 2)
        self.assertEqual(result['state'], 'offline')
        self.assertIn('DNS', result['error'])
        self.assertIn('9.9.9.9', self.guard._targets)
        self.guard._firewall.apply.assert_called_with(self.guard._targets, {}, preserve_older=False)

    def test_resolver_failure_is_distinct_from_negative_dns_answer(self):
        self.save(allowed_ips=['1.1.1.1'])
        self.assertEqual(self.guard.tick()['state'], 'allowed')
        self.guard._dns_checks.run.side_effect = lambda fn, hosts, timeout: {
            host: None if host == 'claude.ai' else set() for host in hosts}
        self.assertEqual(self.guard.tick()['state'], 'offline')
        self.guard._dns_checks.run.side_effect = lambda fn, hosts, timeout: dict.fromkeys(hosts, set())
        self.assertEqual(self.guard.tick()['state'], 'allowed')

    def test_cache_access_failure_leaves_previous_firewall_rules_in_place(self):
        self.acl.side_effect = backend.WindowsGuardError('Could not secure runtime')
        result = self.guard.tick()
        self.assertEqual(result['state'], 'error')
        self.assertFalse(result['protected'])
        self.guard._firewall.apply.assert_called_once_with(set(DEDICATED), {}, preserve_older=True)

    def test_firewall_failure_does_not_report_protected_or_leave_proxy_running(self):
        self.guard._process = Mock()
        self.guard._process.poll.return_value = None
        previous = self.guard._process
        self.guard._firewall.apply.side_effect = backend.WindowsGuardError('Firewall unavailable')
        result = self.guard.tick()
        self.assertEqual(result['state'], 'blocked')
        self.assertFalse(result['protected'])
        self.assertIsNone(self.guard._process)
        previous.terminate.assert_called_once()
        self.process_guard.enforce.assert_called_once()

    def test_firewall_failure_without_vpn_evidence_never_stops_claude(self):
        self.guard._ip_checks.run.return_value = {4: None, 6: None}
        self.guard._firewall.apply.side_effect = backend.WindowsGuardError('Firewall unavailable')
        result = self.guard.tick()
        self.assertEqual(result['state'], 'error')
        self.assertFalse(result['protected'])
        self.assertIn('Firewall unavailable', result['error'])
        self.process_guard.enforce.assert_not_called()

    def test_repeated_scans_count_closures_until_offline(self):
        self.process_guard.enforce.side_effect = [ProcessReport(1, 0), ProcessReport(0, 1), ProcessReport()]
        blocked = self.guard.tick()
        retried = self.guard.enforce_processes()
        self.assertEqual((blocked['desktop_closed'], blocked['cli_closed']), (1, 0))
        self.assertEqual((retried['desktop_closed'], retried['cli_closed']), (1, 1))
        self.assertEqual(blocked['block_episode'], retried['block_episode'])

        self.guard._ip_checks.run.return_value = {4: None, 6: None}
        offline = self.guard.tick()
        self.assertEqual(offline['state'], 'offline')
        self.assertIsNone(offline['block_episode'])
        self.assertEqual(self.guard.enforce_processes(), offline)
        self.assertEqual(self.process_guard.enforce.call_count, 2)

        self.guard._ip_checks.run.return_value = {4: ('1.1.1.1', '10.8.0.14')}
        self.assertGreater(self.guard.tick()['block_episode'], blocked['block_episode'])

    def test_network_check_does_not_wait_for_running_process_scan(self):
        started, release = threading.Event(), threading.Event()

        def scan(*args, **kwargs):
            started.set()
            release.wait()
            return ProcessReport(1, 0)

        self.process_guard.enforce.side_effect = scan
        status = self.guard.tick(enforce_processes=False)
        self.assertIsNotNone(status['block_episode'])
        self.process_guard.enforce.assert_not_called()

        with ThreadPoolExecutor(max_workers=2) as pool:
            scanning = pool.submit(self.guard.enforce_processes)
            try:
                self.assertTrue(started.wait(2))
                checked = pool.submit(self.guard.tick).result(timeout=2)
                self.assertEqual(checked['block_episode'], status['block_episode'])
                self.assertEqual(checked['desktop_closed'], 0)
            finally:
                release.set()
            self.assertEqual(scanning.result(timeout=2)['desktop_closed'], 1)
        self.process_guard.enforce.assert_called_once()

    def test_disable_can_complete_during_synchronous_process_scan(self):
        started, release = threading.Event(), threading.Event()

        def scan(settings, status, *, should_enforce):
            started.set()
            release.wait()
            self.assertFalse(should_enforce())
            return ProcessReport()

        self.process_guard.enforce.side_effect = scan
        with ThreadPoolExecutor(max_workers=2) as pool:
            checking = pool.submit(self.guard.tick)
            try:
                self.assertTrue(started.wait(2))
                self.assertEqual(pool.submit(self.guard.disable).result(timeout=2)['state'], 'disabled')
            finally:
                release.set()
            self.assertEqual(checking.result(timeout=2)['state'], 'disabled')

    def test_process_failure_degrades_protection_until_successful_retry(self):
        message = 'Claude Code could not be closed.'
        self.process_guard.enforce.side_effect = [ProcessReport(1, 0, message), ProcessReport(0, 1)]
        blocked = self.guard.tick()
        self.assertEqual(blocked['state'], 'blocked')
        self.assertFalse(blocked['protected'])
        self.assertIn(message, blocked['error'])
        self.assertEqual(blocked['process_enforcement_error'], message)
        retried = self.guard.enforce_processes()
        self.assertTrue(retried['protected'])
        self.assertIsNone(retried['process_enforcement_error'])
        self.assertEqual((retried['desktop_closed'], retried['cli_closed']), (1, 1))

    def test_settings_edit_invalidates_active_process_scan(self):
        def enforce(settings, status, *, should_enforce):
            self.assertTrue(should_enforce())
            self.save(protection_enabled=False)
            self.assertFalse(should_enforce())
            return ProcessReport()

        self.process_guard.enforce.side_effect = enforce
        self.guard.tick()
        self.guard.enforce_processes()
        self.assertEqual(self.guard.tick()['state'], 'disabled')
        self.process_guard.enforce.assert_called_once()

    def test_pending_settings_prevent_stale_network_check_from_arming_process_scan(self):
        def check(*args, **kwargs):
            self.guard.invalidate_process_verdict()
            return {4: ('1.1.1.1', '10.8.0.14')}

        self.guard._ip_checks.run.side_effect = check
        self.assertIsNone(self.guard.tick()['block_episode'])
        self.guard._ip_checks.run.side_effect = None
        self.assertIsNone(self.guard.tick()['block_episode'])
        self.process_guard.enforce.assert_not_called()

        self.guard.resume_process_verdict()
        self.assertIsNotNone(self.guard.tick()['block_episode'])
        self.process_guard.enforce.assert_called_once()

    def test_proxy_shutdown_can_retry_after_job_close_and_timeout(self):
        process = self.guard._process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('sing-box.exe', 5), 0]
        close_job = self.guard._close_job = Mock()
        with self.assertRaisesRegex(backend.WindowsGuardError, 'Could not stop'):
            self.guard.disable()
        self.guard._firewall.remove.assert_not_called()
        self.assertIs(self.guard._process, process)
        self.assertEqual(self.guard.disable()['state'], 'disabled')
        self.assertIsNone(self.guard._process)
        close_job.assert_called_once()
        process.terminate.assert_called_once()
        self.guard._firewall.remove.assert_called_once()

    def test_invalid_saved_whitelist_clears_a_previous_vpn_exception(self):
        self.save(allowed_ips=['1.1.1.1'])
        self.assertEqual(self.guard.tick()['state'], 'allowed')
        self.save(allowed_ips=[{"not": "an IP"}])
        invalid = self.guard.tick()
        self.assertEqual(invalid['state'], 'blocked')
        self.assertTrue(invalid['protected'])
        self.guard._firewall.apply.assert_called_with(set(DEDICATED), {}, preserve_older=False)

    def test_proxy_checks_owned_listener_and_failure_retains_blanket_rules(self):
        profile = {'type': 'socks', 'server': 'example.org', 'server_port': 1080,
                   'password': 'do-not-return-this'}
        self.save(connection_mode='proxy', proxy_profile=profile)
        programs = (r'C:\Users\Test\.local\bin\claude.exe',)
        self.process_guard.approved_program_paths.return_value = programs
        process = Mock()
        process.poll.return_value = None

        def start(configured):
            self.guard._process = process
            self.guard._profile = configured

        with (patch.object(self.guard, '_start_proxy', side_effect=start) as launch,
              patch.object(backend, '_is_proxy_owner', return_value=True) as owner,
              patch.object(backend, '_proxy_exit', return_value='1.1.1.1') as probe):
            result = self.guard.tick()
            self.assertEqual(result['state'], 'allowed')
            self.assertTrue(result['protected'])
            self.assertEqual(result['proxy_url'], f'http://127.0.0.1:{PORT}')
            self.guard._firewall.apply.assert_called_with(set(DEDICATED), {}, programs=programs, proxy=True)
            self.process_guard.enforce.assert_not_called()
            launch.assert_called_once_with(profile)
            owner.assert_called_once_with(process)

            self.guard._firewall.apply.reset_mock()
            self.assertEqual(self.guard.tick()['state'], 'allowed')
            self.guard._firewall.apply.assert_called_once_with(set(DEDICATED), {}, programs=programs, proxy=True)
            launch.assert_called_once()

            process.poll.return_value = 1
            launch.side_effect = backend.WindowsGuardError('Could not start sing-box.exe.')
            failed = self.guard.tick()
        self.assertEqual(failed['state'], 'blocked')
        self.assertTrue(failed['protected'])
        self.assertIsNone(failed['proxy_url'])
        self.assertNotIn(profile['password'], str(failed))
        self.assertEqual(probe.call_count, 2)
        self.guard._firewall.apply.assert_called_with(set(DEDICATED), {}, programs=programs, preserve_older=False)
        self.process_guard.enforce.assert_called_once()

    def test_missing_proxy_configuration_keeps_apps_blocked(self):
        self.save(connection_mode='proxy', proxy_profile=None)
        result = self.guard.tick()
        self.assertEqual(result['state'], 'blocked')
        self.assertTrue(result['protected'])
        self.guard._ip_checks.run.assert_not_called()
        self.process_guard.enforce.assert_called_once()

    def test_loopback_proxy_configuration_has_no_direct_fallback(self):
        config = backend._proxy_config({'type': 'http', 'server': 'example.org', 'server_port': 3128})
        self.assertEqual(config['inbounds'], [
            {'type': 'mixed', 'tag': 'claudeguard', 'listen': '127.0.0.1', 'listen_port': PORT},
        ])
        self.assertEqual([outbound['tag'] for outbound in config['outbounds']], ['proxy'])
        self.assertEqual(config['route']['final'], 'proxy')

    def test_quit_blocks_verified_vpn_and_explicit_disable_removes_owned_rules(self):
        self.save(allowed_ips=['1.1.1.1'])
        programs = (r'C:\Users\Test\.local\bin\claude.exe',)
        self.process_guard.approved_program_paths.return_value = programs
        self.assertEqual(self.guard.tick()['state'], 'allowed')
        self.guard._firewall.apply.assert_called_with(set(DEDICATED), {4: '10.8.0.14'}, programs=programs)
        self.guard.close()
        self.guard._firewall.apply.assert_called_with(set(DEDICATED), {}, programs=programs, preserve_older=False)
        self.guard._firewall.remove.assert_not_called()
        self.assertEqual(self.guard.status()['state'], 'blocked')
        self.assertEqual(self.guard.disable()['state'], 'disabled')
        self.guard._firewall.remove.assert_called_once()
        self.assertTrue(ConfigManager(self.path).config['protection_enabled'])
        self.process_guard.enforce.assert_not_called()


if __name__ == '__main__':
    unittest.main()
