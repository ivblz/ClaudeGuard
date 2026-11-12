"""Exercise real controller decisions with an in-memory PF, never the host PF."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import pf_controller as backend


DEFAULT_ROOT = 'anchor "com.apple/*" all\npass out all'
LEGACY_ROOT = '\n'.join('block drop out quick proto ' + proto + ' from any to <claude_guard>'
                        for proto in ('tcp', 'udp'))
OWN_CALL = 'anchor "com.claudeguard" out quick all label "ClaudeGuard anchor"'


class FakePF:
    def __init__(self, root=DEFAULT_ROOT):
        self.root = root
        self.anchors = {'com.apple/vpn': 'pass quick all'}
        self.references = {'777'}  # Another service owns this reference.
        self.states = {'160.79.104.10', '2607:6bc0::10', '203.0.113.42'}
        self.calls = []
        self.fail = None
        self.sequence = 1000

    def __call__(self, command, **kwargs):
        args = tuple(command[1:])
        self.calls.append((args, kwargs.get('input')))
        if args == self.fail:
            return subprocess.CompletedProcess(command, 1, '', 'injected failure')
        output = ''
        if args == ('-sr',):
            output = self.root
        elif args == ('ensure',):
            if OWN_CALL not in self.root.splitlines():
                self.root = (OWN_CALL + '\n' + self.root).strip()
        elif args == ('remove',):
            self.root = '\n'.join(line for line in self.root.splitlines() if line != OWN_CALL)
        elif args == ('migrate-legacy',):
            self.root = '\n'.join(line for line in self.root.splitlines()
                                  if line not in LEGACY_ROOT.splitlines())
        elif args == ('-a', backend.ANCHOR, '-f', '-'):
            self.anchors[backend.ANCHOR] = kwargs['input']
        elif args == ('-E',):
            self.sequence += 1
            token = str(self.sequence)
            self.references.add(token)
            return subprocess.CompletedProcess(command, 0, '', 'pf enabled\nToken : ' + token + '\n')
        elif args == ('-s', 'References'):
            output = 'TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n'
            output += '\n'.join('42       pfctl                        ' + t + ' 0 days 00:00:01'
                                for t in self.references)
        elif args[0] == '-X':
            self.references.remove(args[1])
        elif args[:1] == ('-k',):
            self.states.discard(args[3])
        elif args in (('-a', backend.ANCHOR, '-F', 'rules'),
                      ('-a', backend.PREVIOUS_ANCHOR, '-F', 'rules')):
            self.anchors[args[1]] = ''
        elif args in (('-a', backend.ANCHOR, '-F', 'Tables'),
                      ('-a', backend.PREVIOUS_ANCHOR, '-F', 'Tables'),
                      ('-t', backend.TABLE, '-T', 'kill')):
            pass
        else:
            raise AssertionError('Unexpected/unsafe PF operation: ' + repr(args))
        return subprocess.CompletedProcess(command, 0, output, '')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.pf = FakePF()
        self.controller = backend.PFController(self.directory, self.pf)

    def test_block_then_unblock_preserves_other_rules_references_and_states(self):
        self.controller.block(['160.79.104.10', '2607:6bc0::10'])
        self.assertEqual(self.pf.root, OWN_CALL + '\n' + DEFAULT_ROOT)
        self.assertIn('tcp, udp', self.pf.anchors[backend.ANCHOR])
        self.assertEqual(self.pf.states, {'203.0.113.42'})
        self.assertEqual(self.pf.references, {'777', '1001'})
        self.controller.unblock()
        self.assertEqual(self.pf.root, DEFAULT_ROOT)
        self.assertEqual(self.pf.anchors['com.apple/vpn'], 'pass quick all')
        self.assertEqual(self.pf.anchors[backend.ANCHOR], '')
        self.assertEqual(self.pf.references, {'777'})
        self.assertEqual(self.pf.states, {'203.0.113.42'})
        self.assertFalse(self.controller.token_path.exists())

    def test_repeated_block_reuses_token_and_unblock_is_idempotent(self):
        self.controller.block(['160.79.104.10'])
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.references, {'777', '1001'})
        self.controller.unblock()
        self.controller.unblock()
        self.assertEqual(self.pf.references, {'777'})

    def test_reboot_stale_token_is_replaced_without_releasing_another_reference(self):
        backend.atomic_json(self.controller.token_path, {'token': '999'})
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.references, {'777', '1001'})
        self.controller.unblock()
        self.assertEqual(self.pf.references, {'777'})

    def test_stale_token_unblock_does_not_release_any_reference(self):
        backend.atomic_json(self.controller.token_path, {'token': '999'})
        self.controller.unblock()
        self.assertEqual(self.pf.references, {'777'})
        self.assertFalse(any(args[0] == '-X' for args, _ in self.pf.calls))

    def test_failed_release_keeps_token_for_retry(self):
        self.controller.block(['160.79.104.10'])
        self.pf.fail = ('-X', '1001')
        with self.assertRaises(backend.PFError):
            self.controller.unblock()
        self.assertEqual(self.controller.read_token(), '1001')
        self.pf.fail = None
        self.controller.unblock()
        self.assertEqual(self.pf.references, {'777'})

    def test_failed_rule_load_never_claims_success_or_enables_pf(self):
        self.pf.fail = ('-a', backend.ANCHOR, '-f', '-')
        with self.assertRaises(backend.PFError):
            self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.references, {'777'})
        self.assertEqual(self.pf.states, {'160.79.104.10', '2607:6bc0::10', '203.0.113.42'})

    def test_failed_state_removal_is_reported_with_block_still_installed(self):
        self.pf.fail = ('-k', '0.0.0.0/0', '-k', '160.79.104.10')
        with self.assertRaises(backend.PFError):
            self.controller.block(['160.79.104.10'])
        self.assertTrue(self.pf.anchors[backend.ANCHOR])
        self.assertEqual(self.controller.read_token(), '1001')

    def test_legacy_migration_stages_anchor_before_switching_own_root_rules(self):
        self.pf.root = LEGACY_ROOT
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.root, OWN_CALL)
        self.assertEqual(self.pf.anchors['com.apple/vpn'], 'pass quick all')
        operations = [args for args, _ in self.pf.calls]
        self.assertLess(operations.index(('-a', backend.ANCHOR, '-f', '-')),
                        operations.index(('migrate-legacy',)))
        self.assertNotIn(('-F', 'states'), operations)

    def test_empty_root_can_be_bootstrapped_without_flushing_other_rulesets(self):
        self.pf.root = ''
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.root, OWN_CALL)
        self.assertEqual(self.pf.anchors['com.apple/vpn'], 'pass quick all')

    def test_foreign_root_and_mixed_legacy_rules_are_never_rewritten(self):
        for root in (LEGACY_ROOT + '\npass out all',
                     DEFAULT_ROOT + '\n' + LEGACY_ROOT):
            with self.subTest(root=root):
                self.pf.root = root
                with self.assertRaises(backend.PFError):
                    self.controller.block(['160.79.104.10'])
                self.assertEqual(self.pf.root, root)
                self.assertFalse(any(args == ('-R', '-f', '-') for args, _ in self.pf.calls))

    def test_anchor_precedes_early_quick_pass_without_rewriting_it(self):
        self.pf.root = 'pass out quick all\n' + DEFAULT_ROOT
        before = self.pf.root
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.root, OWN_CALL + '\n' + before)
        self.controller.unblock()
        self.assertEqual(self.pf.root, before)

    def test_internet_sharing_without_system_wildcard_is_preserved(self):
        before = ('scrub-anchor "com.apple.internet-sharing" all fragment reassemble\n'
                  'anchor "com.apple.internet-sharing" all')
        self.pf.root = before
        self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.root.replace(OWN_CALL + '\n', ''), before)
        self.controller.unblock()
        self.assertEqual(self.pf.root, before)

    def test_native_attachment_failure_is_not_reported_as_success(self):
        self.pf.fail = ('ensure',)
        with self.assertRaisesRegex(backend.PFError, 'pf-anchor ensure'):
            self.controller.block(['160.79.104.10'])
        self.assertEqual(self.pf.root, DEFAULT_ROOT)
        self.assertEqual(self.pf.references, {'777'})


class StagingTests(unittest.TestCase):
    def test_only_ip_literals_and_fixed_rule_shape_are_accepted(self):
        addresses = ['160.79.104.10', '2607:6bc0::10']
        self.assertEqual(backend.parse_rule(backend.make_rule(addresses)), addresses)
        for rule in (backend.make_rule(['example.com']),
                     backend.make_rule(addresses) + 'set skip on en0\n',
                     backend.make_rule(['0.0.0.0/0'])):
            with self.subTest(rule=rule), self.assertRaises((ValueError, backend.PFError)):
                backend.parse_rule(rule)

    def test_hosts_merge_preserves_new_foreign_entries(self):
        old = backend.HEADER + '0.0.0.0 old.example\n' + backend.FOOTER
        current = '127.0.0.1 localhost\n192.0.2.1 vpn.internal\n' + old
        staged = '127.0.0.1 localhost\n' + backend.HEADER + '::1 claude.ai\n' + backend.FOOTER
        result = backend.merge_hosts(current, staged)
        self.assertIn('192.0.2.1 vpn.internal', result)
        self.assertNotIn('old.example', result)
        self.assertIn('::1 claude.ai', result)
        self.assertEqual(backend.merge_hosts(result, '127.0.0.1 localhost\n'),
                         '127.0.0.1 localhost\n192.0.2.1 vpn.internal\n')

    def test_arbitrary_hosts_mapping_injection_is_rejected(self):
        with self.assertRaises(backend.PFError):
            backend.merge_hosts('', backend.HEADER + '192.0.2.1 bank.example\n' + backend.FOOTER)

    def test_symlink_staging_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_text('data')
            link = Path(directory) / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                backend.trusted_read(link, os.getuid())

    def test_request_acknowledges_pf_failures_and_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = root / 'pending'
            pending.mkdir()
            request = 'a' * 32
            (pending / 'request').write_text(request)
            (pending / 'hosts.tmp').write_text(backend.HEADER + '::1 claude.ai\n' + backend.FOOTER)
            (pending / 'pf.rule').write_text(backend.make_rule(['160.79.104.10']))
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n192.0.2.1 vpn.internal\n')
            fake = FakePF()
            controller = backend.PFController(root, fake)
            fake.fail = ('-a', backend.ANCHOR, '-f', '-')
            with patch.object(backend, 'HOSTS_PATH', hosts), patch.object(backend.subprocess, 'run'):
                with self.assertRaises(backend.PFError):
                    backend.apply_request(root, controller)
                status = json.loads((root / 'network-status.json').read_text())
                self.assertEqual(status['request'], request)
                self.assertFalse(status['ok'])
                self.assertIn('claude.ai', hosts.read_text())  # hosts still protects on PF failure
                fake.fail = None
                backend.apply_request(root, controller)
                status = json.loads((root / 'network-status.json').read_text())
                self.assertTrue(status['ok'])
                self.assertTrue(status['blocked'])
                self.assertIn('vpn.internal', hosts.read_text())
                self.assertIn('claude.ai', hosts.read_text())


if __name__ == '__main__':
    unittest.main()
