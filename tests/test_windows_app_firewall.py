import unittest
from unittest.mock import patch

from src.windows import windows_backend as backend
from src.proxy_config import DEDICATED


class ApplicationFirewallTests(unittest.TestCase):
    def setUp(self):
        self.desktop = r'C:\Program Files\Claude\Claude.exe'
        self.cli = r'C:\Users\Example\.local\bin\claude.exe'

    def test_program_rules_cover_both_address_families_and_preserve_destination_rules(self):
        with patch.object(backend, '_powershell') as powershell:
            backend.WindowsFirewall().apply(DEDICATED, {}, programs=[self.desktop, self.cli])
        payload = powershell.call_args.args[1]
        rules = payload['rules']
        self.assertEqual(rules[:2], backend._rule_specs(DEDICATED, {}))
        self.assertEqual(len({rule['name'] for rule in rules}), 6)
        for rule in rules[2:]:
            self.assertRegex(rule['name'], payload['pattern'])
            self.assertEqual(rule['local'], ['Any'])
            self.assertIn(rule['program'], [self.desktop.lower(), self.cli.lower()])
        self.assertEqual([rule['remote'] for rule in rules[2:]], [
            ['0.0.0.0/1', '128.0.0.0/1'], ['0.0.0.0/1', '128.0.0.0/1'],
            ['::/1', '8000::/1'], ['::/1', '8000::/1'],
        ])

    def test_vpn_verified_sources_are_exempted_in_their_own_family(self):
        program = [self.desktop, self.desktop.lower()]
        blocked = backend._program_rule_specs(program, {}, proxy=False)
        partial = backend._program_rule_specs(program, {4: '10.8.0.14'}, proxy=False)
        self.assertEqual(len(partial), 2)
        self.assertEqual(partial[0]['local'], ['0.0.0.0-10.8.0.13', '10.8.0.15-255.255.255.255'])
        self.assertNotEqual(partial[0]['name'], blocked[0]['name'])
        self.assertEqual(partial[1], blocked[1])

    def test_proxy_rules_exclude_ipv4_and_ipv6_loopback(self):
        rules = backend._program_rule_specs([self.desktop], {4: '10.8.0.14'}, proxy=True)
        self.assertEqual([rule['local'] for rule in rules], [['Any'], ['Any']])
        self.assertEqual(rules[0]['remote'], ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255'])
        self.assertEqual(rules[1]['remote'], ['::', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'])


if __name__ == '__main__':
    unittest.main()
