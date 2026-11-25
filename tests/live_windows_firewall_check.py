"""Run from an elevated Windows prompt. Uses only documentation destinations."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.windows import windows_backend as backend
from src.windows.windows_platform import is_admin


TARGETS = ('192.0.2.0/24', '2001:db8::/32')
SOURCES = {4: '192.0.2.9', 6: '2001:db8::9'}
EXEMPTED_LOCAL_RANGES = (
    ('0.0.0.0-192.0.2.8', '192.0.2.10-255.255.255.255'),
    ('::-2001:db8::8', '2001:db8::a-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
)

READ_RULES = r'''
function Get-TestRules([string]$store) {
    Get-NetFirewallRule -PolicyStore $store | Where-Object {
        $sameGroup = $_.Group -eq $inputData.group
        $sameName = $inputData.names -contains $_.Name
        ($sameGroup -and $sameName) -or ($inputData.preflight -and ($sameGroup -or $sameName))
    }
}

if ($inputData.cleanup) {
    Get-TestRules PersistentStore | Remove-NetFirewallRule
}

$records = @(
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        foreach ($rule in @(Get-TestRules $store)) {
            $filter = $rule | Get-NetFirewallAddressFilter
            [PSCustomObject]@{
                store = $store
                name = $rule.Name
                group = $rule.Group
                enabled = [string]$rule.Enabled
                action = [string]$rule.Action
                direction = [string]$rule.Direction
                profile = [string]$rule.Profile
                local = @($filter.LocalAddress)
                remote = @($filter.RemoteAddress)
            }
        }
    }
)
ConvertTo-Json -InputObject $records -Compress
'''


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def canonical(value):
    if value == 'Any':
        return value
    if '-' in value:
        return '-'.join(str(ipaddress.ip_address(part)) for part in value.split('-'))
    address, separator, mask = value.partition('/')
    if not separator:
        return str(ipaddress.ip_address(address))
    if not mask.isdecimal():
        mask = int(ipaddress.ip_address(mask)).bit_count()
    return str(ipaddress.ip_network(f'{address}/{mask}'))


def check_firewall(report):
    token = uuid.uuid4().hex
    group = f'ClaudeGuard live firewall test {token}'
    prefix = f'ClaudeGuard-live-{token}-'
    pattern = '^' + re.escape(prefix) + '[46]-[0-9a-f]{24}$'
    report['group'] = group
    powershell = backend._powershell
    run_system = backend.run_system

    def record_native_failure(*args, **kwargs):
        result = run_system(*args, **kwargs)
        if result.returncode and result.stderr:
            report.setdefault('powershell_errors', []).append(result.stderr.strip())
        return result

    with (patch.object(backend, 'RULE_GROUP', group),
          patch.object(backend, 'RULE_PREFIX', prefix),
          patch.object(backend, 'run_system', side_effect=record_native_failure)):
        blanket = backend._rule_specs(TARGETS, {})
        exempted = backend._rule_specs(TARGETS, SOURCES)
        for specs, scopes in ((blanket, (('Any',), ('Any',))), (exempted, EXEMPTED_LOCAL_RANGES)):
            require(len(specs) == len(TARGETS), 'Expected one rule per test address family.')
            for spec, target, scope in zip(specs, TARGETS, scopes):
                require(re.fullmatch(pattern, spec['name']), 'Unexpected firewall rule name.')
                require(spec['remote'] == [target], 'Refusing a rule outside the test destinations.')
                require(set(spec['local']) == set(scope), 'Unexpected firewall source scope.')
        names = sorted({rule['name'] for rule in blanket + exempted})
        require(len(names) == 4, 'Firewall rule names did not distinguish source scopes.')
        report['names'] = names

        def read_rules(*, preflight=False, cleanup=False):
            return json.loads(powershell(READ_RULES, {
                'group': group, 'names': names, 'preflight': preflight, 'cleanup': cleanup,
            }, message='Could not read or clean up the isolated firewall test rules.'))

        def verify_rules(specs):
            actual = read_rules()
            require(len(actual) == 2 * len(specs), 'Unexpected rule count in firewall readback.')
            for store in ('ActiveStore', 'PersistentStore'):
                by_name = {record['name']: record for record in actual if record['store'] == store}
                require(set(by_name) == {spec['name'] for spec in specs}, f'Unexpected names in {store}.')
                for spec in specs:
                    record = by_name[spec['name']]
                    require(record['group'] == group and record['enabled'] == 'True'
                            and record['action'] == 'Block' and record['direction'] == 'Outbound'
                            and record['profile'] == 'Any', f'Unexpected rule properties in {store}.')
                    for field in ('local', 'remote'):
                        observed = {canonical(value) for value in record[field]}
                        require(observed == set(spec[field]), f'Unexpected {field} addresses in {store}.')

        def checked_powershell(script, payload, **kwargs):
            require(script == backend._FIREWALL and payload['group'] == group
                    and payload['pattern'] == pattern, 'Refusing a firewall operation outside the test group.')
            require(payload['rules'] is None if payload['remove'] else payload['rules'] in (blanket, exempted),
                    'Refusing firewall rules outside the verified test scopes.')
            return powershell(script, payload, **kwargs)

        require(read_rules(preflight=True) == [], 'Test rule identities already exist. No changes were made.')
        firewall = backend.WindowsFirewall()
        report['cleaned'] = False
        try:
            with patch.object(backend, '_powershell', side_effect=checked_powershell):
                firewall.apply(TARGETS, {})
                verify_rules(blanket)
                report['passed'].append('blanket blocks for both documentation ranges')

                firewall.apply(TARGETS, SOURCES, preserve_older=True)
                verify_rules(blanket + exempted)
                firewall.apply(TARGETS, SOURCES)
                verify_rules(exempted)
                report['passed'].append('source exemptions and replacement of older rules')

                firewall.remove()
                verify_rules([])
                report['passed'].append('adapter removal from the persistent and active stores')
        finally:
            report['cleaned'] = read_rules(cleanup=True) == []
            require(report['cleaned'], 'Temporary firewall rules are still present.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='Also write the result to this JSON file.')
    options = parser.parse_args()
    report = {'passed': []}
    try:
        require(sys.platform == 'win32' and is_admin(), 'Run this check from an elevated Windows prompt.')
        check_firewall(report)
    except Exception as error:
        report['error'] = str(error)
    output = json.dumps(report, indent=2)
    if options.report:
        options.report.write_text(output + '\n', encoding='utf-8')
    print(output)
    return int('error' in report)


if __name__ == '__main__':
    sys.exit(main())
