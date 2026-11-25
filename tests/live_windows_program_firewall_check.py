"""Verify live Windows program firewall filters for a temporary executable."""

import argparse
import json
import ntpath
from pathlib import Path
import re
import shutil
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import uuid

from live_windows_firewall_check import EXEMPTED_LOCAL_RANGES, SOURCES, canonical, require
from src.windows import windows_backend as backend
from src.windows.windows_platform import is_admin


FULL_REMOTE = (
    ('0.0.0.0/1', '128.0.0.0/1'),
    ('::/1', '8000::/1'),
)
PROXY_REMOTE = (
    ('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255'),
    ('::', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
)
ANY_LOCAL = (('Any',), ('Any',))

READ_RULES = r'''
function Get-TestRules([string]$store) {
    Get-NetFirewallRule -PolicyStore $store | Where-Object {
        $inGroup = $_.Group -eq $inputData.group
        $knownName = $_.Name -in $inputData.names
        ($inGroup -and $knownName) -or ($inputData.preflight -and ($inGroup -or $knownName))
    }
}

if ($inputData.cleanup) {
    Get-TestRules PersistentStore | Remove-NetFirewallRule
}

$records = @(
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        foreach ($rule in @(Get-TestRules $store)) {
            $addresses = $rule | Get-NetFirewallAddressFilter
            $application = $rule | Get-NetFirewallApplicationFilter
            [PSCustomObject]@{
                store = $store
                name = $rule.Name
                group = $rule.Group
                enabled = [string]$rule.Enabled
                action = [string]$rule.Action
                direction = [string]$rule.Direction
                profile = [string]$rule.Profile
                program = [string]$application.Program
                local = @($addresses.LocalAddress)
                remote = @($addresses.RemoteAddress)
            }
        }
    }
)
ConvertTo-Json -InputObject $records -Compress
'''


def check_program_firewall(report, executable):
    token = uuid.uuid4().hex
    group = f'ClaudeGuard program firewall test {token}'
    prefix = f'ClaudeGuard-program-test-{token}-'
    pattern = '^' + re.escape(prefix) + '[46]-[0-9a-f]{24}$'
    program = ntpath.normcase(str(executable))
    report['group'] = group
    powershell = backend._powershell

    with patch.object(backend, 'RULE_GROUP', group), patch.object(backend, 'RULE_PREFIX', prefix):
        cases = (
            ('blanket program block', {}, False, ANY_LOCAL, FULL_REMOTE),
            ('verified source exemptions', SOURCES, False, EXEMPTED_LOCAL_RANGES, FULL_REMOTE),
            ('proxy loopback exemptions', {}, True, ANY_LOCAL, PROXY_REMOTE),
        )
        plans = []
        for label, sources, proxy, local, remote in cases:
            specs = backend._program_rule_specs((program,), sources, proxy)
            require(len(specs) == 2, 'Expected one rule for each address family.')
            for spec, family, allowed_local, allowed_remote in zip(specs, (4, 6), local, remote):
                require(re.fullmatch(pattern, spec['name'])
                        and spec['name'].startswith(f'{prefix}{family}-'),
                        'Refusing an unexpected firewall rule name.')
                require(spec.get('program') == program, 'Refusing a rule outside the fixture program.')
                require(set(spec['local']) == set(allowed_local)
                        and set(spec['remote']) == set(allowed_remote),
                        'Refusing a rule with an unexpected address scope.')
            plans.append((label, specs))
        names = sorted({spec['name'] for _, specs in plans for spec in specs})
        require(len(names) == 6, 'Firewall rule names did not distinguish test scopes.')
        report['names'] = names

        def read_rules(*, preflight=False, cleanup=False):
            return json.loads(powershell(READ_RULES, {
                'group': group, 'names': names, 'preflight': preflight, 'cleanup': cleanup,
            }, message='Could not inspect or clean up the isolated program firewall rules.'))

        def verify_rules(specs):
            actual = read_rules()
            require(len(actual) == 2 * len(specs), 'Unexpected rule count in firewall readback.')
            for store in ('ActiveStore', 'PersistentStore'):
                records = {row['name']: row for row in actual if row['store'] == store}
                require(records.keys() == {spec['name'] for spec in specs}, f'Unexpected names in {store}.')
                for spec in specs:
                    row = records[spec['name']]
                    require(row['group'] == group and row['enabled'] == 'True'
                            and row['action'] == 'Block' and row['direction'] == 'Outbound'
                            and row['profile'] == 'Any', f'Unexpected rule properties in {store}.')
                    require(ntpath.normcase(row['program']) == program, f'Unexpected program in {store}.')
                    for field in ('local', 'remote'):
                        require({canonical(value) for value in row[field]} == set(spec[field]),
                                f'Unexpected {field} addresses in {store}.')

        def checked_powershell(script, payload, **kwargs):
            require(script == backend._FIREWALL and payload['group'] == group and payload['pattern'] == pattern
                    and not payload['remove'] and any(payload['rules'] == specs for _, specs in plans),
                    'Refusing a firewall change outside the verified fixture scopes.')
            return powershell(script, payload, **kwargs)

        require(read_rules(preflight=True) == [], 'Test rule names or group already exist.')
        report['cleaned'] = False
        try:
            firewall = backend.WindowsFirewall()
            with patch.object(backend, '_powershell', side_effect=checked_powershell):
                for label, specs in plans:
                    firewall._run(rules=specs)
                    verify_rules(specs)
                    report['passed'].append(label)
        finally:
            report['cleaned'] = read_rules(cleanup=True) == []
            require(report['cleaned'], 'Temporary program firewall rules are still present.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='Also write the result to this JSON file.')
    options = parser.parse_args()
    report = {'passed': []}
    try:
        require(sys.platform == 'win32' and is_admin(), 'Run this check from an elevated Windows prompt.')
        with TemporaryDirectory(prefix='ClaudeGuard-program-test-') as directory:
            executable = Path(directory) / 'firewall-fixture.exe'
            shutil.copyfile(sys._base_executable, executable)
            check_program_firewall(report, executable)
    except Exception as error:
        report['error'] = str(error)
    output = json.dumps(report, indent=2)
    if options.report:
        options.report.write_text(output + '\n', encoding='utf-8')
    print(output)
    return int('error' in report)


if __name__ == '__main__':
    sys.exit(main())
