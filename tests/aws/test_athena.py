"""Behavioural tests for policies/aws/athena.yml.

Offline: no AWS credentials, no network.

`Configuration` comes from GetWorkGroup, not from ListWorkGroups, so a
work group whose detail call was never merged in has no `Configuration`
key at all -- which is why every test here carries that case.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/athena.yml'


def test_athena_workgroup_results_not_encrypted():
    resources = [
        {'Name': 'matches', 'State': 'ENABLED',
         'Configuration': {'ResultConfiguration': {'OutputLocation': 's3://results/'}}},
        {'Name': 'clean', 'State': 'ENABLED',
         'Configuration': {'ResultConfiguration': {
             'OutputLocation': 's3://results/',
             'EncryptionConfiguration': {'EncryptionOption': 'SSE_S3'}}}},
        {'Name': 'disabled-workgroup', 'State': 'DISABLED',
         'Configuration': {'ResultConfiguration': {'OutputLocation': 's3://results/'}}},
        # the whole Configuration never came back: `value: absent` catches it
        {'Name': 'key-absent', 'State': 'ENABLED'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'athena-workgroup-results-not-encrypted', resources)]
    assert matched == ['matches', 'key-absent']


def test_athena_workgroup_config_not_enforced():
    resources = [
        {'Name': 'matches', 'State': 'ENABLED',
         'Configuration': {'EnforceWorkGroupConfiguration': False}},
        {'Name': 'clean', 'State': 'ENABLED',
         'Configuration': {'EnforceWorkGroupConfiguration': True}},
        # covered: EnforceWorkGroupConfiguration defaults to false, so absent
        # and false are the same finding.
        {'Name': 'key-absent', 'State': 'ENABLED', 'Configuration': {}},
        # the whole Configuration block missing, same branch
        {'Name': 'config-absent', 'State': 'ENABLED'},
        # still scoped out by the State gate, absent field or not
        {'Name': 'clean-disabled', 'State': 'DISABLED', 'Configuration': {}},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['Name'] for r in run_policy(
        POLICIES, 'athena-workgroup-config-not-enforced', resources))
    assert matched == ['config-absent', 'key-absent', 'matches']


def test_athena_workgroup_logging_disabled():
    resources = [
        {'Name': 'matches', 'State': 'ENABLED',
         'Configuration': {'PublishCloudWatchMetricsEnabled': False}},
        {'Name': 'clean', 'State': 'ENABLED',
         'Configuration': {'PublishCloudWatchMetricsEnabled': True}},
        # covered: PublishCloudWatchMetricsEnabled defaults to false, and a
        # work group with no Configuration at all was never verified either.
        {'Name': 'key-absent', 'State': 'ENABLED'},
    ]
    matched = sorted(r['Name'] for r in run_policy(
        POLICIES, 'athena-workgroup-logging-disabled', resources))
    assert matched == ['key-absent', 'matches']
