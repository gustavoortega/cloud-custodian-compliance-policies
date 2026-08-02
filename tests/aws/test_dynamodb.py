"""Behavioural tests for policies/aws/dynamodb.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/dynamodb.yml'


def test_dynamodb_point_in_time_recovery_disabled():
    resources = [
        {'TableName': 'matches', 'TableStatus': 'ACTIVE',
         '_ContinuousBackups': {
             'ContinuousBackupsStatus': 'ENABLED',
             'PointInTimeRecoveryDescription': {
                 'PointInTimeRecoveryStatus': 'DISABLED'}}},
        {'TableName': 'clean', 'TableStatus': 'ACTIVE',
         '_ContinuousBackups': {
             'ContinuousBackupsStatus': 'ENABLED',
             'PointInTimeRecoveryDescription': {
                 'PointInTimeRecoveryStatus': 'ENABLED'}}},
        # `_ContinuousBackups` is NOT a field DescribeTable returns and nothing
        # in c7n or in this repo's extensions populates it, so in a real run
        # every table looks like this one and the `absent` branch matches all of
        # them. Documented, not fixed here.
        {'TableName': 'key-absent', 'TableStatus': 'ACTIVE'},
    ]
    matched = [r['TableName'] for r in run_policy(
        POLICIES, 'dynamodb-point-in-time-recovery-disabled', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']


def test_dynamodb_deletion_protection_disabled():
    resources = [
        {'TableName': 'matches', 'TableStatus': 'ACTIVE',
         'DeletionProtectionEnabled': False},
        {'TableName': 'clean', 'TableStatus': 'ACTIVE',
         'DeletionProtectionEnabled': True},
        # KNOWN LIMITATION: `value: false` with no `absent` branch, so a table
        # whose DeletionProtectionEnabled never came back reads as compliant.
        {'TableName': 'key-absent', 'TableStatus': 'ACTIVE'},
    ]
    matched = [r['TableName'] for r in run_policy(
        POLICIES, 'dynamodb-deletion-protection-disabled', resources)]
    assert matched == ['matches']
