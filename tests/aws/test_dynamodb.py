"""Behavioural tests for policies/aws/dynamodb.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/dynamodb.yml'


def test_dynamodb_point_in_time_recovery_disabled():
    """This one cannot run offline any more, and that is the fix.

    It used to filter on `_ContinuousBackups`, a key nothing populates: not
    DescribeTable, not c7n, not this pack. Both branches of its `or` therefore
    matched every table in a real run, so the control reported 100% of the
    fleet and read as if every table had PITR off.

    It now uses c7n's own `continuous-backup` filter, which calls
    DescribeContinuousBackups per table. That is a real API call, so the
    harness refuses it rather than returning an empty list that looks like a
    clean result.
    """
    import pytest
    from c7n_kit.testing import FilterNeedsNetwork

    resources = [{'TableName': 'any', 'TableStatus': 'ACTIVE'}]
    with pytest.raises(FilterNeedsNetwork):
        run_policy(POLICIES, 'dynamodb-point-in-time-recovery-disabled', resources)


def test_dynamodb_deletion_protection_disabled():
    resources = [
        {'TableName': 'matches', 'TableStatus': 'ACTIVE',
         'DeletionProtectionEnabled': False},
        {'TableName': 'clean', 'TableStatus': 'ACTIVE',
         'DeletionProtectionEnabled': True},
        # covered: protection has to be turned on explicitly, so a table with
        # no flag at all is exactly as deletable as one with an explicit
        # false.
        {'TableName': 'key-absent', 'TableStatus': 'ACTIVE'},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['TableName'] for r in run_policy(
        POLICIES, 'dynamodb-deletion-protection-disabled', resources))
    assert matched == ['key-absent', 'matches']
