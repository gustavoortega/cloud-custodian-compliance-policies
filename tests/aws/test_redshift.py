"""Behavioural tests for policies/aws/redshift.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy, verify_mutation

POLICIES = 'policies/aws/redshift.yml'


def drop_absent_branch(policy):
    """Mutation: strip the `absent` branch out of the policy's leading `or`.

    That branch IS the fix, so every test that runs this mutation has to go
    red under it. `verify_mutation` raises if it stays green.
    """
    branch = policy['filters'][0]['or']
    policy['filters'][0]['or'] = [f for f in branch if f.get('value') != 'absent']
    return policy


def test_redshift_publicly_accessible():
    resources = [
        {'ClusterIdentifier': 'matches', 'PubliclyAccessible': True},
        {'ClusterIdentifier': 'clean', 'PubliclyAccessible': False},
        # PubliclyAccessible never came back from describe_clusters.
        # `value: true` on an absent key is None == True -> False, so the
        # cluster reads as compliant. Here absence is the safe direction.
        {'ClusterIdentifier': 'key-absent'},
    ]
    matched = [r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-publicly-accessible', resources)]
    assert matched == ['matches']


def test_redshift_automated_snapshot_retention_insufficient():
    resources = [
        {'ClusterIdentifier': 'matches', 'AutomatedSnapshotRetentionPeriod': 1},
        {'ClusterIdentifier': 'clean', 'AutomatedSnapshotRetentionPeriod': 7},
        # `op: lt` against an absent key compares None to 7, raises TypeError
        # and c7n reads that as "no match" -- which is why the fix is a SECOND
        # filter under an `or` and not a `value: absent` on this one.
        {'ClusterIdentifier': 'key-absent'},
    ]

    def expected(matched):
        # `or` unions its branches through a set, so the order c7n returns is
        # set-iteration order, not input order: sort before asserting.
        assert sorted(r['ClusterIdentifier'] for r in matched) == [
            'key-absent', 'matches']

    expected(run_policy(
        POLICIES, 'redshift-automated-snapshot-retention-insufficient', resources))
    verify_mutation(
        POLICIES, 'redshift-automated-snapshot-retention-insufficient', resources,
        mutate=drop_absent_branch, assertions=expected)


def test_redshift_auto_major_version_upgrade_disabled():
    resources = [
        {'ClusterIdentifier': 'matches', 'AllowVersionUpgrade': False},
        {'ClusterIdentifier': 'clean', 'AllowVersionUpgrade': True},
        # `None == False` is False in Python, so without the `absent` branch
        # the cluster missing the key would read as compliant.
        {'ClusterIdentifier': 'key-absent'},
    ]

    def expected(matched):
        assert sorted(r['ClusterIdentifier'] for r in matched) == [
            'key-absent', 'matches']

    expected(run_policy(
        POLICIES, 'redshift-auto-major-version-upgrade-disabled', resources))
    verify_mutation(
        POLICIES, 'redshift-auto-major-version-upgrade-disabled', resources,
        mutate=drop_absent_branch, assertions=expected)


def test_redshift_enhanced_vpc_routing_disabled():
    resources = [
        {'ClusterIdentifier': 'matches', 'EnhancedVpcRouting': False},
        {'ClusterIdentifier': 'clean', 'EnhancedVpcRouting': True},
        # The API documents the default as false, so the cluster missing the
        # key is caught by the `absent` branch rather than read as compliant.
        {'ClusterIdentifier': 'key-absent'},
    ]

    def expected(matched):
        assert sorted(r['ClusterIdentifier'] for r in matched) == [
            'key-absent', 'matches']

    expected(run_policy(POLICIES, 'redshift-enhanced-vpc-routing-disabled', resources))
    verify_mutation(
        POLICIES, 'redshift-enhanced-vpc-routing-disabled', resources,
        mutate=drop_absent_branch, assertions=expected)


def test_redshift_storage_unencrypted():
    resources = [
        {'ClusterIdentifier': 'matches', 'Encrypted': False},
        {'ClusterIdentifier': 'clean', 'Encrypted': True},
        # This policy DOES carry the `absent` branch, so the missing key is
        # captured instead of slipping through.
        {'ClusterIdentifier': 'key-absent'},
    ]
    # c7n's `or` resolves via set union (Or.process_set), so the order it
    # returns is set-iteration order, not input order: sort before asserting.
    matched = sorted(r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-storage-unencrypted', resources))
    assert matched == ['key-absent', 'matches']


def test_redshift_not_multi_az():
    resources = [
        {'ClusterIdentifier': 'matches', 'MultiAZ': 'Disabled'},
        {'ClusterIdentifier': 'clean', 'MultiAZ': 'Enabled'},
        # A cluster whose MultiAZ field never came back (an older cluster
        # predating the opt-in feature) IS single-AZ: the `absent` branch
        # reports it, and that is a true positive rather than a guess.
        {'ClusterIdentifier': 'key-absent'},
    ]

    def expected(matched):
        assert sorted(r['ClusterIdentifier'] for r in matched) == [
            'key-absent', 'matches']

    expected(run_policy(POLICIES, 'redshift-not-multi-az', resources))
    verify_mutation(POLICIES, 'redshift-not-multi-az', resources,
                    mutate=drop_absent_branch, assertions=expected)
