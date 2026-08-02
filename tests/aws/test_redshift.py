"""Behavioural tests for policies/aws/redshift.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/redshift.yml'


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
        # KNOWN LIMITATION: `op: lt` against an absent key compares None and
        # never matches, so a cluster whose retention period never came back
        # is reported as compliant.
        {'ClusterIdentifier': 'key-absent'},
    ]
    matched = [r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-automated-snapshot-retention-insufficient', resources)]
    assert matched == ['matches']


def test_redshift_auto_major_version_upgrade_disabled():
    resources = [
        {'ClusterIdentifier': 'matches', 'AllowVersionUpgrade': False},
        {'ClusterIdentifier': 'clean', 'AllowVersionUpgrade': True},
        # KNOWN LIMITATION: `value: false` with no `absent` branch. None ==
        # False is False in Python, so a cluster missing the key escapes.
        {'ClusterIdentifier': 'key-absent'},
    ]
    matched = [r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-auto-major-version-upgrade-disabled', resources)]
    assert matched == ['matches']


def test_redshift_enhanced_vpc_routing_disabled():
    resources = [
        {'ClusterIdentifier': 'matches', 'EnhancedVpcRouting': False},
        {'ClusterIdentifier': 'clean', 'EnhancedVpcRouting': True},
        # KNOWN LIMITATION: `value: false` with no `absent` branch; the
        # cluster missing EnhancedVpcRouting is reported as compliant.
        {'ClusterIdentifier': 'key-absent'},
    ]
    matched = [r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-enhanced-vpc-routing-disabled', resources)]
    assert matched == ['matches']


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
        # KNOWN LIMITATION: the comparison is an equality against the string
        # "Disabled", so a cluster whose MultiAZ field never came back (an
        # older cluster predating the feature) is reported as compliant.
        {'ClusterIdentifier': 'key-absent'},
    ]
    matched = [r['ClusterIdentifier'] for r in run_policy(
        POLICIES, 'redshift-not-multi-az', resources)]
    assert matched == ['matches']
