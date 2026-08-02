"""Behavioural tests for policies/aws/elasticache.yml.

Offline: no AWS credentials, no network.

Two resource types here: aws.elasticache-group (describe_replication_groups,
id ReplicationGroupId) and aws.cache-cluster (describe_cache_clusters, id
CacheClusterId).
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/elasticache.yml'


def test_elasticache_replication_group_unencrypted_at_rest():
    resources = [
        {'ReplicationGroupId': 'matches', 'AtRestEncryptionEnabled': False},
        {'ReplicationGroupId': 'clean', 'AtRestEncryptionEnabled': True},
        # covered: the policy carries the explicit `absent` branch
        {'ReplicationGroupId': 'key-absent'},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['ReplicationGroupId'] for r in run_policy(
        POLICIES, 'elasticache-replication-group-unencrypted-at-rest', resources))
    assert matched == ['key-absent', 'matches']


def test_elasticache_replication_group_no_transit_encryption():
    resources = [
        {'ReplicationGroupId': 'matches', 'TransitEncryptionEnabled': False},
        {'ReplicationGroupId': 'clean', 'TransitEncryptionEnabled': True},
        # covered: the policy carries the explicit `absent` branch
        {'ReplicationGroupId': 'key-absent'},
    ]
    matched = sorted(r['ReplicationGroupId'] for r in run_policy(
        POLICIES, 'elasticache-replication-group-no-transit-encryption', resources))
    assert matched == ['key-absent', 'matches']


def test_elasticache_replication_group_no_auth():
    resources = [
        {'ReplicationGroupId': 'matches', 'AuthTokenEnabled': False},
        {'ReplicationGroupId': 'clean-token', 'AuthTokenEnabled': True},
        {'ReplicationGroupId': 'clean-rbac', 'AuthTokenEnabled': False,
         'UserGroupIds': ['user-group-1']},
        # KNOWN LIMITATION: `value: false` on AuthTokenEnabled with no
        # `absent` branch. A group missing the key is None == False -> False,
        # so it is reported as compliant even though it has no auth at all.
        {'ReplicationGroupId': 'key-absent'},
    ]
    matched = [r['ReplicationGroupId'] for r in run_policy(
        POLICIES, 'elasticache-replication-group-no-auth', resources)]
    assert matched == ['matches']


def test_elasticache_replication_group_backup_disabled():
    resources = [
        {'ReplicationGroupId': 'matches', 'SnapshotRetentionLimit': 0},
        {'ReplicationGroupId': 'clean', 'SnapshotRetentionLimit': 5},
        # covered: the policy carries the explicit `absent` branch
        {'ReplicationGroupId': 'key-absent'},
    ]
    matched = sorted(r['ReplicationGroupId'] for r in run_policy(
        POLICIES, 'elasticache-replication-group-backup-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_elasticache_cluster_backup_disabled():
    resources = [
        {'CacheClusterId': 'matches', 'Engine': 'redis',
         'SnapshotRetentionLimit': 0},
        {'CacheClusterId': 'clean-retained', 'Engine': 'redis',
         'SnapshotRetentionLimit': 5},
        # part of a replication group: counted by the group-level control
        {'CacheClusterId': 'clean-in-group', 'Engine': 'redis',
         'ReplicationGroupId': 'rg-1', 'SnapshotRetentionLimit': 0},
        # memcached has no snapshot feature at all
        {'CacheClusterId': 'clean-memcached', 'Engine': 'memcached'},
        # covered: the policy carries the explicit `absent` branch on
        # SnapshotRetentionLimit
        {'CacheClusterId': 'key-absent', 'Engine': 'valkey'},
    ]
    matched = sorted(r['CacheClusterId'] for r in run_policy(
        POLICIES, 'elasticache-cluster-backup-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_elasticache_cluster_auto_minor_version_upgrade_disabled():
    resources = [
        {'CacheClusterId': 'matches', 'Engine': 'redis',
         'AutoMinorVersionUpgrade': False},
        {'CacheClusterId': 'clean', 'Engine': 'redis',
         'AutoMinorVersionUpgrade': True},
        {'CacheClusterId': 'clean-memcached', 'Engine': 'memcached',
         'AutoMinorVersionUpgrade': False},
        # covered: the policy carries the explicit `absent` branch
        {'CacheClusterId': 'key-absent', 'Engine': 'redis'},
        # Engine itself absent: `op: ne memcached` on None is True, so the
        # engine gate lets it through and the absent-upgrade branch reports
        # it. Documented, not a miss.
        {'CacheClusterId': 'engine-absent', 'AutoMinorVersionUpgrade': False},
    ]
    matched = sorted(r['CacheClusterId'] for r in run_policy(
        POLICIES, 'elasticache-cluster-auto-minor-version-upgrade-disabled', resources))
    assert matched == ['engine-absent', 'key-absent', 'matches']


def test_elasticache_replication_group_auto_failover_disabled():
    resources = [
        {'ReplicationGroupId': 'matches', 'AutomaticFailover': 'disabled'},
        {'ReplicationGroupId': 'clean', 'AutomaticFailover': 'enabled'},
        # `op: ne` against an absent key is None != 'enabled' -> True, so the
        # missing key IS captured. The policy's description bets on the field
        # always being populated; either way it does not slip through.
        {'ReplicationGroupId': 'key-absent'},
    ]
    matched = [r['ReplicationGroupId'] for r in run_policy(
        POLICIES, 'elasticache-replication-group-auto-failover-disabled', resources)]
    assert matched == ['matches', 'key-absent']


def test_elasticache_cluster_default_subnet_group():
    resources = [
        {'CacheClusterId': 'matches', 'CacheSubnetGroupName': 'default'},
        {'CacheClusterId': 'clean', 'CacheSubnetGroupName': 'cache-private'},
        # KNOWN LIMITATION: equality against the string "default", so a
        # cluster whose subnet group name never came back is compliant.
        {'CacheClusterId': 'key-absent'},
    ]
    matched = [r['CacheClusterId'] for r in run_policy(
        POLICIES, 'elasticache-cluster-default-subnet-group', resources)]
    assert matched == ['matches']
