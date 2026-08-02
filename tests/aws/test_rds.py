"""Behavioural tests for policies/aws/rds.yml.

Offline: no AWS credentials, no network.

Every test asserts the REAL behaviour of the policy as written, including the
cases where a resource that is missing the key escapes the filter. Those are
marked with a `# KNOWN LIMITATION` comment. Nothing here fixes a policy.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/rds.yml'


def ids(matched, key='DBInstanceIdentifier'):
    """Matched identifiers in the order c7n returned them.

    Only valid for a flat `and` chain of value filters, which preserves the
    input order.
    """
    return [r[key] for r in matched]


def sids(matched, key='DBInstanceIdentifier'):
    """Matched identifiers, sorted.

    c7n's `or` and `not` filters union their branches through a Python `set`
    (c7n/filters/core.py, `Or.process_set` / `Not.process_set`), so the order
    they return is the set's iteration order, not the input order, and it
    varies with PYTHONHASHSEED between runs. For any policy that contains a
    boolean group, the identifier SET is the observable behaviour.
    """
    return sorted(r[key] for r in matched)


# ---------------------------------------------------------------- aws.rds ---

def test_rds_backup_retention_insufficient():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'BackupRetentionPeriod': 0},
        {'DBInstanceIdentifier': 'matches-short', 'BackupRetentionPeriod': 3},
        {'DBInstanceIdentifier': 'clean', 'BackupRetentionPeriod': 7},
        # KNOWN LIMITATION: `op: lt` over an absent key compares None < 7,
        # c7n swallows the TypeError and returns False, so the instance is
        # reported as compliant.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-backup-retention-insufficient', resources))
    assert matched == ['matches', 'matches-short']


def test_inventory_rds_public_endpoint():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'PubliclyAccessible': True},
        {'DBInstanceIdentifier': 'clean', 'PubliclyAccessible': False},
        # `value: true` over an absent key: None == True is False, so an
        # instance whose flag never came back is not inventoried.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'inventory-rds-public-endpoint', resources))
    assert matched == ['matches']


def test_rds_storage_unencrypted():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'StorageEncrypted': False},
        {'DBInstanceIdentifier': 'clean', 'StorageEncrypted': True},
        # KNOWN LIMITATION: no `absent` branch. None == False is False, so an
        # instance where StorageEncrypted never came back reads as encrypted.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-storage-unencrypted', resources))
    assert matched == ['matches']


def test_rds_instance_deletion_protection_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'DeletionProtection': False},
        {'DBInstanceIdentifier': 'clean', 'DeletionProtection': True},
        # This policy DOES carry the `absent` branch, so the key-less
        # instance is correctly caught.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = sids(run_policy(POLICIES, 'rds-instance-deletion-protection-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_rds_instance_iam_auth_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'Engine': 'postgres',
         'DBInstanceStatus': 'available', 'IAMDatabaseAuthenticationEnabled': False},
        {'DBInstanceIdentifier': 'clean', 'Engine': 'postgres',
         'DBInstanceStatus': 'available', 'IAMDatabaseAuthenticationEnabled': True},
        {'DBInstanceIdentifier': 'other-engine', 'Engine': 'oracle-se2',
         'DBInstanceStatus': 'available', 'IAMDatabaseAuthenticationEnabled': False},
        {'DBInstanceIdentifier': 'not-available', 'Engine': 'postgres',
         'DBInstanceStatus': 'stopped', 'IAMDatabaseAuthenticationEnabled': False},
        # KNOWN LIMITATION: no `absent` branch on the boolean.
        {'DBInstanceIdentifier': 'key-absent', 'Engine': 'postgres',
         'DBInstanceStatus': 'available'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-instance-iam-auth-disabled', resources))
    assert matched == ['matches']


def test_rds_instance_auto_minor_version_upgrade_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'AutoMinorVersionUpgrade': False},
        {'DBInstanceIdentifier': 'clean', 'AutoMinorVersionUpgrade': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less instance escapes.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(
        POLICIES, 'rds-instance-auto-minor-version-upgrade-disabled', resources))
    assert matched == ['matches']


def test_rds_instance_copy_tags_to_snapshot_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'CopyTagsToSnapshot': False},
        {'DBInstanceIdentifier': 'clean', 'CopyTagsToSnapshot': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less instance escapes.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(
        POLICIES, 'rds-instance-copy-tags-to-snapshot-disabled', resources))
    assert matched == ['matches']


def test_rds_instance_using_default_engine_port():
    resources = [
        {'DBInstanceIdentifier': 'matches-pg', 'Engine': 'postgres', 'DbInstancePort': 5432},
        {'DBInstanceIdentifier': 'matches-mysql', 'Engine': 'mysql', 'DbInstancePort': 3306},
        {'DBInstanceIdentifier': 'matches-mssql', 'Engine': 'sqlserver-ex', 'DbInstancePort': 1433},
        {'DBInstanceIdentifier': 'clean-pg', 'Engine': 'postgres', 'DbInstancePort': 6543},
        {'DBInstanceIdentifier': 'aurora-excluded', 'Engine': 'aurora-mysql', 'DbInstancePort': 3306},
        # Engine absent passes the `not-in` guard (None not-in [...] is True)
        # but no engine/port branch can match, so it is not reported.
        {'DBInstanceIdentifier': 'key-absent', 'DbInstancePort': 5432},
    ]
    matched = sids(run_policy(POLICIES, 'rds-instance-using-default-engine-port', resources))
    assert matched == ['matches-mssql', 'matches-mysql', 'matches-pg']


def test_rds_instance_default_admin_username():
    resources = [
        {'DBInstanceIdentifier': 'matches-pg', 'Engine': 'postgres', 'MasterUsername': 'postgres'},
        {'DBInstanceIdentifier': 'matches-mysql', 'Engine': 'mysql', 'MasterUsername': 'admin'},
        {'DBInstanceIdentifier': 'clean', 'Engine': 'postgres', 'MasterUsername': 'appowner'},
        {'DBInstanceIdentifier': 'aurora-excluded', 'Engine': 'aurora-mysql', 'MasterUsername': 'admin'},
        # MasterUsername absent: None never equals the default name.
        {'DBInstanceIdentifier': 'key-absent', 'Engine': 'postgres'},
    ]
    matched = sids(run_policy(POLICIES, 'rds-instance-default-admin-username', resources))
    assert matched == ['matches-mysql', 'matches-pg']


def test_rds_postgres_instance_cloudwatch_logs_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'Engine': 'postgres',
         'EnabledCloudwatchLogsExports': ['upgrade']},
        {'DBInstanceIdentifier': 'clean', 'Engine': 'postgres',
         'EnabledCloudwatchLogsExports': ['postgresql', 'upgrade']},
        {'DBInstanceIdentifier': 'other-engine', 'Engine': 'mysql',
         'EnabledCloudwatchLogsExports': []},
        # `not: contains` over an absent list DOES catch it: contains(None)
        # is False, and the `not` flips it to a match.
        {'DBInstanceIdentifier': 'key-absent', 'Engine': 'postgres'},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-postgres-instance-cloudwatch-logs-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_rds_sqlserver_instance_cloudwatch_logs_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'Engine': 'sqlserver-se',
         'EnabledCloudwatchLogsExports': ['error']},
        {'DBInstanceIdentifier': 'clean', 'Engine': 'sqlserver-se',
         'EnabledCloudwatchLogsExports': ['agent', 'error']},
        {'DBInstanceIdentifier': 'other-engine', 'Engine': 'postgres'},
        # absent list is caught by the `not: and: contains` composition.
        {'DBInstanceIdentifier': 'key-absent', 'Engine': 'sqlserver-ex'},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-sqlserver-instance-cloudwatch-logs-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_rds_mariadb_instance_cloudwatch_logs_disabled():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'Engine': 'mariadb',
         'EnabledCloudwatchLogsExports': ['error']},
        {'DBInstanceIdentifier': 'clean', 'Engine': 'mariadb',
         'EnabledCloudwatchLogsExports': ['audit', 'error']},
        {'DBInstanceIdentifier': 'other-engine', 'Engine': 'mysql'},
        # absent list is caught by the `not: and: contains` composition.
        {'DBInstanceIdentifier': 'key-absent', 'Engine': 'mariadb'},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-mariadb-instance-cloudwatch-logs-disabled', resources))
    assert matched == ['key-absent', 'matches']


def test_rds_security_groups():
    resources = [
        {'DBInstanceIdentifier': 'matches', 'VpcSecurityGroups': [
            {'VpcSecurityGroupId': 'sg-0a1b2c3d', 'Status': 'active'}]},
        # c7n implements `not-null` as truthiness (`v == 'not-null' and r`),
        # not as `is not None`, so an EMPTY list does not match.
        {'DBInstanceIdentifier': 'empty-list-not-matched', 'VpcSecurityGroups': []},
        # `value: not-null` over an absent key does not match either.
        {'DBInstanceIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-security-groups', resources))
    assert matched == ['matches']


# -------------------------------------------------------- aws.rds-cluster ---

def test_rds_cluster_iam_auth_disabled():
    resources = [
        {'DBClusterIdentifier': 'matches', 'IAMDatabaseAuthenticationEnabled': False},
        {'DBClusterIdentifier': 'clean', 'IAMDatabaseAuthenticationEnabled': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less cluster escapes.
        {'DBClusterIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-cluster-iam-auth-disabled', resources),
                  'DBClusterIdentifier')
    assert matched == ['matches']


def test_rds_cluster_not_multi_az():
    resources = [
        {'DBClusterIdentifier': 'matches', 'MultiAZ': False},
        {'DBClusterIdentifier': 'clean', 'MultiAZ': True},
        # KNOWN LIMITATION: DescribeDBClusters does not return MultiAZ for
        # every engine/cluster shape, and there is no `absent` branch, so
        # those clusters are silently reported as multi-AZ.
        {'DBClusterIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-cluster-not-multi-az', resources),
                  'DBClusterIdentifier')
    assert matched == ['matches']


def test_rds_cluster_copy_tags_to_snapshot_disabled():
    resources = [
        {'DBClusterIdentifier': 'matches', 'CopyTagsToSnapshot': False},
        {'DBClusterIdentifier': 'clean', 'CopyTagsToSnapshot': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less cluster escapes.
        {'DBClusterIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(
        POLICIES, 'rds-cluster-copy-tags-to-snapshot-disabled', resources),
        'DBClusterIdentifier')
    assert matched == ['matches']


def test_rds_cluster_storage_unencrypted():
    resources = [
        {'DBClusterIdentifier': 'matches', 'StorageEncrypted': False},
        {'DBClusterIdentifier': 'clean', 'StorageEncrypted': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less cluster escapes.
        {'DBClusterIdentifier': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-cluster-storage-unencrypted', resources),
                  'DBClusterIdentifier')
    assert matched == ['matches']


def test_rds_cluster_default_admin_username():
    resources = [
        {'DBClusterIdentifier': 'matches-mysql', 'Engine': 'aurora-mysql',
         'MasterUsername': 'admin'},
        {'DBClusterIdentifier': 'matches-pg', 'Engine': 'aurora-postgresql',
         'MasterUsername': 'postgres'},
        {'DBClusterIdentifier': 'clean', 'Engine': 'aurora-mysql',
         'MasterUsername': 'appowner'},
        # MasterUsername absent: None never equals the default name.
        {'DBClusterIdentifier': 'key-absent', 'Engine': 'aurora-mysql'},
    ]
    matched = sids(run_policy(POLICIES, 'rds-cluster-default-admin-username', resources),
                  'DBClusterIdentifier')
    assert matched == ['matches-mysql', 'matches-pg']


def test_rds_cluster_aurora_mysql_audit_log_disabled():
    resources = [
        {'DBClusterIdentifier': 'matches', 'Engine': 'aurora-mysql',
         'EngineMode': 'provisioned', 'EnabledCloudwatchLogsExports': ['error']},
        {'DBClusterIdentifier': 'clean', 'Engine': 'aurora-mysql',
         'EngineMode': 'provisioned', 'EnabledCloudwatchLogsExports': ['audit', 'error']},
        {'DBClusterIdentifier': 'serverless-excluded', 'Engine': 'aurora-mysql',
         'EngineMode': 'serverless'},
        # absent list is caught by the `not: contains` composition.
        {'DBClusterIdentifier': 'key-absent', 'Engine': 'aurora-mysql',
         'EngineMode': 'provisioned'},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-cluster-aurora-mysql-audit-log-disabled', resources),
        'DBClusterIdentifier')
    assert matched == ['key-absent', 'matches']


def test_rds_multi_az_cluster_auto_minor_version_upgrade_disabled():
    resources = [
        {'DBClusterIdentifier': 'matches', 'Engine': 'mysql',
         'AutoMinorVersionUpgrade': False},
        {'DBClusterIdentifier': 'clean', 'Engine': 'mysql',
         'AutoMinorVersionUpgrade': True},
        {'DBClusterIdentifier': 'aurora-excluded', 'Engine': 'aurora-mysql',
         'AutoMinorVersionUpgrade': False},
        # KNOWN LIMITATION: no `absent` branch, the key-less cluster escapes.
        {'DBClusterIdentifier': 'key-absent', 'Engine': 'mysql'},
    ]
    matched = ids(run_policy(
        POLICIES, 'rds-multi-az-cluster-auto-minor-version-upgrade-disabled', resources),
        'DBClusterIdentifier')
    assert matched == ['matches']


def test_rds_cluster_aurora_postgresql_cloudwatch_logs_disabled():
    resources = [
        {'DBClusterIdentifier': 'matches', 'Engine': 'aurora-postgresql',
         'EnabledCloudwatchLogsExports': []},
        {'DBClusterIdentifier': 'clean', 'Engine': 'aurora-postgresql',
         'EnabledCloudwatchLogsExports': ['postgresql']},
        {'DBClusterIdentifier': 'other-engine', 'Engine': 'aurora-mysql'},
        # absent list is caught by the `not: contains` composition.
        {'DBClusterIdentifier': 'key-absent', 'Engine': 'aurora-postgresql'},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-cluster-aurora-postgresql-cloudwatch-logs-disabled', resources),
        'DBClusterIdentifier')
    assert matched == ['key-absent', 'matches']


# ------------------------------------------------------- aws.rds-snapshot ---

def test_rds_snapshot_unencrypted_manual():
    resources = [
        {'DBSnapshotIdentifier': 'matches', 'SnapshotType': 'manual', 'Encrypted': False},
        {'DBSnapshotIdentifier': 'clean', 'SnapshotType': 'manual', 'Encrypted': True},
        {'DBSnapshotIdentifier': 'automated-excluded', 'SnapshotType': 'automated',
         'Encrypted': False},
        # KNOWN LIMITATION: no `absent` branch on Encrypted, so a manual
        # snapshot missing the flag reads as encrypted.
        {'DBSnapshotIdentifier': 'key-absent', 'SnapshotType': 'manual'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-snapshot-unencrypted-manual', resources),
                  'DBSnapshotIdentifier')
    assert matched == ['matches']


def test_rds_cluster_snapshot_unencrypted_manual():
    resources = [
        {'DBClusterSnapshotIdentifier': 'matches', 'SnapshotType': 'manual',
         'Encrypted': False},
        {'DBClusterSnapshotIdentifier': 'clean', 'SnapshotType': 'manual',
         'Encrypted': True},
        {'DBClusterSnapshotIdentifier': 'automated-excluded', 'SnapshotType': 'automated',
         'Encrypted': False},
        # KNOWN LIMITATION: no `absent` branch on Encrypted.
        {'DBClusterSnapshotIdentifier': 'key-absent', 'SnapshotType': 'manual'},
    ]
    matched = ids(run_policy(
        POLICIES, 'rds-cluster-snapshot-unencrypted-manual', resources),
        'DBClusterSnapshotIdentifier')
    assert matched == ['matches']


# --------------------------------------------------- aws.rds-subscription ---

def test_rds_event_subscription_cluster_incomplete():
    resources = [
        {'CustSubscriptionId': 'matches-disabled', 'SourceType': 'db-cluster',
         'Enabled': False, 'EventCategoriesList': ['maintenance', 'failure']},
        {'CustSubscriptionId': 'matches-missing-category', 'SourceType': 'db-cluster',
         'Enabled': True, 'EventCategoriesList': ['maintenance']},
        {'CustSubscriptionId': 'clean', 'SourceType': 'db-cluster',
         'Enabled': True, 'EventCategoriesList': ['maintenance', 'failure']},
        {'CustSubscriptionId': 'other-source-type', 'SourceType': 'db-instance',
         'Enabled': False, 'EventCategoriesList': []},
        # KNOWN LIMITATION: `Enabled` absent does not match the `value: false`
        # branch, so with a complete category list the subscription escapes.
        {'CustSubscriptionId': 'enabled-absent', 'SourceType': 'db-cluster',
         'EventCategoriesList': ['maintenance', 'failure']},
        # An absent category list IS caught by the `not: contains` branch.
        {'CustSubscriptionId': 'categories-absent', 'SourceType': 'db-cluster',
         'Enabled': True},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-event-subscription-cluster-incomplete', resources),
        'CustSubscriptionId')
    assert matched == ['categories-absent', 'matches-disabled', 'matches-missing-category']


def test_rds_event_subscription_instance_incomplete():
    full = ['maintenance', 'configuration change', 'failure']
    resources = [
        {'CustSubscriptionId': 'matches-disabled', 'SourceType': 'db-instance',
         'Enabled': False, 'EventCategoriesList': full},
        {'CustSubscriptionId': 'matches-missing-category', 'SourceType': 'db-instance',
         'Enabled': True, 'EventCategoriesList': ['maintenance', 'failure']},
        {'CustSubscriptionId': 'clean', 'SourceType': 'db-instance',
         'Enabled': True, 'EventCategoriesList': full},
        {'CustSubscriptionId': 'other-source-type', 'SourceType': 'db-cluster',
         'Enabled': False, 'EventCategoriesList': []},
        # KNOWN LIMITATION: `Enabled` absent escapes when the categories are complete.
        {'CustSubscriptionId': 'enabled-absent', 'SourceType': 'db-instance',
         'EventCategoriesList': full},
        # An absent category list IS caught.
        {'CustSubscriptionId': 'categories-absent', 'SourceType': 'db-instance',
         'Enabled': True},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-event-subscription-instance-incomplete', resources),
        'CustSubscriptionId')
    assert matched == ['categories-absent', 'matches-disabled', 'matches-missing-category']


def test_rds_event_subscription_parameter_group_incomplete():
    resources = [
        {'CustSubscriptionId': 'matches-disabled', 'SourceType': 'db-parameter-group',
         'Enabled': False, 'EventCategoriesList': ['configuration change']},
        {'CustSubscriptionId': 'matches-missing-category',
         'SourceType': 'db-parameter-group', 'Enabled': True,
         'EventCategoriesList': ['failure']},
        {'CustSubscriptionId': 'clean', 'SourceType': 'db-parameter-group',
         'Enabled': True, 'EventCategoriesList': ['configuration change']},
        {'CustSubscriptionId': 'other-source-type', 'SourceType': 'db-instance',
         'Enabled': False, 'EventCategoriesList': []},
        # KNOWN LIMITATION: `Enabled` absent escapes when the category is present.
        {'CustSubscriptionId': 'enabled-absent', 'SourceType': 'db-parameter-group',
         'EventCategoriesList': ['configuration change']},
        # An absent category list IS caught.
        {'CustSubscriptionId': 'categories-absent', 'SourceType': 'db-parameter-group',
         'Enabled': True},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-event-subscription-parameter-group-incomplete', resources),
        'CustSubscriptionId')
    assert matched == ['categories-absent', 'matches-disabled', 'matches-missing-category']


def test_rds_event_subscription_security_group_incomplete():
    full = ['configuration change', 'failure']
    resources = [
        {'CustSubscriptionId': 'matches-disabled', 'SourceType': 'db-security-group',
         'Enabled': False, 'EventCategoriesList': full},
        {'CustSubscriptionId': 'matches-missing-category',
         'SourceType': 'db-security-group', 'Enabled': True,
         'EventCategoriesList': ['failure']},
        {'CustSubscriptionId': 'clean', 'SourceType': 'db-security-group',
         'Enabled': True, 'EventCategoriesList': full},
        {'CustSubscriptionId': 'other-source-type', 'SourceType': 'db-instance',
         'Enabled': False, 'EventCategoriesList': []},
        # KNOWN LIMITATION: `Enabled` absent escapes when the categories are complete.
        {'CustSubscriptionId': 'enabled-absent', 'SourceType': 'db-security-group',
         'EventCategoriesList': full},
        # An absent category list IS caught.
        {'CustSubscriptionId': 'categories-absent', 'SourceType': 'db-security-group',
         'Enabled': True},
    ]
    matched = sids(run_policy(
        POLICIES, 'rds-event-subscription-security-group-incomplete', resources),
        'CustSubscriptionId')
    assert matched == ['categories-absent', 'matches-disabled', 'matches-missing-category']


# ---------------------------------------------------------- aws.rds-proxy ---

def test_rds_proxy_tls_not_required():
    resources = [
        {'DBProxyName': 'matches', 'RequireTLS': False},
        {'DBProxyName': 'clean', 'RequireTLS': True},
        # KNOWN LIMITATION: no `absent` branch, the key-less proxy escapes.
        {'DBProxyName': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'rds-proxy-tls-not-required', resources),
                  'DBProxyName')
    assert matched == ['matches']
