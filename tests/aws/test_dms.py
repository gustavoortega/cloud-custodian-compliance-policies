"""Behavioural tests for policies/aws/dms.yml.

Offline: no AWS credentials, no network.

Resource shapes:
  - `aws.dms-instance` -> describe_replication_instances:
    ReplicationInstanceIdentifier (c7n's id), ReplicationInstanceArn,
    PubliclyAccessible / AutoMinorVersionUpgrade / MultiAZ as booleans.
  - `aws.dms-endpoint` -> describe_endpoints: EndpointArn (c7n's id),
    EndpointIdentifier, EngineName, SslMode, and one engine-specific settings
    block (NeptuneSettings / MongoDbSettings / RedisSettings) present only for
    that engine.
  - `aws.dms-replication-task` -> describe_replication_tasks:
    ReplicationTaskArn (c7n's id), ReplicationTaskIdentifier, and
    ReplicationTaskSettings as a JSON-ENCODED STRING (hence json.dumps below
    and the `from_json()` jmespath function in the policies).

ARNs are unique per resource because c7n's `or:` deduplicates matches by the
resource-type id. Assertions use the short identifier and are SORTED, because
`or:` rebuilds its result from a Python `set` and the order varies between
processes.
"""
import json

import pytest
from jmespath.exceptions import JMESPathTypeError

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/dms.yml'


def instance(name, **kw):
    return {
        'ReplicationInstanceIdentifier': name,
        'ReplicationInstanceArn': f'arn:aws:dms:us-east-1:111111111111:rep:{name}',
        'ReplicationInstanceClass': 'dms.t3.medium',
        **kw,
    }


def endpoint(name, **kw):
    return {
        'EndpointIdentifier': name,
        'EndpointArn': f'arn:aws:dms:us-east-1:111111111111:endpoint:{name}',
        **kw,
    }


ALL_LOG_COMPONENTS = ('SOURCE_CAPTURE', 'SOURCE_UNLOAD',
                      'TARGET_APPLY', 'TARGET_LOAD')


def task(name, *, enable_logging=True, components=ALL_LOG_COMPONENTS,
         with_enable_logging=True):
    logging = {'LogComponents': [
        {'Id': c, 'Severity': 'LOGGER_SEVERITY_DEFAULT'} for c in components]}
    if with_enable_logging:
        logging['EnableLogging'] = enable_logging
    return {
        'ReplicationTaskIdentifier': name,
        'ReplicationTaskArn': f'arn:aws:dms:us-east-1:111111111111:task:{name}',
        # comes back from the API as a JSON string, not a nested object
        'ReplicationTaskSettings': json.dumps({'Logging': logging}),
    }


def matched(policy, resources, key):
    return sorted(r[key] for r in run_policy(POLICIES, policy, resources))


def test_dms_replication_instance_publicly_accessible():
    resources = [
        instance('matches', PubliclyAccessible=True),
        instance('clean', PubliclyAccessible=False),
        # KNOWN LIMITATION: a bare `value: true` with no `absent` branch. An
        # instance whose PubliclyAccessible never came back resolves to None,
        # None == True is False, and it is reported as compliant.
        instance('key-absent'),
    ]
    assert matched('dms-replication-instance-publicly-accessible', resources,
                   'ReplicationInstanceIdentifier') == ['matches']


def test_dms_replication_instance_auto_minor_version_upgrade_disabled():
    resources = [
        instance('matches', AutoMinorVersionUpgrade=False),
        instance('clean', AutoMinorVersionUpgrade=True),
        # caught by the `or: absent` branch
        instance('key-absent'),
    ]
    assert matched('dms-replication-instance-auto-minor-version-upgrade-disabled',
                   resources, 'ReplicationInstanceIdentifier') == [
        'key-absent', 'matches']


def test_dms_replication_instance_single_az():
    resources = [
        instance('matches', MultiAZ=False),
        instance('clean', MultiAZ=True),
        # caught by the `or: absent` branch
        instance('key-absent'),
    ]
    assert matched('dms-replication-instance-single-az', resources,
                   'ReplicationInstanceIdentifier') == ['key-absent', 'matches']


def test_dms_endpoint_ssl_disabled():
    resources = [
        endpoint('matches', EngineName='mysql', SslMode='none'),
        endpoint('clean', EngineName='mysql', SslMode='require'),
        # S3 targets are structurally SslMode 'none' and are excluded
        endpoint('s3-excluded', EngineName='s3', SslMode='none'),
        # caught by the `or: absent` branch on SslMode
        endpoint('sslmode-absent', EngineName='mysql'),
        # `EngineName op: ne s3` on an absent key matches (None != 's3'), so an
        # endpoint with no EngineName still reaches the SslMode check. Over-
        # reporting rather than under-reporting, which is the safe direction.
        endpoint('enginename-absent', SslMode='none'),
    ]
    assert matched('dms-endpoint-ssl-disabled', resources, 'EndpointIdentifier') == [
        'enginename-absent', 'matches', 'sslmode-absent']


def test_dms_endpoint_neptune_iam_auth_disabled():
    resources = [
        endpoint('matches', EngineName='neptune', NeptuneSettings={
            'IamAuthEnabled': False, 'S3BucketName': 'stage-bucket',
            'S3BucketFolder': 'neptune'}),
        endpoint('clean', EngineName='neptune', NeptuneSettings={
            'IamAuthEnabled': True, 'S3BucketName': 'stage-bucket',
            'S3BucketFolder': 'neptune'}),
        # NeptuneSettings absent -> caught by the `or: absent` branch
        endpoint('settings-absent', EngineName='neptune'),
        endpoint('other-engine', EngineName='mysql'),
    ]
    assert matched('dms-endpoint-neptune-iam-auth-disabled', resources,
                   'EndpointIdentifier') == ['matches', 'settings-absent']


def test_dms_endpoint_mongodb_auth_disabled():
    resources = [
        # note the API returns the literal string 'NO', not a boolean
        endpoint('matches', EngineName='mongodb', MongoDbSettings={
            'AuthType': 'NO', 'AuthMechanism': 'default'}),
        endpoint('clean', EngineName='mongodb', MongoDbSettings={
            'AuthType': 'PASSWORD', 'AuthMechanism': 'scram-sha-1'}),
        # caught by the `or: absent` branch
        endpoint('settings-absent', EngineName='mongodb'),
        endpoint('other-engine', EngineName='mysql'),
    ]
    assert matched('dms-endpoint-mongodb-auth-disabled', resources,
                   'EndpointIdentifier') == ['matches', 'settings-absent']


def test_dms_endpoint_redis_tls_disabled():
    resources = [
        endpoint('matches', EngineName='redis', RedisSettings={
            'ServerName': 'redis.internal', 'Port': 6379,
            'SslSecurityProtocol': 'plaintext'}),
        endpoint('clean', EngineName='redis', RedisSettings={
            'ServerName': 'redis.internal', 'Port': 6379,
            'SslSecurityProtocol': 'ssl-encryption'}),
        # caught by the `or: absent` branch next to the `op: ne`
        endpoint('settings-absent', EngineName='redis'),
        endpoint('other-engine', EngineName='mysql'),
    ]
    assert matched('dms-endpoint-redis-tls-disabled', resources,
                   'EndpointIdentifier') == ['matches', 'settings-absent']


def test_dms_replication_task_target_logging_disabled():
    resources = [
        task('logging-off', enable_logging=False),
        task('clean'),
        task('missing-component',
             components=tuple(c for c in ALL_LOG_COMPONENTS if c != 'TARGET_APPLY')),
        # EnableLogging key itself missing -> caught by the `or: absent` branch
        task('enablelogging-absent', with_enable_logging=False),
    ]
    assert matched('dms-replication-task-target-logging-disabled', resources,
                   'ReplicationTaskIdentifier') == [
        'enablelogging-absent', 'logging-off', 'missing-component']

    # KNOWN LIMITATION: ReplicationTaskSettings missing entirely does not read
    # as a finding, it RAISES -- from_json() rejects null. A task the field
    # never came back for aborts the whole policy run rather than being
    # reported or skipped.
    with pytest.raises(JMESPathTypeError):
        run_policy(POLICIES, 'dms-replication-task-target-logging-disabled',
                   [{'ReplicationTaskIdentifier': 'settings-absent',
                     'ReplicationTaskArn':
                         'arn:aws:dms:us-east-1:111111111111:task:settings-absent'}])


def test_dms_replication_task_source_logging_disabled():
    resources = [
        task('logging-off', enable_logging=False),
        task('clean'),
        task('missing-component',
             components=tuple(c for c in ALL_LOG_COMPONENTS if c != 'SOURCE_CAPTURE')),
        # caught by the `or: absent` branch
        task('enablelogging-absent', with_enable_logging=False),
    ]
    assert matched('dms-replication-task-source-logging-disabled', resources,
                   'ReplicationTaskIdentifier') == [
        'enablelogging-absent', 'logging-off', 'missing-component']

    # KNOWN LIMITATION: same from_json() crash as the target-side control.
    with pytest.raises(JMESPathTypeError):
        run_policy(POLICIES, 'dms-replication-task-source-logging-disabled',
                   [{'ReplicationTaskIdentifier': 'settings-absent',
                     'ReplicationTaskArn':
                         'arn:aws:dms:us-east-1:111111111111:task:settings-absent'}])
