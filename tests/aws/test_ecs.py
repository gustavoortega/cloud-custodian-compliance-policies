"""Behavioural tests for policies/aws/ecs.yml.

Offline: no AWS credentials, no network.

The task-definition policies open with the custom `latest-revision`
filter (c7n_pack), which groups by the family inside `taskDefinitionArn`
and keeps the highest revision of each. Every fixture below uses a
distinct family so nothing is dropped by that first filter.

`containerDefinitions` is present on every task-definition fixture on
purpose: the JMESPath `length(containerDefinitions[?...])` raises
`In function length(), invalid type for value: None` when the key is
missing altogether, so "no container definitions at all" is not a silent
miss, it is a hard error. That case is asserted explicitly at the end.
"""

import pytest


from c7n_kit.testing import run_policy  # noqa: E402

POLICIES = 'policies/aws/ecs.yml'
TD = 'arn:aws:ecs:us-east-1:000000000000:task-definition/%s:1'


def test_ecs_task_definition_shares_host_pid_namespace():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'pidMode': 'host', 'containerDefinitions': [{'name': 'app'}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'pidMode': 'task', 'containerDefinitions': [{'name': 'app'}]},
        # pidMode is optional and unset means the isolated default, so the
        # positive match on 'host' correctly reads the absence as compliant.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-shares-host-pid-namespace', resources)]
    assert matched == ['matches']


def test_ecs_task_definition_privileged_container():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'privileged': True}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'privileged': False}]},
        # `privileged` unset comes back as no key at all; the JMESPath positive
        # match on `true` reads that as compliant, which is the right direction.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-privileged-container', resources)]
    assert matched == ['matches']


def test_ecs_task_definition_writable_root_filesystem():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'LINUX'},
         'containerDefinitions': [{'name': 'app', 'readonlyRootFilesystem': False}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'LINUX'},
         'containerDefinitions': [{'name': 'app', 'readonlyRootFilesystem': True}]},
        {'taskDefinitionArn': TD % 'windows', 'family': 'windows', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'WINDOWS_SERVER_2019_CORE'},
         'containerDefinitions': [{'name': 'app'}]},
        # runtimePlatform absent -> `op: ne WINDOWS_SERVER` is True (None != str),
        # and readonlyRootFilesystem absent counts as "not true", so a task
        # definition with neither key IS caught. Both absences work in favour of
        # the control here.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-writable-root-filesystem', resources)]
    assert matched == ['matches', 'windows', 'key-absent']


def test_ecs_task_definition_secret_in_environment():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'environment': [
             {'name': 'AWS_SECRET_ACCESS_KEY', 'value': 'redacted'}]}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'environment': [
             {'name': 'LOG_LEVEL', 'value': 'info'}]}]},
        # no `environment` key at all: the JMESPath flattens to an empty list,
        # length 0, no match. Correct: nothing is exposed.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-secret-in-environment', resources)]
    assert matched == ['matches']


def test_ecs_task_definition_no_log_configuration():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'logConfiguration': {}}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'containerDefinitions': [{'name': 'app', 'logConfiguration': {
             'logDriver': 'awslogs',
             'options': {'awslogs-group': '/ecs/app'}}}]},
        # logConfiguration absent entirely resolves logDriver to null, which is
        # exactly what the filter looks for, so this IS caught.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-no-log-configuration', resources)]
    assert matched == ['matches', 'key-absent']


def test_ecs_task_definition_root_user():
    resources = [
        {'taskDefinitionArn': TD % 'matches', 'family': 'matches', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'LINUX'},
         'containerDefinitions': [{'name': 'app', 'user': 'root'}]},
        {'taskDefinitionArn': TD % 'matches-uid', 'family': 'matches-uid', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'LINUX'},
         'containerDefinitions': [{'name': 'app', 'user': '0:0'}]},
        {'taskDefinitionArn': TD % 'clean', 'family': 'clean', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'LINUX'},
         'containerDefinitions': [{'name': 'app', 'user': '1000'}]},
        {'taskDefinitionArn': TD % 'windows', 'family': 'windows', 'revision': 1,
         'runtimePlatform': {'operatingSystemFamily': 'WINDOWS_SERVER_2019_CORE'},
         'containerDefinitions': [{'name': 'app'}]},
        # `user` unset IS the finding per FSBP ECS.20 (`user==null`), and an
        # absent runtimePlatform passes the `op: ne` Windows exclusion, so a task
        # definition with neither key is caught.
        {'taskDefinitionArn': TD % 'key-absent', 'family': 'key-absent', 'revision': 1,
         'containerDefinitions': [{'name': 'app'}]},
    ]
    matched = [r['family'] for r in run_policy(
        POLICIES, 'ecs-task-definition-root-user', resources)]
    assert matched == ['matches', 'matches-uid', 'windows', 'key-absent']


def test_ecs_task_definition_without_container_definitions_raises():
    """The `length(...)` JMESPath is a hard error, not a silent miss."""
    resources = [{'taskDefinitionArn': TD % 'empty', 'family': 'empty', 'revision': 1}]
    with pytest.raises(Exception) as exc:
        run_policy(POLICIES, 'ecs-task-definition-privileged-container', resources)
    assert 'length()' in str(exc.value)


def test_detect_public_ecs():
    arn = 'arn:aws:ecs:us-east-1:000000000000:service/cluster/%s'
    resources = [
        {'serviceArn': arn % 'matches', 'serviceName': 'matches',
         'networkConfiguration': {'awsvpcConfiguration': {
             'subnets': ['subnet-1'], 'assignPublicIp': 'ENABLED'}}},
        {'serviceArn': arn % 'clean', 'serviceName': 'clean',
         'networkConfiguration': {'awsvpcConfiguration': {
             'subnets': ['subnet-1'], 'assignPublicIp': 'DISABLED'}}},
        # a bridge/host-network service has no networkConfiguration at all;
        # the positive match on ENABLED reads that as compliant, correctly.
        {'serviceArn': arn % 'key-absent', 'serviceName': 'key-absent'},
    ]
    matched = [r['serviceName'] for r in run_policy(
        POLICIES, 'detect-public-ecs', resources)]
    assert matched == ['matches']


def test_ecs_cluster_container_insights_disabled():
    arn = 'arn:aws:ecs:us-east-1:000000000000:cluster/%s'
    resources = [
        {'clusterArn': arn % 'matches', 'clusterName': 'matches',
         'settings': [{'name': 'containerInsights', 'value': 'disabled'}]},
        {'clusterArn': arn % 'clean', 'clusterName': 'clean',
         'settings': [{'name': 'containerInsights', 'value': 'enabled'}]},
        {'clusterArn': arn % 'clean-enhanced', 'clusterName': 'clean-enhanced',
         'settings': [{'name': 'containerInsights', 'value': 'enhanced'}]},
        # no settings list: the JMESPath resolves to null and c7n turns a None
        # into () before a `not-in`, so () not in [enabled, enhanced] -> True.
        # The cluster IS caught, matching FSBP's definition.
        {'clusterArn': arn % 'key-absent', 'clusterName': 'key-absent'},
    ]
    matched = [r['clusterName'] for r in run_policy(
        POLICIES, 'ecs-cluster-container-insights-disabled', resources)]
    assert matched == ['matches', 'key-absent']


def test_ecs_service_fargate_platform_version_outdated():
    arn = 'arn:aws:ecs:us-east-1:000000000000:service/cluster/%s'
    resources = [
        {'serviceArn': arn % 'matches', 'serviceName': 'matches',
         'launchType': 'FARGATE', 'platformVersion': '1.2.0'},
        {'serviceArn': arn % 'clean', 'serviceName': 'clean',
         'launchType': 'FARGATE', 'platformVersion': 'LATEST'},
        {'serviceArn': arn % 'ec2', 'serviceName': 'ec2',
         'launchType': 'EC2'},
        # KNOWN BEHAVIOUR: platformVersion absent on a FARGATE service is not in
        # the allow-list either, so the `not` branch matches it too.
        {'serviceArn': arn % 'key-absent', 'serviceName': 'key-absent',
         'launchType': 'FARGATE'},
    ]
    matched = [r['serviceName'] for r in run_policy(
        POLICIES, 'ecs-service-fargate-platform-version-outdated', resources)]
    # `not` merges through a set of ids, so sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']
