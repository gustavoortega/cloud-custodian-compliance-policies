"""Behavioural tests for policies/aws/opensearch.yml.

Offline: no AWS credentials, no network.

Resource shape: `aws.elasticsearch` is what `es:DescribeElasticsearchDomains`
returns -- `DomainName` plus the option blocks (`EncryptionAtRestOptions`,
`NodeToNodeEncryptionOptions`, `LogPublishingOptions`,
`ElasticsearchClusterConfig`, `DomainEndpointOptions`,
`AdvancedSecurityOptions`, `ServiceSoftwareOptions`, `VPCOptions`).

On sorting: c7n's `or:` (c7n.filters.core.Or.process_set) accumulates the
matches into a Python `set` of resource ids and rebuilds the list from it,
so for any policy using `or:` the output order changes between processes
under string hash randomisation. Every assertion below therefore compares
the SORTED list of ids -- still an assertion about *which* domains matched,
just not a flaky one about their order.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/opensearch.yml'


def matched(policy, resources):
    return sorted(r['DomainName'] for r in run_policy(POLICIES, policy, resources))


def test_opensearch_encryption_at_rest_disabled():
    resources = [
        {'DomainName': 'matches', 'EncryptionAtRestOptions': {'Enabled': False}},
        {'DomainName': 'clean', 'EncryptionAtRestOptions': {'Enabled': True}},
        # the `or: absent` branch catches the domain the key never came back for
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-encryption-at-rest-disabled', resources) == [
        'key-absent', 'matches']


def test_opensearch_node_to_node_encryption_disabled():
    resources = [
        {'DomainName': 'matches', 'NodeToNodeEncryptionOptions': {'Enabled': False}},
        {'DomainName': 'clean', 'NodeToNodeEncryptionOptions': {'Enabled': True}},
        # caught by the `or: absent` branch
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-node-to-node-encryption-disabled', resources) == [
        'key-absent', 'matches']


def test_opensearch_error_logging_disabled():
    resources = [
        {'DomainName': 'matches',
         'LogPublishingOptions': {'ES_APPLICATION_LOGS': {'Enabled': False}}},
        {'DomainName': 'clean',
         'LogPublishingOptions': {'ES_APPLICATION_LOGS': {
             'Enabled': True,
             'CloudWatchLogsLogGroupArn':
                 'arn:aws:logs:us-east-1:111111111111:log-group:/aws/es/app:*'}}},
        # LogPublishingOptions is absent entirely on a domain that never
        # configured log publishing -- the common case, caught by `or: absent`
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-error-logging-disabled', resources) == [
        'key-absent', 'matches']


def test_opensearch_audit_logging_disabled():
    resources = [
        {'DomainName': 'matches',
         'LogPublishingOptions': {'AUDIT_LOGS': {'Enabled': False}}},
        {'DomainName': 'clean',
         'LogPublishingOptions': {'AUDIT_LOGS': {
             'Enabled': True,
             'CloudWatchLogsLogGroupArn':
                 'arn:aws:logs:us-east-1:111111111111:log-group:/aws/es/audit:*'}}},
        # caught by the `or: absent` branch
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-audit-logging-disabled', resources) == [
        'key-absent', 'matches']


def test_opensearch_insufficient_data_nodes():
    resources = [
        {'DomainName': 'too-few-nodes',
         'ElasticsearchClusterConfig': {'InstanceCount': 2, 'ZoneAwarenessEnabled': True}},
        {'DomainName': 'no-zone-awareness',
         'ElasticsearchClusterConfig': {'InstanceCount': 3, 'ZoneAwarenessEnabled': False}},
        {'DomainName': 'clean',
         'ElasticsearchClusterConfig': {'InstanceCount': 3, 'ZoneAwarenessEnabled': True}},
        # ZoneAwarenessEnabled is only written once configured; `or: absent` catches it
        {'DomainName': 'key-absent', 'ElasticsearchClusterConfig': {'InstanceCount': 3}},
    ]
    assert matched('opensearch-insufficient-data-nodes', resources) == [
        'key-absent', 'no-zone-awareness', 'too-few-nodes']


def test_opensearch_insufficient_dedicated_master_nodes():
    resources = [
        {'DomainName': 'masters-disabled',
         'ElasticsearchClusterConfig': {'DedicatedMasterEnabled': False}},
        {'DomainName': 'too-few-masters',
         'ElasticsearchClusterConfig': {'DedicatedMasterEnabled': True,
                                        'DedicatedMasterCount': 1}},
        {'DomainName': 'clean',
         'ElasticsearchClusterConfig': {'DedicatedMasterEnabled': True,
                                        'DedicatedMasterCount': 3}},
        # DedicatedMasterEnabled absent -> caught by the `or: absent` branch
        {'DomainName': 'key-absent', 'ElasticsearchClusterConfig': {}},
    ]
    assert matched('opensearch-insufficient-dedicated-master-nodes', resources) == [
        'key-absent', 'masters-disabled', 'too-few-masters']


def test_opensearch_outdated_tls_policy():
    resources = [
        {'DomainName': 'old-tls',
         'DomainEndpointOptions': {'TLSSecurityPolicy': 'Policy-Min-TLS-1-0-2019-07',
                                   'EnforceHTTPS': True}},
        {'DomainName': 'no-https',
         'DomainEndpointOptions': {
             'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-PFS-2023-10',
             'EnforceHTTPS': False}},
        {'DomainName': 'clean',
         'DomainEndpointOptions': {
             'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-PFS-2023-10',
             'EnforceHTTPS': True}},
        # `op: ne` on an absent key matches: None != the policy string. The
        # domain is reported, which here is the safe direction (the policy's
        # own description notes it relies on the field always being present).
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-outdated-tls-policy', resources) == [
        'key-absent', 'no-https', 'old-tls']


def test_opensearch_fine_grained_access_control_disabled():
    resources = [
        {'DomainName': 'matches', 'AdvancedSecurityOptions': {'Enabled': False}},
        {'DomainName': 'clean', 'AdvancedSecurityOptions': {'Enabled': True}},
        # absent on a domain that never enabled FGAC -- caught by `or: absent`
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-fine-grained-access-control-disabled', resources) == [
        'key-absent', 'matches']


def test_opensearch_software_update_available():
    resources = [
        {'DomainName': 'matches', 'ServiceSoftwareOptions': {'UpdateAvailable': True}},
        {'DomainName': 'clean', 'ServiceSoftwareOptions': {'UpdateAvailable': False}},
        # KNOWN LIMITATION: single `value: true` with no `absent` branch, so a
        # domain whose ServiceSoftwareOptions never came back reads as compliant.
        # Benign here -- the miss direction is "no pending update reported".
        {'DomainName': 'key-absent'},
    ]
    assert matched('opensearch-software-update-available', resources) == ['matches']


def test_detect_public_opensearch():
    resources = [
        # no VPCOptions -> public endpoint; `value: absent` IS the match condition
        {'DomainName': 'matches'},
        {'DomainName': 'clean',
         'VPCOptions': {'VPCId': 'vpc-0abc1234', 'SubnetIds': ['subnet-0abc1234'],
                        'SecurityGroupIds': ['sg-0abc1234'],
                        'AvailabilityZones': ['us-east-1a']}},
    ]
    assert matched('detect-public-opensearch', resources) == ['matches']
