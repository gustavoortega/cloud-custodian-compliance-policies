"""Behavioural tests for policies/aws/msk.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/msk.yml'
ARN = 'arn:aws:kafka:us-east-1:000000000000:cluster/%s/1234-5678-9'


def test_msk_cluster_client_broker_plaintext():
    resources = [
        {'ClusterArn': ARN % 'matches', 'ClusterName': 'matches', 'State': 'ACTIVE',
         'ClusterType': 'PROVISIONED',
         'EncryptionInfo': {'EncryptionInTransit': {
             'ClientBroker': 'TLS_PLAINTEXT', 'InCluster': True}}},
        {'ClusterArn': ARN % 'clean', 'ClusterName': 'clean', 'State': 'ACTIVE',
         'ClusterType': 'PROVISIONED',
         'EncryptionInfo': {'EncryptionInTransit': {
             'ClientBroker': 'TLS', 'InCluster': True}}},
        # covered by the second branch: `op: in` turns an absent key into ()
        # before comparing and () is not in the list, so this provisioned
        # cluster used to score as encrypted without anything being read.
        {'ClusterArn': ARN % 'key-absent', 'ClusterName': 'key-absent',
         'State': 'ACTIVE', 'ClusterType': 'PROVISIONED'},
        # NOT reported, and this is why the branch is scoped: c7n enumerates
        # with list_clusters_v2 and flattens the `Provisioned` sub-document to
        # the top level, so a SERVERLESS cluster has no EncryptionInfo key at
        # all. Serverless MSK has no plaintext option -- TLS is mandatory and
        # not configurable -- so an unscoped absent branch would report the
        # whole serverless fleet.
        {'ClusterArn': ARN % 'clean-serverless', 'ClusterName': 'clean-serverless',
         'State': 'ACTIVE', 'ClusterType': 'SERVERLESS',
         'Serverless': {'VpcConfigs': [{'SubnetIds': ['subnet-1']}]}},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['ClusterName'] for r in run_policy(
        POLICIES, 'msk-cluster-client-broker-plaintext', resources))
    assert matched == ['key-absent', 'matches']


def test_msk_cluster_unauthenticated_access_enabled():
    resources = [
        {'ClusterArn': ARN % 'matches', 'ClusterName': 'matches', 'State': 'ACTIVE',
         'ClientAuthentication': {'Unauthenticated': {'Enabled': True}}},
        {'ClusterArn': ARN % 'clean', 'ClusterName': 'clean', 'State': 'ACTIVE',
         'ClientAuthentication': {'Unauthenticated': {'Enabled': False},
                                  'Sasl': {'Iam': {'Enabled': True}}}},
        # positive match on `true`: an absent block reads as compliant, which is
        # the right direction (no Unauthenticated block means it is off).
        {'ClusterArn': ARN % 'key-absent', 'ClusterName': 'key-absent',
         'State': 'ACTIVE'},
    ]
    matched = [r['ClusterName'] for r in run_policy(
        POLICIES, 'msk-cluster-unauthenticated-access-enabled', resources)]
    assert matched == ['matches']


def test_msk_cluster_public_access_enabled():
    resources = [
        {'ClusterArn': ARN % 'matches', 'ClusterName': 'matches', 'State': 'ACTIVE',
         'BrokerNodeGroupInfo': {'ConnectivityInfo': {
             'PublicAccess': {'Type': 'SERVICE_PROVIDED_EIPS'}}}},
        {'ClusterArn': ARN % 'clean', 'ClusterName': 'clean', 'State': 'ACTIVE',
         'BrokerNodeGroupInfo': {'ConnectivityInfo': {
             'PublicAccess': {'Type': 'DISABLED'}}}},
        # positive match on the literal value: an absent ConnectivityInfo reads
        # as compliant, which is correct (public access is off by default).
        {'ClusterArn': ARN % 'key-absent', 'ClusterName': 'key-absent',
         'State': 'ACTIVE', 'BrokerNodeGroupInfo': {}},
    ]
    matched = [r['ClusterName'] for r in run_policy(
        POLICIES, 'msk-cluster-public-access-enabled', resources)]
    assert matched == ['matches']
