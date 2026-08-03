"""Behavioural tests for policies/aws/eks.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/eks.yml'


def test_eks_cluster_unsupported_kubernetes_version():
    resources = [
        {'name': 'matches', 'version': '1.29', 'status': 'ACTIVE'},
        {'name': 'clean', 'version': '1.33', 'status': 'ACTIVE'},
        {'name': 'clean-newer', 'version': '1.34', 'status': 'ACTIVE'},
        # `version` absent: the `not-null` guard drops the cluster before
        # ComparableVersion(None) can raise AttributeError and abort the whole
        # account/region run. Not reported -- its version is unknown, not old.
        {'name': 'key-absent', 'status': 'ACTIVE'},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'eks-cluster-unsupported-kubernetes-version', resources)]
    assert matched == ['matches']

    # and on its own it is a non-match, not an exception
    assert run_policy(POLICIES, 'eks-cluster-unsupported-kubernetes-version',
                      [{'name': 'key-absent', 'status': 'ACTIVE'}]) == []


def test_eks_cluster_secrets_not_encrypted():
    resources = [
        # encryptionConfig covers a resource other than secrets
        {'name': 'matches-other-resource',
         'encryptionConfig': [{'resources': ['configmaps'],
                               'provider': {'keyArn': 'arn:aws:kms:::key/abc'}}]},
        {'name': 'matches-empty-config', 'encryptionConfig': []},
        # encryptionConfig absent: correctly captured, because the filter is
        # a `not` around a positive assertion instead of a `value: false`.
        {'name': 'key-absent'},
        {'name': 'clean',
         'encryptionConfig': [{'resources': ['secrets'],
                               'provider': {'keyArn': 'arn:aws:kms:::key/abc'}}]},
    ]
    # c7n's `not` resolves via set difference (Not.process_set), so the
    # returned order is set-iteration order, not input order.
    matched = sorted(r['name'] for r in run_policy(
        POLICIES, 'eks-cluster-secrets-not-encrypted', resources))
    assert matched == ['key-absent', 'matches-empty-config', 'matches-other-resource']


def test_eks_cluster_audit_logging_disabled():
    resources = [
        {'name': 'matches-audit-off',
         'logging': {'clusterLogging': [{'types': ['audit'], 'enabled': False}]}},
        {'name': 'matches-other-type-only',
         'logging': {'clusterLogging': [{'types': ['api'], 'enabled': True}]}},
        # logging absent: correctly captured, the `not` wrapper means an
        # absent key fails the positive assertion and therefore matches.
        {'name': 'key-absent'},
        {'name': 'clean',
         'logging': {'clusterLogging': [{'types': ['audit', 'api'], 'enabled': True}]}},
    ]
    # `not` returns a set difference; sort before asserting.
    matched = sorted(r['name'] for r in run_policy(
        POLICIES, 'eks-cluster-audit-logging-disabled', resources))
    assert matched == ['key-absent', 'matches-audit-off', 'matches-other-type-only']


def test_eks_nodegroup_unsupported_kubernetes_version():
    resources = [
        {'nodegroupName': 'matches', 'clusterName': 'c1', 'version': '1.30'},
        {'nodegroupName': 'clean', 'clusterName': 'c1', 'version': '1.33'},
        # same `not-null` guard as the cluster-level control: skipped, not fatal
        {'nodegroupName': 'key-absent', 'clusterName': 'c1'},
    ]
    matched = [r['nodegroupName'] for r in run_policy(
        POLICIES, 'eks-nodegroup-unsupported-kubernetes-version', resources)]
    assert matched == ['matches']

    assert run_policy(POLICIES, 'eks-nodegroup-unsupported-kubernetes-version',
                      [{'nodegroupName': 'key-absent', 'clusterName': 'c1'}]) == []


def test_eks_public_endpoint_open():
    resources = [
        {'name': 'matches',
         'resourcesVpcConfig': {'endpointPublicAccess': True,
                                'endpointPrivateAccess': False,
                                'publicAccessCidrs': ['0.0.0.0/0']}},
        # public but restricted to known ranges: out of scope by design
        {'name': 'clean-restricted',
         'resourcesVpcConfig': {'endpointPublicAccess': True,
                                'endpointPrivateAccess': True,
                                'publicAccessCidrs': ['203.0.113.0/24']}},
        {'name': 'clean-private',
         'resourcesVpcConfig': {'endpointPublicAccess': False,
                                'endpointPrivateAccess': True,
                                'publicAccessCidrs': []}},
        # endpointPublicAccess absent: `value: true` against None does not
        # match, so the cluster reads as compliant (safe direction here).
        {'name': 'key-absent', 'resourcesVpcConfig': {}},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'eks-public-endpoint-open', resources)]
    assert matched == ['matches']


def test_cluster_audit_logging_survives_entry_without_types():
    """A clusterLogging entry with no `types` made `contains(null, ...)` raise,
    which aborts the run for the whole account rather than skipping the
    cluster. The entry is now ignored and the cluster is still reported: it has
    no audit logging enabled, which is exactly the finding."""
    resources = [{'name': 'c1', 'logging': {'clusterLogging': [{'enabled': True}]}}]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'eks-cluster-audit-logging-disabled', resources)]
    assert matched == ['c1']
