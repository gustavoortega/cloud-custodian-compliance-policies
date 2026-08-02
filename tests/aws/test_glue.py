"""Behavioural tests for policies/aws/glue.yml.

Offline: no AWS credentials, no network.
"""
import pytest

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/glue.yml'


def test_glue_data_catalog_encryption_disabled():
    resources = [
        {'CatalogId': 'matches', 'DataCatalogEncryptionSettings': {
            'EncryptionAtRest': {'CatalogEncryptionMode': 'DISABLED'}}},
        {'CatalogId': 'clean', 'DataCatalogEncryptionSettings': {
            'EncryptionAtRest': {
                'CatalogEncryptionMode': 'SSE-KMS',
                'SseAwsKmsKeyId': 'alias/aws/glue'}}},
        # KNOWN LIMITATION: positive match on the literal 'DISABLED' with no
        # `absent` branch, so a catalog whose settings never came back is read
        # as compliant.
        {'CatalogId': 'key-absent'},
    ]
    matched = [r['CatalogId'] for r in run_policy(
        POLICIES, 'glue-data-catalog-encryption-disabled', resources)]
    assert matched == ['matches']


def test_glue_data_catalog_connection_password_unencrypted():
    resources = [
        {'CatalogId': 'matches', 'DataCatalogEncryptionSettings': {
            'ConnectionPasswordEncryption': {
                'ReturnConnectionPasswordEncrypted': False}}},
        {'CatalogId': 'clean', 'DataCatalogEncryptionSettings': {
            'ConnectionPasswordEncryption': {
                'ReturnConnectionPasswordEncrypted': True,
                'AwsKmsKeyId': 'alias/aws/glue'}}},
        # the `absent` branch is present, so this IS caught.
        {'CatalogId': 'key-absent'},
    ]
    matched = [r['CatalogId'] for r in run_policy(
        POLICIES, 'glue-data-catalog-connection-password-unencrypted', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']


def test_glue_job_no_security_configuration():
    resources = [
        # GetJobs omits SecurityConfiguration when the job has none: that IS
        # the finding here, so absence is what the filter looks for.
        {'Name': 'matches', 'GlueVersion': '4.0'},
        {'Name': 'clean', 'GlueVersion': '4.0', 'SecurityConfiguration': 'sec-cfg'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'glue-job-no-security-configuration', resources)]
    assert matched == ['matches']


def test_glue_job_unsupported_version():
    resources = [
        {'Name': 'matches', 'GlueVersion': '2.0'},
        {'Name': 'clean', 'GlueVersion': '4.0'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'glue-job-unsupported-version', resources)]
    assert matched == ['matches']


def test_glue_job_unsupported_version_absent_key_raises():
    """KNOWN BUG: an absent GlueVersion crashes the policy, it does not miss it.

    The `or` runs BOTH branches over the full resource list. The `absent`
    branch would catch the job, but the `value_type: version` branch is also
    evaluated on it and `ComparableVersion(None)` blows up with
    AttributeError, taking the whole policy down for that region.
    """
    resources = [{'Name': 'key-absent'}]
    with pytest.raises(AttributeError) as exc:
        run_policy(POLICIES, 'glue-job-unsupported-version', resources)
    assert 'ComparableVersion' in str(exc.value)
