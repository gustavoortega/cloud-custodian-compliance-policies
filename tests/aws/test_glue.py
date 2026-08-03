"""Behavioural tests for policies/aws/glue.yml.

Offline: no AWS credentials, no network.
"""
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
        # an absent GlueVersion IS the finding here (FSBP Glue.4 treats it as a
        # fail) and is still reported, through the `absent` branch. What changed
        # is that the version comparison no longer sees it: the `not-null` guard
        # AND-ed in front of it keeps ComparableVersion(None) from raising and
        # aborting the whole account/region run.
        {'Name': 'key-absent'},
    ]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    matched = sorted(r['Name'] for r in run_policy(
        POLICIES, 'glue-job-unsupported-version', resources))
    assert matched == ['key-absent', 'matches']


def test_glue_job_unsupported_version_absent_key_is_reported_not_fatal():
    """The job with no GlueVersion comes back as a finding, not an exception.

    Remove the `not-null` guard from the `and` and this raises AttributeError
    out of ComparableVersion(None): `or` runs EVERY branch over the FULL
    resource list, so the job the `absent` branch catches also reaches the
    `value_type: version` branch.
    """
    resources = [{'Name': 'key-absent'}]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'glue-job-unsupported-version', resources)]
    assert matched == ['key-absent']
