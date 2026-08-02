"""Behavioural tests for policies/aws/efs.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/efs.yml'


def test_efs_without_encryption_at_rest():
    resources = [
        {'FileSystemId': 'matches', 'Name': 'a', 'LifeCycleState': 'available',
         'Encrypted': False},
        {'FileSystemId': 'clean', 'Name': 'b', 'LifeCycleState': 'available',
         'Encrypted': True,
         'KmsKeyId': 'arn:aws:kms:us-east-1:000000000000:key/1234'},
        # the `absent` branch is present, so a file system whose Encrypted flag
        # never came back IS caught rather than read as encrypted.
        {'FileSystemId': 'key-absent', 'Name': 'c', 'LifeCycleState': 'available'},
    ]
    matched = [r['FileSystemId'] for r in run_policy(
        POLICIES, 'efs-without-encryption-at-rest', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']
