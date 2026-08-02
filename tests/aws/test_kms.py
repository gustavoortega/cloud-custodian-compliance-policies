"""Behavioural tests for policies/aws/kms.yml.

Offline: no AWS credentials, no network.

Only `kms-key-scheduled-for-deletion` runs offline. The other four
policies in the file need an AWS session (`key-rotation-status`,
`cross-account`, and the custom `cross-account-tolerant` / `unauditable`
filters, which all call `kms:GetKeyPolicy` or
`kms:GetKeyRotationStatus`).
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/kms.yml'


def test_kms_key_scheduled_for_deletion():
    resources = [
        {'KeyId': 'matches', 'KeyManager': 'CUSTOMER', 'KeyState': 'PendingDeletion',
         'Arn': 'arn:aws:kms:us-east-1:000000000000:key/matches'},
        {'KeyId': 'clean', 'KeyManager': 'CUSTOMER', 'KeyState': 'Enabled',
         'Arn': 'arn:aws:kms:us-east-1:000000000000:key/clean'},
        # DescribeKey always returns KeyState; the positive match on the
        # literal 'PendingDeletion' reads an absence as compliant.
        {'KeyId': 'key-absent',
         'Arn': 'arn:aws:kms:us-east-1:000000000000:key/key-absent'},
    ]
    matched = [r['KeyId'] for r in run_policy(
        POLICIES, 'kms-key-scheduled-for-deletion', resources)]
    assert matched == ['matches']
