"""Behavioural tests for policies/aws/secretsmanager.yml.

Offline: no AWS credentials, no network.

`secretsmanager-secret-cross-account` is not here: c7n's cross-account
filter on this resource calls GetResourcePolicy per secret.

Dates are computed relative to now instead of hardcoded so the
`value_type: age` thresholds keep meaning the same thing next year.
"""
from datetime import datetime, timedelta, timezone

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/secretsmanager.yml'


def _days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def test_secretsmanager_rotation_disabled():
    resources = [
        {'Name': 'matches', 'ARN': 'arn:aws:secretsmanager:us-east-1:0:secret:matches',
         'RotationEnabled': False},
        {'Name': 'clean', 'ARN': 'arn:aws:secretsmanager:us-east-1:0:secret:clean',
         'RotationEnabled': True, 'LastRotatedDate': _days_ago(5)},
        # ListSecrets omits RotationEnabled entirely on a secret that never had
        # rotation configured; the `absent` branch is present, so it IS caught.
        {'Name': 'key-absent',
         'ARN': 'arn:aws:secretsmanager:us-east-1:0:secret:key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'secretsmanager-rotation-disabled', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']


def test_secretsmanager_rotation_overdue():
    resources = [
        {'Name': 'matches', 'RotationEnabled': True,
         'LastRotatedDate': _days_ago(200)},
        # rotation on but never actually rotated: the `absent` branch
        {'Name': 'matches-never-rotated', 'RotationEnabled': True},
        {'Name': 'clean', 'RotationEnabled': True,
         'LastRotatedDate': _days_ago(5)},
        # rotation off is out of scope for this policy (covered by
        # secretsmanager-rotation-disabled)
        {'Name': 'rotation-off', 'RotationEnabled': False},
        # RotationEnabled absent: the leading `value: true` reads it as
        # compliant, so the secret never reaches the age check here.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'secretsmanager-rotation-overdue', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches', 'matches-never-rotated']


def test_secretsmanager_unused_and_stale():
    resources = [
        {'Name': 'matches-never-accessed', 'CreatedDate': _days_ago(400)},
        {'Name': 'matches-stale-access', 'CreatedDate': _days_ago(400),
         'LastAccessedDate': _days_ago(300)},
        {'Name': 'clean-recent-access', 'CreatedDate': _days_ago(400),
         'LastAccessedDate': _days_ago(3)},
        {'Name': 'clean-young', 'CreatedDate': _days_ago(10)},
        # KNOWN LIMITATION: with `value_type: age` an absent CreatedDate parses
        # to 0, the comparison against a datetime raises TypeError and c7n
        # swallows it as "no match", so the secret reads as compliant.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'secretsmanager-unused-and-stale', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches-never-accessed', 'matches-stale-access']


def test_secretsmanager_not_rotated_recently():
    resources = [
        {'Name': 'matches', 'RotationEnabled': True,
         'LastRotatedDate': _days_ago(200)},
        {'Name': 'clean', 'RotationEnabled': True,
         'LastRotatedDate': _days_ago(5)},
        # no LastRotatedDate at all: the `absent` branch catches it, so every
        # secret that was never rotated shows up here regardless of
        # RotationEnabled -- this policy does not gate on that flag.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'secretsmanager-not-rotated-recently', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']
