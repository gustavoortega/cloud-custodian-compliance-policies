"""Behavioural tests for policies/aws/backup.yml.

Offline: no AWS credentials, no network.

`aws.backup-recovery-point` and its `unencrypted` filter are custom, they
live in the c7n_pack extension package rather than in c7n itself, so the
package has to be importable before the policy can even be built.
"""


from c7n_kit.testing import run_policy  # noqa: E402

POLICIES = 'policies/aws/backup.yml'


def test_backup_recovery_point_unencrypted():
    resources = [
        {'RecoveryPointArn': 'matches', 'BackupVaultName': 'v',
         'ResourceType': 'EBS', 'IsEncrypted': False},
        {'RecoveryPointArn': 'clean', 'BackupVaultName': 'v',
         'ResourceType': 'EBS', 'IsEncrypted': True},
        # BY DESIGN: an absent IsEncrypted is neither a finding nor a clean
        # result. The filter annotates c7n:BackupEncryptionUnknown and leaves
        # the recovery point out of the match.
        {'RecoveryPointArn': 'key-absent', 'BackupVaultName': 'v',
         'ResourceType': 'EBS'},
    ]
    matched = [r['RecoveryPointArn'] for r in run_policy(
        POLICIES, 'backup-recovery-point-unencrypted', resources)]
    assert matched == ['matches']
