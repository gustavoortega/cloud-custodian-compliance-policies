"""Behavioural tests for policies/aws/ecr.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/ecr.yml'


def test_ecr_repository_scanning_disabled():
    resources = [
        {'repositoryName': 'matches',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/matches',
         'imageScanningConfiguration': {'scanOnPush': False}},
        {'repositoryName': 'clean',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/clean',
         'imageScanningConfiguration': {'scanOnPush': True}},
        # KNOWN LIMITATION: `value: false` with no `absent` branch. A repository
        # with no imageScanningConfiguration block at all is read as compliant
        # even though nothing is scanning it.
        {'repositoryName': 'key-absent',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/key-absent'},
    ]
    matched = [r['repositoryName'] for r in run_policy(
        POLICIES, 'ecr-repository-scanning-disabled', resources)]
    assert matched == ['matches']


def test_ecr_repository_tag_mutable():
    resources = [
        {'repositoryName': 'matches',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/matches',
         'imageTagMutability': 'MUTABLE'},
        {'repositoryName': 'clean',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/clean',
         'imageTagMutability': 'IMMUTABLE'},
        # `op: ne` on an absent key resolves None != 'IMMUTABLE' -> True, so a
        # repository with no imageTagMutability IS caught. Correct direction.
        {'repositoryName': 'key-absent',
         'repositoryArn': 'arn:aws:ecr:us-east-1:000000000000:repository/key-absent'},
    ]
    matched = [r['repositoryName'] for r in run_policy(
        POLICIES, 'ecr-repository-tag-mutable', resources)]
    assert matched == ['matches', 'key-absent']
