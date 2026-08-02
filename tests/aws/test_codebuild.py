"""Behavioural tests for policies/aws/codebuild.yml.

Offline: no AWS credentials, no network.

Resource shape follows codebuild:BatchGetProjects, which is lowerCamelCase
(`name`, `environment.privilegedMode`, `logsConfig.s3Logs.status`).
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/codebuild.yml'


def test_codebuild_privileged_mode_enabled():
    resources = [
        {'name': 'matches',
         'environment': {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0',
                         'computeType': 'BUILD_GENERAL1_SMALL', 'privilegedMode': True}},
        {'name': 'clean',
         'environment': {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0',
                         'computeType': 'BUILD_GENERAL1_SMALL', 'privilegedMode': False}},
        # privilegedMode absent from the environment block: `value: true`
        # against None does not match. Absence is the safe direction here.
        {'name': 'key-absent',
         'environment': {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0',
                         'computeType': 'BUILD_GENERAL1_SMALL'}},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'codebuild-privileged-mode-enabled', resources)]
    assert matched == ['matches']


def test_codebuild_plaintext_secret_env_vars():
    resources = [
        {'name': 'matches',
         'environment': {'environmentVariables': [
             {'name': 'DB_PASSWORD', 'value': 'hunter2', 'type': 'PLAINTEXT'}]}},
        # same variable name, but resolved from Secrets Manager
        {'name': 'clean-secret-ref',
         'environment': {'environmentVariables': [
             {'name': 'DB_PASSWORD', 'value': 'prod/db', 'type': 'SECRETS_MANAGER'}]}},
        # plaintext but the name does not look like a credential
        {'name': 'clean-benign',
         'environment': {'environmentVariables': [
             {'name': 'BUILD_ENV', 'value': 'production', 'type': 'PLAINTEXT'}]}},
        # environmentVariables absent: list-item over None yields nothing,
        # so a project with no env vars is compliant, as intended.
        {'name': 'key-absent', 'environment': {'type': 'LINUX_CONTAINER'}},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'codebuild-plaintext-secret-env-vars', resources)]
    assert matched == ['matches']


def test_codebuild_source_credentials_embedded():
    resources = [
        {'name': 'matches',
         'source': {'type': 'GITHUB',
                    'location': 'https://builder:ghp_secret@github.com/org/repo.git'}},
        {'name': 'clean',
         'source': {'type': 'GITHUB', 'location': 'https://github.com/org/repo.git'}},
        # source.location absent (NO_SOURCE / CODEPIPELINE projects): the
        # regex never runs against None, so the project is compliant.
        {'name': 'key-absent', 'source': {'type': 'NO_SOURCE'}},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'codebuild-source-credentials-embedded', resources)]
    assert matched == ['matches']


def test_codebuild_project_publicly_visible():
    resources = [
        {'name': 'matches', 'projectVisibility': 'PUBLIC_READ'},
        {'name': 'clean', 'projectVisibility': 'PRIVATE'},
        # projectVisibility absent: equality against None does not match.
        {'name': 'key-absent'},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'codebuild-project-publicly-visible', resources)]
    assert matched == ['matches']


def test_codebuild_s3_logs_not_encrypted():
    resources = [
        {'name': 'matches',
         'logsConfig': {'s3Logs': {'status': 'ENABLED', 'location': 'bucket/prefix',
                                   'encryptionDisabled': True}}},
        {'name': 'clean-encrypted',
         'logsConfig': {'s3Logs': {'status': 'ENABLED', 'location': 'bucket/prefix',
                                   'encryptionDisabled': False}}},
        {'name': 'clean-s3-off',
         'logsConfig': {'s3Logs': {'status': 'DISABLED'}}},
        # logsConfig absent entirely. The policy gates on
        # s3Logs.status == ENABLED first, so this reads as compliant --
        # deliberate, per the policy's own description (absence means
        # "never configured", so there is nothing to encrypt).
        {'name': 'key-absent'},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'codebuild-s3-logs-not-encrypted', resources)]
    assert matched == ['matches']
