"""Behavioural tests for policies/aws/appsync.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/appsync.yml'


def test_appsync_field_level_logging_disabled():
    resources = [
        # ListGraphqlApis omits logConfig entirely when logging was never set up
        {'apiId': 'no-log-config', 'name': 'a', 'authenticationType': 'AWS_IAM'},
        {'apiId': 'level-none', 'name': 'b', 'authenticationType': 'AWS_IAM',
         'logConfig': {'fieldLogLevel': 'NONE',
                       'cloudWatchLogsRoleArn': 'arn:aws:iam::000000000000:role/appsync'}},
        # logConfig present but fieldLogLevel missing: the third branch of the `or`
        {'apiId': 'level-absent', 'name': 'c', 'authenticationType': 'AWS_IAM',
         'logConfig': {'cloudWatchLogsRoleArn': 'arn:aws:iam::000000000000:role/appsync'}},
        {'apiId': 'clean', 'name': 'd', 'authenticationType': 'AWS_IAM',
         'logConfig': {'fieldLogLevel': 'ERROR',
                       'cloudWatchLogsRoleArn': 'arn:aws:iam::000000000000:role/appsync'}},
    ]
    matched = [r['apiId'] for r in run_policy(POLICIES, 'appsync-field-level-logging-disabled', resources)]
    # c7n's `or` merges branches through a set of ids, so the order it returns
    # is not the input order; sort to keep the assertion stable.
    assert sorted(matched) == ['level-absent', 'level-none', 'no-log-config']


def test_appsync_api_key_authentication():
    resources = [
        {'apiId': 'matches', 'name': 'a', 'authenticationType': 'API_KEY'},
        {'apiId': 'clean', 'name': 'b', 'authenticationType': 'AMAZON_COGNITO_USER_POOLS'},
        # authenticationType is always returned by ListGraphqlApis; if it ever is
        # not, the positive match on API_KEY reads the absence as compliant.
        {'apiId': 'key-absent', 'name': 'c'},
    ]
    matched = [r['apiId'] for r in run_policy(POLICIES, 'appsync-api-key-authentication', resources)]
    assert matched == ['matches']
