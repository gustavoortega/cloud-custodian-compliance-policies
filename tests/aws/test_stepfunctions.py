"""Behavioural tests for policies/aws/stepfunctions.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/stepfunctions.yml'
ARN = 'arn:aws:states:us-east-1:000000000000:stateMachine:%s'


def test_stepfunctions_state_machine_logging_disabled():
    resources = [
        {'stateMachineArn': ARN % 'matches', 'name': 'matches', 'status': 'ACTIVE',
         'loggingConfiguration': {'level': 'OFF', 'includeExecutionData': False}},
        {'stateMachineArn': ARN % 'clean', 'name': 'clean', 'status': 'ACTIVE',
         'loggingConfiguration': {'level': 'ALL', 'includeExecutionData': True,
                                  'destinations': [{'cloudWatchLogsLogGroup': {
                                      'logGroupArn': 'arn:aws:logs:us-east-1:0:'
                                                     'log-group:/aws/vendedlogs:*'}}]}},
        {'stateMachineArn': ARN % 'deleting', 'name': 'deleting', 'status': 'DELETING',
         'loggingConfiguration': {'level': 'OFF'}},
        # EXPRESS workflows created before logging existed come back with no
        # loggingConfiguration at all; the `absent` branch catches them.
        {'stateMachineArn': ARN % 'key-absent', 'name': 'key-absent',
         'status': 'ACTIVE'},
    ]
    matched = [r['name'] for r in run_policy(
        POLICIES, 'stepfunctions-state-machine-logging-disabled', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']
