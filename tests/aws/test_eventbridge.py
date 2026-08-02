"""Behavioural tests for policies/aws/eventbridge.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/eventbridge.yml'


def test_eventbridge_custom_bus_without_resource_policy():
    resources = [
        # DescribeEventBus omits Policy entirely when no resource policy is set
        {'Name': 'matches',
         'Arn': 'arn:aws:events:us-east-1:000000000000:event-bus/matches'},
        {'Name': 'clean',
         'Arn': 'arn:aws:events:us-east-1:000000000000:event-bus/clean',
         'Policy': '{"Version":"2012-10-17","Statement":[]}'},
        # the account's default bus is excluded by the `not` on Name
        {'Name': 'default',
         'Arn': 'arn:aws:events:us-east-1:000000000000:event-bus/default'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'eventbridge-custom-bus-without-resource-policy', resources)]
    # the leading `not` merges through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches']
