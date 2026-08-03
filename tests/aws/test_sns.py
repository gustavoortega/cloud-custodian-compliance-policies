"""Behavioural tests for policies/aws/sns.yml.

Offline: no AWS credentials, no network.

`Policy` is one of the attributes GetTopicAttributes returns, as a JSON
string, and c7n's cross-account filter reads it straight off the
resource dict. The tests run with the kit's default `account_id` of
000000000000.
"""
import json

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/sns.yml'
ARN = 'arn:aws:sns:us-east-1:000000000000:%s'


def _policy(topic, principal):
    return json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 's', 'Effect': 'Allow',
        'Principal': {'AWS': principal},
        'Action': 'SNS:Publish', 'Resource': ARN % topic}]})


def test_sns_topic_external_access():
    resources = [
        {'TopicArn': ARN % 'matches', 'DisplayName': 'matches',
         'Policy': _policy('matches', 'arn:aws:iam::999999999999:root')},
        {'TopicArn': ARN % 'clean-own', 'DisplayName': 'clean-own',
         'Policy': _policy('clean-own', 'arn:aws:iam::000000000000:root')},
        {'TopicArn': ARN % 'clean-whitelisted', 'DisplayName': 'clean-whitelisted',
         'Policy': _policy('clean-whitelisted', 'arn:aws:iam::111111111111:root')},
        # covered by the second branch of the `or`. CrossAccountAccessFilter
        # returns False outright when the policy attribute is missing, and
        # here that cannot mean "nothing is shared": SNS gives every topic a
        # default access policy at creation and GetTopicAttributes always
        # returns `Policy`. Absent means the attribute set was never
        # assembled -- unverified, not clean. The SQS twin has no such branch
        # on purpose: there the attribute is optional by design.
        {'TopicArn': ARN % 'key-absent', 'DisplayName': 'key-absent'},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['TopicArn'] for r in run_policy(
        POLICIES, 'sns-topic-external-access', resources))
    assert matched == [ARN % 'key-absent', ARN % 'matches']
