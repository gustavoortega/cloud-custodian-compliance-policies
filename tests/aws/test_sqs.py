"""Behavioural tests for policies/aws/sqs.yml.

Offline: no AWS credentials, no network.

GetQueueAttributes returns every attribute as a STRING, which is why
`SqsManagedSseEnabled` is compared against the string 'false' and not
the boolean. c7n merges those attributes straight into the resource
dict, so both policies here run offline.
"""
import json

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/sqs.yml'
URL = 'https://sqs.us-east-1.amazonaws.com/000000000000/%s'


def _policy(queue, principal):
    return json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 's', 'Effect': 'Allow',
        'Principal': {'AWS': principal},
        'Action': 'SQS:SendMessage',
        'Resource': 'arn:aws:sqs:us-east-1:000000000000:%s' % queue}]})


def test_sqs_queue_external_access():
    resources = [
        {'QueueUrl': URL % 'matches',
         'Policy': _policy('matches', 'arn:aws:iam::999999999999:root')},
        {'QueueUrl': URL % 'clean-own',
         'Policy': _policy('clean-own', 'arn:aws:iam::000000000000:root')},
        {'QueueUrl': URL % 'clean-whitelisted',
         'Policy': _policy('clean-whitelisted', 'arn:aws:iam::111111111111:root')},
        # NOT a limitation, and left as is on purpose: `Policy` comes back
        # from GetQueueAttributes only when a resource policy exists, so a
        # queue without one is reachable through IAM in the owning account
        # only -- the secure default, and a true negative. The "we could not
        # read it" case never lands here either: c7n's DescribeQueue.augment
        # DROPS a queue whose GetQueueAttributes returned AccessDenied rather
        # than yielding it with the attribute missing.
        {'QueueUrl': URL % 'clean-no-policy'},
    ]
    matched = [r['QueueUrl'] for r in run_policy(
        POLICIES, 'sqs-queue-external-access', resources)]
    assert matched == [URL % 'matches']


def test_sqs_queue_not_encrypted_at_rest():
    resources = [
        {'QueueUrl': URL % 'matches', 'SqsManagedSseEnabled': 'false'},
        {'QueueUrl': URL % 'clean-sse-sqs', 'SqsManagedSseEnabled': 'true'},
        {'QueueUrl': URL % 'clean-kms', 'SqsManagedSseEnabled': 'false',
         'KmsMasterKeyId': 'alias/aws/sqs'},
        # covered: a queue returning neither KmsMasterKeyId nor
        # SqsManagedSseEnabled has no encryption at all and no attribute to
        # prove otherwise. It used to be the least encrypted queue in the
        # account and the one this control called clean.
        {'QueueUrl': URL % 'key-absent'},
        # a KMS key with the SSE attribute missing is still encrypted: the
        # first filter clears it, so widening the second did not widen the
        # control.
        {'QueueUrl': URL % 'clean-kms-no-sse-key',
         'KmsMasterKeyId': 'alias/aws/sqs'},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['QueueUrl'] for r in run_policy(
        POLICIES, 'sqs-queue-not-encrypted-at-rest', resources))
    assert matched == [URL % 'key-absent', URL % 'matches']
