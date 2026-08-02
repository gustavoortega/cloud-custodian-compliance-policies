"""Behavioural tests for policies/aws/datafirehose.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/datafirehose.yml'


def test_firehose_delivery_stream_not_encrypted():
    resources = [
        {'DeliveryStreamName': 'matches', 'DeliveryStreamStatus': 'ACTIVE',
         'DeliveryStreamEncryptionConfiguration': {'Status': 'DISABLED'}},
        {'DeliveryStreamName': 'clean', 'DeliveryStreamStatus': 'ACTIVE',
         'DeliveryStreamEncryptionConfiguration': {
             'Status': 'ENABLED', 'KeyType': 'AWS_OWNED_CMK'}},
        # DescribeDeliveryStream omits the whole block when SSE was never
        # enabled. `op: ne` on an absent key resolves None != 'ENABLED' -> True,
        # so this one IS caught -- the correct direction here.
        {'DeliveryStreamName': 'key-absent', 'DeliveryStreamStatus': 'ACTIVE'},
    ]
    matched = [r['DeliveryStreamName'] for r in run_policy(
        POLICIES, 'firehose-delivery-stream-not-encrypted', resources)]
    assert matched == ['matches', 'key-absent']
