"""Behavioural tests for policies/aws/cloudtrail.yml.

Offline: no AWS credentials, no network.

Every policy here starts with `is-shadow: state: false`, which drops the
read-only replicas DescribeTrails returns in every region for a
multi-region or organisation trail. c7n decides that by comparing
`HomeRegion` against the run's region (us-east-1 in these tests) and the
account id inside `TrailARN` against the run's account, so the fixtures
carry both fields.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/cloudtrail.yml'
ARN = 'arn:aws:cloudtrail:us-east-1:000000000000:trail/%s'


def test_cloudtrail_not_encrypted_with_kms():
    resources = [
        # no KmsKeyId: DescribeTrails omits it on a trail with SSE-S3 only
        {'Name': 'matches', 'TrailARN': ARN % 'matches', 'HomeRegion': 'us-east-1'},
        {'Name': 'clean', 'TrailARN': ARN % 'clean', 'HomeRegion': 'us-east-1',
         'KmsKeyId': 'arn:aws:kms:us-east-1:000000000000:key/1234'},
        # a shadow copy of a multi-region trail homed elsewhere: excluded
        {'Name': 'shadow', 'TrailARN': ARN % 'shadow', 'HomeRegion': 'sa-east-1',
         'IsMultiRegionTrail': True},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'cloudtrail-not-encrypted-with-kms', resources)]
    assert matched == ['matches']


def test_cloudtrail_log_file_validation_disabled():
    resources = [
        {'Name': 'matches', 'TrailARN': ARN % 'matches', 'HomeRegion': 'us-east-1',
         'LogFileValidationEnabled': False},
        {'Name': 'clean', 'TrailARN': ARN % 'clean', 'HomeRegion': 'us-east-1',
         'LogFileValidationEnabled': True},
        # KNOWN LIMITATION: `value: false` with no `absent` branch, so a trail
        # whose LogFileValidationEnabled never came back reads as compliant.
        {'Name': 'key-absent', 'TrailARN': ARN % 'key-absent', 'HomeRegion': 'us-east-1'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'cloudtrail-log-file-validation-disabled', resources)]
    assert matched == ['matches']


def test_cloudtrail_not_integrated_with_cloudwatch_logs():
    resources = [
        # CloudWatchLogsLogGroupArn is simply absent when the integration is off
        {'Name': 'matches', 'TrailARN': ARN % 'matches', 'HomeRegion': 'us-east-1'},
        {'Name': 'clean', 'TrailARN': ARN % 'clean', 'HomeRegion': 'us-east-1',
         'CloudWatchLogsLogGroupArn':
             'arn:aws:logs:us-east-1:000000000000:log-group:ct:*'},
        {'Name': 'shadow', 'TrailARN': ARN % 'shadow', 'HomeRegion': 'sa-east-1',
         'IsMultiRegionTrail': True},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'cloudtrail-not-integrated-with-cloudwatch-logs', resources)]
    assert matched == ['matches']
