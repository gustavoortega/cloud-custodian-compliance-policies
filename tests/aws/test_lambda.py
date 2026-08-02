"""Behavioural tests for policies/aws/lambda.yml.

Offline: no AWS credentials, no network.

Only `lambda-runtime-deprecated` runs offline: `lambda-with-public-url`
uses the `url-config` filter (GetFunctionUrlConfig) and
`lambda-invocation-errors` uses a `metrics` filter (CloudWatch).
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/lambda.yml'


def test_lambda_runtime_deprecated():
    resources = [
        {'FunctionName': 'matches',
         'FunctionArn': 'arn:aws:lambda:us-east-1:000000000000:function:matches',
         'PackageType': 'Zip', 'Runtime': 'python3.8'},
        {'FunctionName': 'clean',
         'FunctionArn': 'arn:aws:lambda:us-east-1:000000000000:function:clean',
         'PackageType': 'Zip', 'Runtime': 'python3.13'},
        # container-image functions have no Runtime at all and are excluded by
        # the PackageType filter
        {'FunctionName': 'image',
         'FunctionArn': 'arn:aws:lambda:us-east-1:000000000000:function:image',
         'PackageType': 'Image'},
        # KNOWN BEHAVIOUR: PackageType absent passes `op: ne Image` (None != str)
        # and an absent Runtime is not in the supported list either, so a
        # function missing both keys IS reported as running a dead runtime.
        {'FunctionName': 'key-absent',
         'FunctionArn': 'arn:aws:lambda:us-east-1:000000000000:function:key-absent'},
    ]
    matched = [r['FunctionName'] for r in run_policy(
        POLICIES, 'lambda-runtime-deprecated', resources)]
    # the `not` block merges through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']
