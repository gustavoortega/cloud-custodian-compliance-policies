"""Behavioural tests for policies/aws/cloudformation.yml.

Offline: no AWS credentials, no network.

`ParentId` only comes back on nested stacks, so `ParentId: absent` is the
way both policies restrict themselves to root stacks.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/cloudformation.yml'


def test_cloudformation_stack_termination_protection_disabled():
    resources = [
        {'StackName': 'matches', 'StackStatus': 'CREATE_COMPLETE',
         'EnableTerminationProtection': False},
        {'StackName': 'clean', 'StackStatus': 'CREATE_COMPLETE',
         'EnableTerminationProtection': True},
        {'StackName': 'nested', 'StackStatus': 'CREATE_COMPLETE',
         'ParentId': 'arn:aws:cloudformation:us-east-1:000000000000:stack/root/abc',
         'EnableTerminationProtection': False},
        # KNOWN LIMITATION: `value: false` with no `absent` branch. DescribeStacks
        # omits EnableTerminationProtection on stacks that never had it set, and
        # such a stack is reported as compliant.
        {'StackName': 'key-absent', 'StackStatus': 'CREATE_COMPLETE'},
    ]
    matched = [r['StackName'] for r in run_policy(
        POLICIES, 'cloudformation-stack-termination-protection-disabled', resources)]
    assert matched == ['matches']


def test_cloudformation_stack_without_service_role():
    resources = [
        # no RoleARN at all: the stack deploys with the caller's own permissions
        {'StackName': 'matches', 'StackStatus': 'CREATE_COMPLETE'},
        {'StackName': 'clean', 'StackStatus': 'CREATE_COMPLETE',
         'RoleARN': 'arn:aws:iam::000000000000:role/cfn-exec'},
        {'StackName': 'nested', 'StackStatus': 'CREATE_COMPLETE',
         'ParentId': 'arn:aws:cloudformation:us-east-1:000000000000:stack/root/abc'},
    ]
    matched = [r['StackName'] for r in run_policy(
        POLICIES, 'cloudformation-stack-without-service-role', resources)]
    assert matched == ['matches']
