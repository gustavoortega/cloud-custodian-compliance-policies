"""Behavioural tests for policies/aws/waf.yml.

Offline: no AWS credentials, no network.

The two `web-acl-rules` policies are not here: that filter fetches the
full WebACL with GetWebACL before it can look at the rules.

The regional/CloudFront split is done with `query: Scope:` and
`conditions: region`, both of which act on enumeration rather than on
the filter chain, so the two variants of each control are identical
offline and only the REGIONAL one is exercised for the pair.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/waf.yml'


def test_waf_classic_regional_webacl_empty():
    resources = [
        {'WebACLId': 'matches', 'Name': 'matches',
         'DefaultAction': {'Type': 'ALLOW'}, 'Rules': []},
        {'WebACLId': 'clean', 'Name': 'clean',
         'DefaultAction': {'Type': 'ALLOW'},
         'Rules': [{'Priority': 1, 'RuleId': 'r1', 'Action': {'Type': 'BLOCK'}}]},
        # `value: empty` is c7n's `not r`, and an absent key resolves to None,
        # which is also falsy -- so a WebACL whose Rules never came back IS
        # caught rather than read as protected.
        {'WebACLId': 'key-absent', 'Name': 'key-absent',
         'DefaultAction': {'Type': 'ALLOW'}},
    ]
    matched = [r['WebACLId'] for r in run_policy(
        POLICIES, 'waf-classic-regional-webacl-empty', resources)]
    assert matched == ['matches', 'key-absent']


def test_waf_classic_global_webacl_empty():
    resources = [
        {'WebACLId': 'matches', 'Name': 'matches',
         'DefaultAction': {'Type': 'ALLOW'}, 'Rules': []},
        {'WebACLId': 'clean', 'Name': 'clean',
         'DefaultAction': {'Type': 'ALLOW'},
         'Rules': [{'Priority': 1, 'RuleId': 'r1', 'Action': {'Type': 'BLOCK'}}]},
        {'WebACLId': 'key-absent', 'Name': 'key-absent',
         'DefaultAction': {'Type': 'ALLOW'}},
    ]
    matched = [r['WebACLId'] for r in run_policy(
        POLICIES, 'waf-classic-global-webacl-empty', resources)]
    assert matched == ['matches', 'key-absent']


def test_wafv2_webacl_empty_regional():
    resources = [
        {'Id': 'matches', 'Name': 'matches',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:regional/webacl/matches/1',
         'DefaultAction': {'Allow': {}}, 'Rules': []},
        {'Id': 'clean', 'Name': 'clean',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:regional/webacl/clean/1',
         'DefaultAction': {'Allow': {}},
         'Rules': [{'Name': 'r1', 'Priority': 1, 'Action': {'Block': {}}}]},
        # ListWebACLs alone does not return Rules; a WebACL that was never
        # enriched with GetWebACL has no Rules key and `value: empty` catches
        # it, which is the safe direction but also means an incomplete
        # enumeration reads as a finding.
        {'Id': 'key-absent', 'Name': 'key-absent',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:regional/webacl/absent/1',
         'DefaultAction': {'Allow': {}}},
    ]
    matched = [r['Id'] for r in run_policy(
        POLICIES, 'wafv2-webacl-empty-regional', resources)]
    assert matched == ['matches', 'key-absent']


def test_wafv2_webacl_empty_cloudfront():
    resources = [
        {'Id': 'matches', 'Name': 'matches',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:global/webacl/matches/1',
         'DefaultAction': {'Allow': {}}, 'Rules': []},
        {'Id': 'clean', 'Name': 'clean',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:global/webacl/clean/1',
         'DefaultAction': {'Allow': {}},
         'Rules': [{'Name': 'r1', 'Priority': 1, 'Action': {'Block': {}}}]},
        {'Id': 'key-absent', 'Name': 'key-absent',
         'ARN': 'arn:aws:wafv2:us-east-1:000000000000:global/webacl/absent/1',
         'DefaultAction': {'Allow': {}}},
    ]
    matched = [r['Id'] for r in run_policy(
        POLICIES, 'wafv2-webacl-empty-cloudfront', resources)]
    assert matched == ['matches', 'key-absent']
