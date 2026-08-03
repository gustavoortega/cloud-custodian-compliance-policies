"""Behavioural tests for policies/aws/route53.yml.

Offline: no AWS credentials, no network.

The r53domain policies carry a policy-level `conditions:` block pinning them
to us-east-1. `run_policy` exercises the `filters:` chain only, so the
condition is not part of what these tests assert.

Expiry dates are deliberately far from any plausible run date so the
`value_type: expiration` comparisons stay stable over time.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/route53.yml'


def test_r53domain_transfer_lock_disabled():
    resources = [
        {'DomainName': 'matches.example', 'TransferLock': False, 'AutoRenew': True},
        {'DomainName': 'clean.example', 'TransferLock': True, 'AutoRenew': True},
        # covered: the policy carries the explicit `absent` branch. Without it
        # `None == False` is False and a domain AWS never described would be
        # reported as locked.
        {'DomainName': 'key-absent.example', 'AutoRenew': True},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['DomainName'] for r in run_policy(
        POLICIES, 'r53domain-transfer-lock-disabled', resources))
    assert matched == ['key-absent.example', 'matches.example']


def test_r53domain_autorenew_disabled():
    resources = [
        {'DomainName': 'matches.example', 'AutoRenew': False, 'TransferLock': True},
        {'DomainName': 'clean.example', 'AutoRenew': True, 'TransferLock': True},
        # covered: the policy carries the explicit `absent` branch, same shape
        # as the transfer-lock control.
        {'DomainName': 'key-absent.example', 'TransferLock': True},
    ]
    matched = sorted(r['DomainName'] for r in run_policy(
        POLICIES, 'r53domain-autorenew-disabled', resources))
    assert matched == ['key-absent.example', 'matches.example']


def test_r53domain_expiring_90d():
    resources = [
        {'DomainName': 'matches.example', 'Expiry': '2020-01-01T00:00:00Z'},
        {'DomainName': 'clean.example', 'Expiry': '2099-01-01T00:00:00Z'},
        # covered by the SECOND branch of the `or`, not by the comparison: an
        # absent Expiry makes `value_type: expiration` raise TypeError inside
        # c7n, which swallows it as "no match", so only a separate filter
        # reaches it.
        {'DomainName': 'key-absent.example'},
    ]
    matched = sorted(r['DomainName'] for r in run_policy(
        POLICIES, 'r53domain-expiring-90d', resources))
    assert matched == ['key-absent.example', 'matches.example']


def test_inventory_hosted_zones():
    resources = [
        {'Id': '/hostedzone/MATCHES', 'Name': 'public.example.',
         'Config': {'PrivateZone': False}},
        {'Id': '/hostedzone/PRIVATE', 'Name': 'internal.example.',
         'Config': {'PrivateZone': True}},
        # covered: PrivateZone is optional and defaults to false, so a zone
        # with no Config block is public and belongs in the inventory.
        {'Id': '/hostedzone/KEYABSENT', 'Name': 'unknown.example.'},
    ]
    matched = sorted(r['Id'] for r in run_policy(
        POLICIES, 'inventory-hosted-zones', resources))
    assert matched == ['/hostedzone/KEYABSENT', '/hostedzone/MATCHES']


def test_inventory_hosted_zones_records():
    resources = [
        {'Name': 'a.example.', 'Type': 'A', 'TTL': 300},
        {'Name': 'cname.example.', 'Type': 'CNAME', 'TTL': 300},
        {'Name': 'mx.example.', 'Type': 'MX', 'TTL': 300},
        {'Name': 'txt.example.', 'Type': 'TXT', 'TTL': 300},
        # Type absent: `op: in` against None does not match, so the record
        # is left out of the inventory.
        {'Name': 'key-absent.example.', 'TTL': 300},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'inventory-hosted-zones-records', resources)]
    assert matched == ['a.example.', 'cname.example.', 'mx.example.']
