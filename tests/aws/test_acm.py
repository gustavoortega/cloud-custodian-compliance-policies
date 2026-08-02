"""Behavioural tests for policies/aws/acm.yml.

Offline: no AWS credentials, no network.

The expiry dates below are deliberately far apart from any plausible run
date so the `value_type: expiration` comparisons stay stable over time:
`2020-…` is long past, `2099-…` is long future.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/acm.yml'


def test_acm_certificate_not_renewed():
    resources = [
        # already expired: expiration is signed, so it sits below 30 days too
        {'CertificateArn': 'matches', 'DomainName': 'a.example.com',
         'Status': 'EXPIRED', 'NotAfter': '2020-01-01T00:00:00Z'},
        {'CertificateArn': 'clean', 'DomainName': 'b.example.com',
         'Status': 'ISSUED', 'NotAfter': '2099-01-01T00:00:00Z'},
        # KNOWN LIMITATION: NotAfter absent resolves to None and the
        # expiration comparison never matches, so a certificate AWS never
        # finished describing is reported as compliant.
        {'CertificateArn': 'key-absent', 'DomainName': 'c.example.com',
         'Status': 'ISSUED'},
    ]
    matched = [r['CertificateArn'] for r in run_policy(
        POLICIES, 'acm-certificate-not-renewed', resources)]
    assert matched == ['matches']


def test_acm_certificate_rsa_key_too_short():
    resources = [
        {'CertificateArn': 'matches', 'DomainName': 'a.example.com',
         'Type': 'IMPORTED', 'KeyAlgorithm': 'RSA-1024'},
        {'CertificateArn': 'clean', 'DomainName': 'b.example.com',
         'Type': 'AMAZON_ISSUED', 'KeyAlgorithm': 'RSA-2048'},
        # KeyAlgorithm absent: equality against None never matches, the
        # certificate reads as compliant.
        {'CertificateArn': 'key-absent', 'DomainName': 'c.example.com'},
    ]
    matched = [r['CertificateArn'] for r in run_policy(
        POLICIES, 'acm-certificate-rsa-key-too-short', resources)]
    assert matched == ['matches']


def test_acm_certificate_expired_in_use():
    resources = [
        {'CertificateArn': 'matches', 'DomainName': 'a.example.com',
         'Status': 'EXPIRED', 'InUseBy': ['arn:aws:elasticloadbalancing:::lb/x']},
        # expired but detached: no client is hitting it
        {'CertificateArn': 'clean-unused', 'DomainName': 'b.example.com',
         'Status': 'EXPIRED', 'InUseBy': []},
        # in use but valid
        {'CertificateArn': 'clean-valid', 'DomainName': 'c.example.com',
         'Status': 'ISSUED', 'InUseBy': ['arn:aws:elasticloadbalancing:::lb/y']},
        # InUseBy absent: `not-null` requires the key, so it does not match.
        # Here absence is the right direction (nothing is serving it).
        {'CertificateArn': 'key-absent', 'DomainName': 'd.example.com',
         'Status': 'EXPIRED'},
    ]
    matched = [r['CertificateArn'] for r in run_policy(
        POLICIES, 'acm-certificate-expired-in-use', resources)]
    assert matched == ['matches']


def test_acm_certificate_expiring_30d():
    resources = [
        {'CertificateArn': 'matches', 'DomainName': 'a.example.com',
         'Status': 'ISSUED', 'NotAfter': '2020-01-01T00:00:00Z'},
        {'CertificateArn': 'clean', 'DomainName': 'b.example.com',
         'Status': 'ISSUED', 'NotAfter': '2099-01-01T00:00:00Z'},
        # not ISSUED, so out of scope even though it is past NotAfter
        {'CertificateArn': 'clean-pending', 'DomainName': 'c.example.com',
         'Status': 'PENDING_VALIDATION', 'NotAfter': '2020-01-01T00:00:00Z'},
        # KNOWN LIMITATION: absent NotAfter never matches the expiration
        # comparison, so the certificate is reported as compliant.
        {'CertificateArn': 'key-absent', 'DomainName': 'd.example.com',
         'Status': 'ISSUED'},
    ]
    matched = [r['CertificateArn'] for r in run_policy(
        POLICIES, 'acm-certificate-expiring-30d', resources)]
    assert matched == ['matches']


def test_acm_certificate_renewal_failed():
    resources = [
        {'CertificateArn': 'matches', 'DomainName': 'a.example.com',
         'Status': 'ISSUED',
         'RenewalSummary': {'RenewalStatus': 'FAILED',
                            'DomainValidationOptions': []}},
        {'CertificateArn': 'clean', 'DomainName': 'b.example.com',
         'Status': 'ISSUED',
         'RenewalSummary': {'RenewalStatus': 'SUCCESS',
                            'DomainValidationOptions': []}},
        # RenewalSummary absent (no renewal ever attempted): does not match,
        # which is the intended direction for this control.
        {'CertificateArn': 'key-absent', 'DomainName': 'c.example.com',
         'Status': 'ISSUED'},
    ]
    matched = [r['CertificateArn'] for r in run_policy(
        POLICIES, 'acm-certificate-renewal-failed', resources)]
    assert matched == ['matches']
