"""Behavioural tests for policies/aws/ses.yml.

Offline: no AWS credentials, no network.

`SendingEnabled` and `IdentityName` come from ListEmailIdentities;
`DkimAttributes` and `Policies` from GetEmailIdentity, which c7n merges
into the same dict. `Policies` is a map of policy name -> policy JSON,
not a single document.

The tests run with the kit's default `account_id` of 000000000000.
"""
import json

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/ses.yml'


def test_ses_identity_policy_external_access():
    external = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 'ext', 'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
        'Action': 'ses:SendEmail',
        'Resource': 'arn:aws:ses:us-east-1:000000000000:identity/matches'}]})
    whitelisted = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 'wl', 'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::111111111111:root'},
        'Action': 'ses:SendEmail',
        'Resource': 'arn:aws:ses:us-east-1:000000000000:identity/clean-wl'}]})
    resources = [
        {'IdentityName': 'matches', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True, 'Policies': {'ext': external}},
        {'IdentityName': 'clean-whitelisted', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True, 'Policies': {'wl': whitelisted}},
        # no identity policy at all: the filter returns False on a missing
        # Policies map, so the identity reads as compliant.
        {'IdentityName': 'key-absent', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True},
    ]
    matched = [r['IdentityName'] for r in run_policy(
        POLICIES, 'ses-identity-policy-external-access', resources)]
    assert matched == ['matches']


def test_ses_identity_dkim_disabled():
    resources = [
        {'IdentityName': 'matches', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True,
         'DkimAttributes': {'SigningEnabled': False, 'Status': 'NOT_STARTED'}},
        {'IdentityName': 'clean', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True,
         'DkimAttributes': {'SigningEnabled': True, 'Status': 'SUCCESS'}},
        {'IdentityName': 'not-sending', 'IdentityType': 'DOMAIN',
         'SendingEnabled': False,
         'DkimAttributes': {'SigningEnabled': False}},
        # the `absent` branch is present, so an identity with no DkimAttributes
        # block IS caught rather than read as signed.
        {'IdentityName': 'key-absent', 'IdentityType': 'DOMAIN',
         'SendingEnabled': True},
    ]
    matched = [r['IdentityName'] for r in run_policy(
        POLICIES, 'ses-identity-dkim-disabled', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches']


def test_ses_identity_dkim_weak_key():
    resources = [
        {'IdentityName': 'matches', 'IdentityType': 'DOMAIN',
         'DkimAttributes': {'SigningEnabled': True,
                            'CurrentSigningKeyLength': 'RSA_1024_BIT'}},
        {'IdentityName': 'clean', 'IdentityType': 'DOMAIN',
         'DkimAttributes': {'SigningEnabled': True,
                            'CurrentSigningKeyLength': 'RSA_2048_BIT'}},
        # DKIM off is out of scope for this policy
        {'IdentityName': 'dkim-off', 'IdentityType': 'DOMAIN',
         'DkimAttributes': {'SigningEnabled': False}},
        # CurrentSigningKeyLength is not returned for BYODKIM identities; the
        # positive match on the literal reads that absence as compliant.
        {'IdentityName': 'key-absent', 'IdentityType': 'DOMAIN',
         'DkimAttributes': {'SigningEnabled': True}},
    ]
    matched = [r['IdentityName'] for r in run_policy(
        POLICIES, 'ses-identity-dkim-weak-key', resources)]
    assert matched == ['matches']


def test_ses_configuration_set_tls_not_required():
    resources = [
        {'ConfigurationSetName': 'matches',
         'DeliveryOptions': {'TlsPolicy': 'OPTIONAL'}},
        {'ConfigurationSetName': 'clean',
         'DeliveryOptions': {'TlsPolicy': 'REQUIRE'}},
        # `op: ne` on an absent key resolves None != 'REQUIRE' -> True, so a
        # configuration set with no DeliveryOptions IS caught. Correct
        # direction: OPTIONAL is the default when the block is missing.
        {'ConfigurationSetName': 'key-absent'},
    ]
    matched = [r['ConfigurationSetName'] for r in run_policy(
        POLICIES, 'ses-configuration-set-tls-not-required', resources)]
    assert matched == ['matches', 'key-absent']
