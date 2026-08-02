"""Behavioural tests for policies/aws/cognito.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/cognito.yml'

STRONG_PASSWORD_POLICY = {
    'MinimumLength': 12,
    'RequireUppercase': True,
    'RequireLowercase': True,
    'RequireNumbers': True,
    'RequireSymbols': True,
    'TemporaryPasswordValidityDays': 7,
}


def test_cognito_identity_pool_unauthenticated_access():
    resources = [
        {'IdentityPoolId': 'matches', 'IdentityPoolName': 'a',
         'AllowUnauthenticatedIdentities': True},
        {'IdentityPoolId': 'clean', 'IdentityPoolName': 'b',
         'AllowUnauthenticatedIdentities': False},
        # AllowUnauthenticatedIdentities absent: `value: true` against None
        # does not match. Absence is the safe direction here.
        {'IdentityPoolId': 'key-absent', 'IdentityPoolName': 'c'},
    ]
    matched = [r['IdentityPoolId'] for r in run_policy(
        POLICIES, 'cognito-identity-pool-unauthenticated-access', resources)]
    assert matched == ['matches']


def test_cognito_user_pool_weak_password_policy():
    short = dict(STRONG_PASSWORD_POLICY, MinimumLength=6)
    no_symbols = dict(STRONG_PASSWORD_POLICY, RequireSymbols=False)
    long_temp = dict(STRONG_PASSWORD_POLICY, TemporaryPasswordValidityDays=30)
    resources = [
        {'Id': 'matches-short', 'Name': 'a',
         'Policies': {'PasswordPolicy': short}},
        {'Id': 'matches-no-symbols', 'Name': 'b',
         'Policies': {'PasswordPolicy': no_symbols}},
        {'Id': 'matches-long-temp', 'Name': 'c',
         'Policies': {'PasswordPolicy': long_temp}},
        {'Id': 'clean', 'Name': 'd',
         'Policies': {'PasswordPolicy': dict(STRONG_PASSWORD_POLICY)}},
        # KNOWN LIMITATION: with Policies absent every branch resolves to
        # None -- `op: lt` does not match, `value: false` is None == False
        # which is False, `op: gt` does not match -- so a user pool whose
        # password policy never came back is reported as compliant.
        {'Id': 'key-absent', 'Name': 'e'},
    ]
    # `or` resolves via set union, so sort before asserting.
    matched = sorted(r['Id'] for r in run_policy(
        POLICIES, 'cognito-user-pool-weak-password-policy', resources))
    assert matched == ['matches-long-temp', 'matches-no-symbols', 'matches-short']


def test_cognito_user_pool_custom_auth_threat_protection_disabled():
    resources = [
        {'Id': 'matches', 'Name': 'a',
         'LambdaConfig': {'DefineAuthChallenge': 'arn:aws:lambda:::function:define'},
         'UserPoolAddOns': {'AdvancedSecurityMode': 'AUDIT'}},
        {'Id': 'clean-enforced', 'Name': 'b',
         'LambdaConfig': {'DefineAuthChallenge': 'arn:aws:lambda:::function:define'},
         'UserPoolAddOns': {'AdvancedSecurityMode': 'ENFORCED',
                            'AdvancedSecurityAdditionalFlows': {
                                'CustomAuthMode': 'ENFORCED'}}},
        # no custom-auth Lambda: out of the control's scope entirely
        {'Id': 'clean-no-custom-auth', 'Name': 'c', 'LambdaConfig': {}},
        # UserPoolAddOns absent AND LambdaConfig absent: the `present` gate on
        # DefineAuthChallenge stops it first, which is exactly the point of
        # crossing the two conditions -- `op: ne` on an absent CustomAuthMode
        # would otherwise match every pool in the account.
        {'Id': 'key-absent', 'Name': 'd'},
    ]
    matched = [r['Id'] for r in run_policy(
        POLICIES, 'cognito-user-pool-custom-auth-threat-protection-disabled', resources)]
    assert matched == ['matches']


def test_cognito_user_pool_mfa_disabled():
    resources = [
        {'Id': 'matches', 'Name': 'a',
         'Policies': {'SignInPolicy': {'AllowedFirstAuthFactors': ['PASSWORD']}},
         'MfaConfiguration': 'OFF'},
        {'Id': 'clean-mfa-on', 'Name': 'b',
         'Policies': {'SignInPolicy': {'AllowedFirstAuthFactors': ['PASSWORD']}},
         'MfaConfiguration': 'ON'},
        # passwordless/federated sign-in: control does not apply
        {'Id': 'clean-passwordless', 'Name': 'c',
         'Policies': {'SignInPolicy': {
             'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']}},
         'MfaConfiguration': 'OFF'},
        # SignInPolicy absent: the equality against ['PASSWORD'] fails first,
        # so the pool is not reported. This is the deliberate scoping gate --
        # the bare `op: ne` on MfaConfiguration would match everything.
        {'Id': 'key-absent', 'Name': 'd', 'MfaConfiguration': 'OFF'},
    ]
    matched = [r['Id'] for r in run_policy(
        POLICIES, 'cognito-user-pool-mfa-disabled', resources)]
    assert matched == ['matches']


def test_cognito_user_pool_deletion_protection_disabled():
    resources = [
        {'Id': 'matches', 'Name': 'a', 'DeletionProtection': 'INACTIVE'},
        {'Id': 'clean', 'Name': 'b', 'DeletionProtection': 'ACTIVE'},
        # KNOWN LIMITATION: equality against the string "INACTIVE", so a pool
        # whose DeletionProtection field never came back reads as compliant
        # even though an unset field means protection is off.
        {'Id': 'key-absent', 'Name': 'c'},
    ]
    matched = [r['Id'] for r in run_policy(
        POLICIES, 'cognito-user-pool-deletion-protection-disabled', resources)]
    assert matched == ['matches']
