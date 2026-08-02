"""Behavioural tests for policies/aws/iam.yml.

Offline: no AWS credentials, no network.

Only four of the twenty policies in this file run offline. The rest use
`credential` (the IAM credential report), `check-permissions` (the IAM
policy simulator), `has-allow-all` / `has-inline-policy` / `policy` /
`has-specific-managed-policy` / `access-key` (extra IAM calls per user or
role) or `usage` (access advisor) -- every one of those goes back to AWS
for data that is not in the `list_*` response.

`external-trust` is a custom filter and lives in the c7n_pack extension
package, which has to be importable before the policy can be built.

The tests run with the kit's default `account_id` of 000000000000, so
that is "our" account in every fixture below.
"""


from c7n_kit.testing import run_policy  # noqa: E402

POLICIES = 'policies/aws/iam.yml'


def _role(name, statements):
    return {
        'RoleName': name,
        'Arn': 'arn:aws:iam::000000000000:role/%s' % name,
        'Path': '/',
        'AssumeRolePolicyDocument': {
            'Version': '2012-10-17', 'Statement': statements},
    }


def test_iam_server_certificate_expired():
    resources = [
        {'ServerCertificateName': 'matches', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:server-certificate/matches',
         'Expiration': '2020-01-01T00:00:00+00:00'},
        {'ServerCertificateName': 'clean', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:server-certificate/clean',
         'Expiration': '2099-01-01T00:00:00+00:00'},
        # KNOWN LIMITATION: with `value_type: expiration` an absent Expiration
        # parses to 0, the comparison against a datetime raises TypeError and
        # c7n swallows it as "no match" -- the certificate reads as valid.
        {'ServerCertificateName': 'key-absent', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:server-certificate/key-absent'},
    ]
    matched = [r['ServerCertificateName'] for r in run_policy(
        POLICIES, 'iam-server-certificate-expired', resources)]
    assert matched == ['matches']


def test_inventory_iam_role_cross_account():
    resources = [
        _role('matches', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
            'Action': 'sts:AssumeRole'}]),
        _role('clean', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::000000000000:root'},
            'Action': 'sts:AssumeRole'}]),
        # a service-linked style trust: no AWS principal at all
        _role('service', [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ec2.amazonaws.com'},
            'Action': 'sts:AssumeRole'}]),
        # KNOWN LIMITATION: c7n's cross-account returns False when the policy
        # attribute is missing, so a role whose AssumeRolePolicyDocument never
        # came back reads as compliant.
        {'RoleName': 'key-absent', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:role/key-absent'},
    ]
    matched = [r['RoleName'] for r in run_policy(
        POLICIES, 'inventory-iam-role-cross-account', resources)]
    assert matched == ['matches']


def test_iam_role_assumable_from_outside_the_org():
    resources = [
        # an account that is neither ours, nor whitelisted, nor an approved
        # third party
        _role('matches', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
            'Action': 'sts:AssumeRole'}]),
        _role('matches-star', [{
            'Effect': 'Allow', 'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole'}]),
        # bounded by a POSITIVE condition on our own org id
        _role('clean-orgid', [{
            'Effect': 'Allow', 'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole',
            'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-exampleorg1'}}}]),
        _role('clean-whitelisted', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::111111111111:root'},
            'Action': 'sts:AssumeRole'}]),
        _role('clean-third-party', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::444444444444:root'},
            'Action': 'sts:AssumeRole'}]),
        # StringNotEquals is the OPPOSITE of scoped: "anyone except this org"
        _role('matches-negative-condition', [{
            'Effect': 'Allow', 'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole',
            'Condition': {
                'StringNotEquals': {'aws:PrincipalOrgID': 'o-exampleorg1'}}}]),
        # federated OIDC provider with no `:sub` condition: assumable from any
        # repository the provider will mint a token for
        _role('matches-federated', [{
            'Effect': 'Allow',
            'Principal': {'Federated':
                          'arn:aws:iam::000000000000:oidc-provider/'
                          'token.actions.githubusercontent.com'},
            'Action': 'sts:AssumeRoleWithWebIdentity'}]),
        # KNOWN LIMITATION: no AssumeRolePolicyDocument means no statements to
        # walk, so a role whose trust policy never came back reads as compliant.
        {'RoleName': 'key-absent', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:role/key-absent'},
    ]
    matched = [r['RoleName'] for r in run_policy(
        POLICIES, 'iam-role-assumable-from-outside-the-org', resources)]
    assert matched == ['matches', 'matches-star',
                       'matches-negative-condition', 'matches-federated']


def test_iam_role_external_trust_without_external_id():
    resources = [
        # external account, no sts:ExternalId condition
        _role('matches', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
            'Action': 'sts:AssumeRole'}]),
        # even a WHITELISTED third party is reported when it has no ExternalId:
        # this rule answers "which external access has no confused-deputy
        # protection", not "who is approved"
        _role('matches-approved-third-party', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::444444444444:root'},
            'Action': 'sts:AssumeRole'}]),
        _role('clean-with-external-id', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
            'Action': 'sts:AssumeRole',
            'Condition': {'StringEquals': {'sts:ExternalId': 'abc123'}}}]),
        # inside the organisation the confused deputy does not apply
        _role('clean-own-account', [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::000000000000:root'},
            'Action': 'sts:AssumeRole'}]),
        # KNOWN LIMITATION: no trust document, nothing to walk, reads as clean.
        {'RoleName': 'key-absent', 'Path': '/',
         'Arn': 'arn:aws:iam::000000000000:role/key-absent'},
    ]
    matched = [r['RoleName'] for r in run_policy(
        POLICIES, 'iam-role-external-trust-without-external-id', resources)]
    assert matched == ['matches', 'matches-approved-third-party']
