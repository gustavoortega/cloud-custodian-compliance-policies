"""Behavioural tests for policies/aws/s3.yml.

Offline: no AWS credentials, no network.

c7n's S3 resource manager augments every bucket with `Acl`, `Policy`,
`Logging` and `Lifecycle` during enumeration, so the filters that look
"remote" (`global-grants`, `cross-account`, `bucket-logging`,
`insecure-transport`) actually read those keys off the resource dict and
do run offline. `check-public-block` and `bucket-encryption` do NOT:
they issue their own per-bucket API call, which is why the four
Block-Public-Access policies and `s3-kms-bucket-key-disabled` are not
tested here.

`insecure-transport` is a custom filter from the c7n_pack extension
package, which has to be importable before those policies can be built.

The tests run with the kit's default `account_id` of 000000000000, so
999999999999 is "an account outside the organisation" everywhere below.
"""
import json


from c7n_kit.testing import run_policy  # noqa: E402

POLICIES = 'policies/aws/s3.yml'

OWNER = 'c7b1e4f0000000000000000000000000000000000000000000000000000000000'
ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
LOG_DELIVERY = 'http://acs.amazonaws.com/groups/s3/LogDelivery'


def _tls_deny(bucket):
    """The canonical aws:SecureTransport deny, covering bucket AND objects."""
    return json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 'DenyInsecureTransport', 'Effect': 'Deny', 'Principal': '*',
        'Action': 's3:*',
        'Resource': ['arn:aws:s3:::%s' % bucket, 'arn:aws:s3:::%s/*' % bucket],
        'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}]})


def _public_read_policy(bucket):
    return json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 'PublicRead', 'Effect': 'Allow', 'Principal': '*',
        'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::%s/*' % bucket}]})


def _own_acl():
    return {'Owner': {'ID': OWNER},
            'Grants': [{'Grantee': {'Type': 'CanonicalUser', 'ID': OWNER},
                        'Permission': 'FULL_CONTROL'}]}


def _public_acl():
    acl = _own_acl()
    acl['Grants'].append(
        {'Grantee': {'Type': 'Group', 'URI': ALL_USERS}, 'Permission': 'READ'})
    return acl


def test_s3_public_policy_and_global_access():
    resources = [
        {'Name': 'matches-acl', 'Acl': _public_acl(),
         'Policy': _tls_deny('matches-acl')},
        {'Name': 'matches-policy', 'Acl': _own_acl(),
         'Policy': _public_read_policy('matches-policy')},
        {'Name': 'clean', 'Acl': _own_acl(), 'Policy': _tls_deny('clean')},
        # no Acl and no Policy at all: global-grants finds no grants and
        # cross-account finds no policy, so the bucket reads as compliant.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-public-policy-and-global-access', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches-acl', 'matches-policy']


def test_inventory_s3_insecure_transport():
    resources = [
        # a policy that denies nothing: Reason "no-deny"
        {'Name': 'matches-no-deny', 'Acl': _own_acl(),
         'Policy': _public_read_policy('matches-no-deny')},
        {'Name': 'clean', 'Acl': _own_acl(), 'Policy': _tls_deny('clean')},
        # no Policy key at all is the AWS default and IS caught (Reason
        # "no-policy") -- absence is a finding here, not a silent pass.
        {'Name': 'key-absent', 'Acl': _own_acl()},
        # an AccessDenied reading the policy is EXCLUDED rather than counted:
        # not being able to look is not evidence the deny is missing.
        {'Name': 'denied', 'Acl': _own_acl(),
         'c7n:DeniedMethods': ['get_bucket_policy']},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 'inventory-s3-insecure-transport', resources)]
    assert matched == ['matches-no-deny', 'key-absent']


def test_s3_insecure_transport_exposed():
    resources = [
        # no TLS deny AND public through the bucket policy
        {'Name': 'matches', 'Acl': _own_acl(),
         'Policy': _public_read_policy('matches')},
        # no TLS deny but not exposed: excluded on purpose, this policy is the
        # crossed version
        {'Name': 'insecure-not-exposed', 'Acl': _own_acl()},
        # exposed but the TLS deny is in place
        {'Name': 'exposed-but-tls', 'Acl': _public_acl(),
         'Policy': _tls_deny('exposed-but-tls')},
        {'Name': 'clean', 'Acl': _own_acl(), 'Policy': _tls_deny('clean')},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-insecure-transport-exposed', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches']


def test_s3_bucket_policy_grants_sensitive_actions_to_external_account():
    external = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
        'Action': 's3:PutObjectAcl', 'Resource': 'arn:aws:s3:::matches/*'}]})
    wildcard = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
        'Action': 's3:*', 'Resource': 'arn:aws:s3:::matches-wildcard/*'}]})
    whitelisted = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::111111111111:root'},
        'Action': 's3:PutObjectAcl', 'Resource': 'arn:aws:s3:::clean-wl/*'}]})
    harmless = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow',
        'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
        'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::clean/*'}]})
    resources = [
        {'Name': 'matches', 'Acl': _own_acl(), 'Policy': external},
        # `s3:*` is a wildcard PATTERN and c7n matches it against every
        # blacklisted action, so it is caught too
        {'Name': 'matches-wildcard', 'Acl': _own_acl(), 'Policy': wildcard},
        {'Name': 'clean-whitelisted', 'Acl': _own_acl(), 'Policy': whitelisted},
        {'Name': 'clean', 'Acl': _own_acl(), 'Policy': harmless},
        # no bucket policy: nothing to grant, reads as compliant
        {'Name': 'key-absent', 'Acl': _own_acl()},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-bucket-policy-grants-sensitive-actions-to-external-account',
        resources)]
    assert matched == ['matches', 'matches-wildcard']


def test_s3_server_access_logging_disabled():
    resources = [
        # get_bucket_logging on a bucket without logging returns an empty body
        {'Name': 'matches', 'Logging': {}},
        {'Name': 'clean', 'Logging': {'TargetBucket': 'logs',
                                      'TargetPrefix': 'clean/'}},
        # the key never came back at all: c7n defaults it to {} and the bucket
        # IS caught, same as an explicitly empty configuration.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-server-access-logging-disabled', resources)]
    assert matched == ['matches', 'key-absent']


def test_s3_acl_used_for_access():
    other = 'd0e2' + '0' * 60
    resources = [
        # a second, distinct canonical-user grantee
        {'Name': 'matches-canonical', 'Acl': {
            'Owner': {'ID': OWNER},
            'Grants': [
                {'Grantee': {'Type': 'CanonicalUser', 'ID': OWNER},
                 'Permission': 'FULL_CONTROL'},
                {'Grantee': {'Type': 'CanonicalUser', 'ID': other},
                 'Permission': 'READ'}]}},
        # a Group grant that is not LogDelivery
        {'Name': 'matches-group', 'Acl': _public_acl()},
        # the owner listed twice is NOT a finding: unique_size collapses it
        {'Name': 'clean-duplicate-owner', 'Acl': {
            'Owner': {'ID': OWNER},
            'Grants': [
                {'Grantee': {'Type': 'CanonicalUser', 'ID': OWNER},
                 'Permission': 'FULL_CONTROL'},
                {'Grantee': {'Type': 'CanonicalUser', 'ID': OWNER},
                 'Permission': 'READ_ACP'}]}},
        # LogDelivery is carved out on purpose
        {'Name': 'clean-log-delivery', 'Acl': {
            'Owner': {'ID': OWNER},
            'Grants': [
                {'Grantee': {'Type': 'CanonicalUser', 'ID': OWNER},
                 'Permission': 'FULL_CONTROL'},
                {'Grantee': {'Type': 'Group', 'URI': LOG_DELIVERY},
                 'Permission': 'WRITE'}]}},
        # KNOWN LIMITATION: with no Acl key, `unique_size`/`size` fall back to 0
        # and neither branch fires, so a bucket whose ACL never came back is
        # reported as compliant.
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-acl-used-for-access', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['matches-canonical', 'matches-group']


def test_s3_lifecycle_configuration_missing():
    resources = [
        # the key is present but null: the second branch of the `or`
        {'Name': 'matches-null', 'Lifecycle': None},
        {'Name': 'clean', 'Lifecycle': {'Rules': [
            {'ID': 'expire', 'Status': 'Enabled',
             'Expiration': {'Days': 365}}]}},
        # the key never came back: the `absent` branch catches it
        {'Name': 'key-absent'},
    ]
    matched = [r['Name'] for r in run_policy(
        POLICIES, 's3-lifecycle-configuration-missing', resources)]
    # `or` merges branches through a set of ids: sort for a stable assertion.
    assert sorted(matched) == ['key-absent', 'matches-null']
