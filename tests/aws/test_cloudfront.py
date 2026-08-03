"""Behavioural tests for policies/aws/cloudfront.yml.

Offline: no AWS credentials, no network.

Resource shape: `aws.distribution` is the `DistributionSummary` returned by
`cloudfront:ListDistributions`, NOT the `Distribution{DistributionConfig{...}}`
envelope of `GetDistribution`. Everything the summary carries sits at the top
level of the resource dict -- `Enabled`, `WebACLId`, `Origins`,
`DefaultCacheBehavior`, `CacheBehaviors`, `ViewerCertificate` -- which is why
the policies write `key: Enabled` and `key: Origins.Items[...]` with no
`DistributionConfig.` prefix. The fields that only exist in the full config
(`DefaultRootObject`, `Logging`, `OriginGroups`) are reached by the separate
`distribution-config` filter, which calls GetDistributionConfig and therefore
cannot run offline -- those policies are not covered here.

`Origins.Items[]` entries carry either `S3OriginConfig` or `CustomOriginConfig`
(never both), plus an optional `OriginAccessControlId`.

Assertions are SORTED: c7n's `or:` rebuilds its result from a Python `set` of
resource ids, so the order varies between processes.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/cloudfront.yml'


def distribution(dist_id, **kw):
    return {
        'Id': dist_id,
        'ARN': f'arn:aws:cloudfront::111111111111:distribution/{dist_id}',
        'DomainName': f'{dist_id}.cloudfront.net',
        'Status': 'Deployed',
        **kw,
    }


def s3_origin(origin_id='s3-origin', **kw):
    return {'Id': origin_id,
            'DomainName': 'assets.s3.us-east-1.amazonaws.com',
            'OriginPath': '',
            'S3OriginConfig': {'OriginAccessIdentity': ''},
            **kw}


def custom_origin(origin_id='custom-origin', domain='origin.example.com',
                  protocol_policy='https-only', **kw):
    return {'Id': origin_id,
            'DomainName': domain,
            'OriginPath': '',
            'CustomOriginConfig': {
                'HTTPPort': 80, 'HTTPSPort': 443,
                'OriginProtocolPolicy': protocol_policy,
                'OriginSslProtocols': {'Quantity': 1, 'Items': ['TLSv1.2']}},
            **kw}


def behavior(viewer_protocol_policy='redirect-to-https'):
    return {'TargetOriginId': 'origin',
            'ViewerProtocolPolicy': viewer_protocol_policy,
            'Compress': True}


def matched(policy, resources):
    return sorted(r['Id'] for r in run_policy(POLICIES, policy, resources))


def test_cloudfront_distribution_without_waf():
    resources = [
        # no web ACL comes back as an empty string, which `value: empty` matches
        distribution('matches', Enabled=True, WebACLId=''),
        distribution('clean', Enabled=True,
                     WebACLId='arn:aws:wafv2:us-east-1:111111111111:global/'
                              'webacl/prod/12345678-1234-1234-1234-123456789012'),
        distribution('disabled', Enabled=False, WebACLId=''),
        # `value: empty` also matches a missing key (`not None` is True)
        distribution('webaclid-absent', Enabled=True),
        # KNOWN LIMITATION: `Enabled` absent -> None == True is False, so a
        # distribution the field never came back for is dropped by the first
        # filter and never evaluated for WAF at all.
        distribution('enabled-absent', WebACLId=''),
    ]
    assert matched('cloudfront-distribution-without-waf', resources) == [
        'matches', 'webaclid-absent']


def test_cloudfront_distribution_weak_tls():
    resources = [
        distribution('matches', ViewerCertificate={
            'MinimumProtocolVersion': 'TLSv1',
            'CloudFrontDefaultCertificate': False,
            'SSLSupportMethod': 'sni-only'}),
        distribution('clean', ViewerCertificate={
            'MinimumProtocolVersion': 'TLSv1.2_2021',
            'CloudFrontDefaultCertificate': False,
            'SSLSupportMethod': 'sni-only'}),
        # KNOWN LIMITATION: `op: in` against an absent key resolves to None,
        # which is not in the list, so a distribution with no ViewerCertificate
        # is reported as compliant.
        distribution('key-absent'),
    ]
    assert matched('cloudfront-distribution-weak-tls', resources) == ['matches']


def test_cloudfront_viewer_protocol_allow_all():
    resources = [
        distribution('default-behavior',
                     DefaultCacheBehavior=behavior('allow-all'),
                     CacheBehaviors={'Quantity': 0}),
        # one non-default behaviour left on allow-all is enough
        distribution('extra-behavior',
                     DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 1, 'Items': [
                         {'PathPattern': '/legacy/*', 'TargetOriginId': 'origin',
                          'ViewerProtocolPolicy': 'allow-all'}]}),
        distribution('clean', DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 0}),
        # the `|| `[]`` fallback keeps a distribution with neither key from
        # blowing up; it simply does not match
        distribution('key-absent'),
    ]
    assert matched('cloudfront-viewer-protocol-allow-all', resources) == [
        'default-behavior', 'extra-behavior']


def test_cloudfront_using_default_certificate():
    resources = [
        distribution('matches', ViewerCertificate={
            'CloudFrontDefaultCertificate': True,
            'MinimumProtocolVersion': 'TLSv1',
            'CertificateSource': 'cloudfront'}),
        distribution('clean', ViewerCertificate={
            'CloudFrontDefaultCertificate': False,
            'ACMCertificateArn': 'arn:aws:acm:us-east-1:111111111111:certificate/'
                                 '12345678-1234-1234-1234-123456789012',
            'SSLSupportMethod': 'sni-only',
            'MinimumProtocolVersion': 'TLSv1.2_2021',
            'CertificateSource': 'acm'}),
        # KNOWN LIMITATION: bare `value: true` with no `absent` branch -- a
        # distribution with no ViewerCertificate reads as compliant.
        distribution('key-absent'),
    ]
    assert matched('cloudfront-using-default-certificate', resources) == ['matches']


def test_cloudfront_custom_origin_unencrypted():
    resources = [
        distribution('http-only',
                     Origins={'Quantity': 1, 'Items': [
                         custom_origin(protocol_policy='http-only')]},
                     DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 0}),
        # match-viewer is only insecure combined with a viewer policy of allow-all
        distribution('match-viewer-allow-all',
                     Origins={'Quantity': 1, 'Items': [
                         custom_origin(protocol_policy='match-viewer')]},
                     DefaultCacheBehavior=behavior('allow-all'),
                     CacheBehaviors={'Quantity': 0}),
        distribution('match-viewer-https',
                     Origins={'Quantity': 1, 'Items': [
                         custom_origin(protocol_policy='match-viewer')]},
                     DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 0}),
        distribution('clean',
                     Origins={'Quantity': 1, 'Items': [
                         custom_origin(protocol_policy='https-only')]},
                     DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 0}),
        # no custom origin at all -> control does not apply
        distribution('s3-only',
                     Origins={'Quantity': 1, 'Items': [s3_origin()]},
                     DefaultCacheBehavior=behavior(),
                     CacheBehaviors={'Quantity': 0}),
        # `Origins` absent: the `Origins.Items not-null` guard drops it before
        # length(null) can raise and abort the whole invocation. Not reported.
        distribution('origins-absent',
                     DefaultCacheBehavior=behavior('allow-all'),
                     CacheBehaviors={'Quantity': 0}),
        # Origins present but Items absent crashes the same way without a guard
        distribution('items-absent', Origins={'Quantity': 0},
                     DefaultCacheBehavior=behavior('allow-all'),
                     CacheBehaviors={'Quantity': 0}),
    ]
    assert matched('cloudfront-custom-origin-unencrypted', resources) == [
        'http-only', 'match-viewer-allow-all']

    # and each of them alone is a non-match, not an exception
    assert run_policy(POLICIES, 'cloudfront-custom-origin-unencrypted',
                      [distribution('origins-absent')]) == []


def test_cloudfront_s3_origin_without_oac():
    resources = [
        distribution('matches', Origins={'Quantity': 1, 'Items': [s3_origin()]}),
        distribution('clean', Origins={'Quantity': 1, 'Items': [
            s3_origin(OriginAccessControlId='E1ABCDEFGHIJKL')]}),
        # no S3 origin -> control does not apply
        distribution('custom-only',
                     Origins={'Quantity': 1, 'Items': [custom_origin()]}),
        # guarded out instead of crashing the run
        distribution('origins-absent'),
        distribution('items-absent', Origins={'Quantity': 0}),
    ]
    assert matched('cloudfront-s3-origin-without-oac', resources) == ['matches']

    assert run_policy(POLICIES, 'cloudfront-s3-origin-without-oac',
                      [distribution('origins-absent')]) == []


def test_cloudfront_tls_policy_not_recommended():
    acm = 'arn:aws:acm:us-east-1:111111111111:certificate/' \
          '12345678-1234-1234-1234-123456789012'
    resources = [
        distribution('matches', ViewerCertificate={
            'CloudFrontDefaultCertificate': False, 'SSLSupportMethod': 'sni-only',
            'MinimumProtocolVersion': 'TLSv1.1_2016', 'ACMCertificateArn': acm}),
        distribution('clean', ViewerCertificate={
            'CloudFrontDefaultCertificate': False, 'SSLSupportMethod': 'sni-only',
            'MinimumProtocolVersion': 'TLSv1.2_2021', 'ACMCertificateArn': acm}),
        # legacy dedicated-IP support method is out of the control's scope
        distribution('vip', ViewerCertificate={
            'CloudFrontDefaultCertificate': False, 'SSLSupportMethod': 'vip',
            'MinimumProtocolVersion': 'TLSv1.1_2016', 'ACMCertificateArn': acm}),
        distribution('default-cert', ViewerCertificate={
            'CloudFrontDefaultCertificate': True,
            'MinimumProtocolVersion': 'TLSv1'}),
        # `op: not-in` on an absent MinimumProtocolVersion matches (None is not
        # in the recommended list), so it is reported -- the safe direction
        distribution('minprotocol-absent', ViewerCertificate={
            'CloudFrontDefaultCertificate': False, 'SSLSupportMethod': 'sni-only',
            'ACMCertificateArn': acm}),
        # KNOWN LIMITATION: no ViewerCertificate at all -> the first filter
        # (`CloudFrontDefaultCertificate value: false`) sees None, None == False
        # is False, and the distribution is dropped as compliant.
        distribution('viewercert-absent'),
    ]
    assert matched('cloudfront-tls-policy-not-recommended', resources) == [
        'matches', 'minprotocol-absent']


def test_cloudfront_lambda_url_origin_without_oac():
    lambda_url = 'abcdefghij1234567890.lambda-url.us-east-1.on.aws'
    resources = [
        distribution('matches', Origins={'Quantity': 1, 'Items': [
            custom_origin('lambda', lambda_url)]}),
        distribution('clean', Origins={'Quantity': 1, 'Items': [
            custom_origin('lambda', lambda_url,
                          OriginAccessControlId='E1ABCDEFGHIJKL')]}),
        # the `.lambda-url.` infix is the only thing identifying the origin type
        distribution('not-lambda', Origins={'Quantity': 1, 'Items': [
            custom_origin()]}),
        # guarded out instead of crashing the run
        distribution('origins-absent'),
        distribution('items-absent', Origins={'Quantity': 0}),
    ]
    assert matched('cloudfront-lambda-url-origin-without-oac', resources) == ['matches']

    assert run_policy(POLICIES, 'cloudfront-lambda-url-origin-without-oac',
                      [distribution('origins-absent')]) == []


def test_s3_origin_without_default_root_object_survives_missing_origins():
    """A distribution with no `Origins` used to abort the whole account's run.

    `length(null)` raises JMESPathTypeError, c7n does not catch it, and the
    account writes no results at all, which on a dashboard is indistinguishable
    from an account with nothing wrong. The guard costs one filter and turns a
    lost account into a skipped resource.
    """
    resources = [{'Id': 'no-origins', 'Enabled': True}]
    assert run_policy(
        POLICIES, 'cloudfront-s3-origin-without-default-root-object',
        resources) == []


def test_lambda_url_origin_without_oac_survives_origin_without_domain():
    """Same failure one level down: the guard covers `Origins.Items`, but
    `contains(DomainName, ...)` still received a null for an origin that had
    no DomainName of its own."""
    resources = [{'Id': 'd', 'Origins': {'Items': [{'Id': 'o1'}]}}]
    assert run_policy(
        POLICIES, 'cloudfront-lambda-url-origin-without-oac', resources) == []
