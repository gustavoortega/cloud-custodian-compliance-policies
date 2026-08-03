"""Behavioural tests for policies/aws/apigateway.yml.

Offline: no AWS credentials, no network.

Resource shapes:
  - `aws.rest-stage` -> apigateway:GetStages. Lowercase-camel fields
    (`stageName`, `deploymentId`, `tracingEnabled`, `webAclArn`,
    `clientCertificateId`) and `methodSettings`, a MAP keyed by
    '<resource-path>/<HTTP-METHOD>' with '*/*' as the blanket entry -- which is
    why the policies reach into it with `values(methodSettings)`.
    NOTE `deploymentId` is c7n's id for this type and is NOT unique across
    stages in real accounts (two stages promoted from one deployment share it);
    the fixtures below keep it unique so the `or:`/dedup behaviour does not
    silently swallow a match, which is exactly the trap the policy comments
    describe.
  - `aws.apigwv2-stage` -> apigatewayv2:GetStages. PascalCase (`StageName`,
    `AccessLogSettings`) -- a different API and a different resource type.
  - `aws.apigw-domain-name` -> apigateway:GetDomainNames (`domainName`,
    `securityPolicy`).
  - `rest-api` -> apigateway:GetRestApis (`id`, `name`,
    `endpointConfiguration.types`).

Assertions are SORTED for consistency with the rest of the suite.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/apigateway.yml'


def stage(name, **kw):
    return {
        'stageName': name,
        'deploymentId': f'dep-{name}',
        'restApiId': 'abc123defg',
        'createdDate': '2024-01-01T00:00:00Z',
        'cacheClusterEnabled': False,
        **kw,
    }


def method_setting(**kw):
    return {'metricsEnabled': False, 'dataTraceEnabled': False, **kw}


def matched(policy, resources, key):
    return sorted(r[key] for r in run_policy(POLICIES, policy, resources))


def test_apigw_rest_stage_execution_logging_disabled():
    resources = [
        stage('off', methodSettings={'*/*': method_setting(loggingLevel='OFF')}),
        stage('error', methodSettings={'*/*': method_setting(loggingLevel='ERROR')}),
        # a per-path override with INFO is enough to clear the control
        stage('per-path-info', methodSettings={
            '*/*': method_setting(loggingLevel='OFF'),
            '~1orders/GET': method_setting(loggingLevel='INFO')}),
        # no method settings configured at all
        stage('empty-methodsettings', methodSettings={}),
        stage('no-logginglevel', methodSettings={'*/*': method_setting()}),
        # `methodSettings` missing entirely: the `value: present` guard drops it
        # BEFORE values(null) can raise and abort the whole invocation. The
        # stage is not reported -- its logging state is unknown, not verified.
        stage('methodsettings-absent'),
    ]
    assert matched('apigw-rest-stage-execution-logging-disabled', resources,
                   'stageName') == ['empty-methodsettings', 'no-logginglevel', 'off']

    # and on its own it is a non-match, not an exception
    assert run_policy(POLICIES, 'apigw-rest-stage-execution-logging-disabled',
                      [stage('methodsettings-absent')]) == []


def test_apigw_rest_stage_without_client_certificate():
    resources = [
        # `value: absent` IS the match condition here
        stage('matches'),
        stage('clean', clientCertificateId='abc123'),
    ]
    assert matched('apigw-rest-stage-without-client-certificate', resources,
                   'stageName') == ['matches']


def test_apigw_rest_stage_xray_tracing_disabled():
    resources = [
        stage('matches', tracingEnabled=False),
        stage('clean', tracingEnabled=True),
        # a single `value: empty` (not an `or:` pair, deliberately -- see the
        # policy description on deploymentId dedup) also matches the missing key
        stage('key-absent'),
    ]
    assert matched('apigw-rest-stage-xray-tracing-disabled', resources,
                   'stageName') == ['key-absent', 'matches']


def test_apigw_rest_stage_without_waf():
    resources = [
        stage('empty-string', webAclArn=''),
        stage('clean', webAclArn='arn:aws:wafv2:us-east-1:111111111111:regional/'
                                 'webacl/prod/12345678-1234-1234-1234-123456789012'),
        # `value: empty` matches the missing key too
        stage('key-absent'),
    ]
    assert matched('apigw-rest-stage-without-waf', resources, 'stageName') == [
        'empty-string', 'key-absent']


def test_apigw_rest_stage_cache_not_encrypted():
    resources = [
        stage('matches', methodSettings={
            '*/*': method_setting(cachingEnabled=True, cacheDataEncrypted=False)}),
        stage('clean', methodSettings={
            '*/*': method_setting(cachingEnabled=True, cacheDataEncrypted=True)}),
        stage('caching-off', methodSettings={
            '*/*': method_setting(cachingEnabled=False, cacheDataEncrypted=False)}),
        # caching turned on by a per-path override rather than the blanket entry
        stage('per-path', methodSettings={
            '*/*': method_setting(cachingEnabled=False),
            '~1orders/GET': method_setting(cachingEnabled=True,
                                           cacheDataEncrypted=False)}),
        stage('empty-methodsettings', methodSettings={}),
        # same `value: present` guard: no crash, and no report either
        stage('methodsettings-absent'),
    ]
    assert matched('apigw-rest-stage-cache-not-encrypted', resources,
                   'stageName') == ['matches', 'per-path']

    assert run_policy(POLICIES, 'apigw-rest-stage-cache-not-encrypted',
                      [stage('methodsettings-absent')]) == []


def test_apigwv2_stage_access_logging_disabled():
    resources = [
        # `value: absent` IS the match condition
        {'StageName': 'matches', 'ApiId': 'a1b2c3d4e5', 'AutoDeploy': True},
        {'StageName': 'clean', 'ApiId': 'f6g7h8i9j0', 'AccessLogSettings': {
            'DestinationArn':
                'arn:aws:logs:us-east-1:111111111111:log-group:/aws/apigw/http',
            'Format': '$context.requestId'}},
    ]
    assert matched('apigwv2-stage-access-logging-disabled', resources,
                   'StageName') == ['matches']


def test_apigw_domain_name_tls_policy_not_recommended():
    resources = [
        {'domainName': 'matches', 'securityPolicy': 'TLS_1_2',
         'endpointConfiguration': {'types': ['REGIONAL']}},
        {'domainName': 'clean', 'securityPolicy': 'SecurityPolicy_TLS13_1_3_2025_09',
         'endpointConfiguration': {'types': ['REGIONAL']}},
        # the EDGE spelling of an accepted policy
        {'domainName': 'clean-edge', 'securityPolicy': 'SecurityPolicy_TLS13_2025_EDGE',
         'endpointConfiguration': {'types': ['EDGE']}},
        # `op: not-in` on an absent key matches (None is not in the list), so a
        # domain name with no securityPolicy is reported -- the safe direction
        {'domainName': 'key-absent',
         'endpointConfiguration': {'types': ['REGIONAL']}},
    ]
    assert matched('apigw-domain-name-tls-policy-not-recommended', resources,
                   'domainName') == ['key-absent', 'matches']


def test_api_gateway_internet_facing():
    resources = [
        {'id': 'edge', 'name': 'edge-api',
         'endpointConfiguration': {'types': ['EDGE']}},
        {'id': 'regional', 'name': 'regional-api',
         'endpointConfiguration': {'types': ['REGIONAL']}},
        {'id': 'private', 'name': 'private-api',
         'endpointConfiguration': {'types': ['PRIVATE']}},
        # the `value: present` guard drops an API with no endpointConfiguration
        # before the not-equal test, so an absent key is NOT reported
        {'id': 'key-absent', 'name': 'no-endpoint-config'},
    ]
    assert matched('api-gateway-internet-facing', resources, 'id') == [
        'edge', 'regional']
