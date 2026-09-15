"""Regression tests for the absent-guard audit fixes.

Offline: no AWS credentials, no network.

An audit of the 89 policies that compare a boolean to `false` found 23
without a guard for the key being entirely absent from the resource dict
(c7n resolves a missing key to `None`, and `None == False` is `False` in
Python, so `value: false` silently reads "AWS never returned this" as
"compliant"). 19 of those 23 were fine on inspection (documented
deliberate, an always-present field, or a jmespath that cannot return
null). This file covers the 5 that were not:

  - kms-cmk-rotation-disabled (policies/aws/kms.yml)
  - rds-sqlserver-instance-not-encrypted-in-transit (policies/aws/rds.yml)
  - rds-mariadb-instance-not-encrypted-in-transit (policies/aws/rds.yml)
  - opensearch-outdated-tls-policy (policies/aws/opensearch.yml)
  - wafv2-rules-without-cloudwatch-metrics-{regional,cloudfront} (policies/aws/waf.yml)

Two of the five (kms rotation, both rds TLS-in-transit policies) need an
AWS session to enumerate through `run_policy` (`key-rotation-status` calls
`kms:GetKeyRotationStatus`, `db-parameter` calls `rds:DescribeDBParameters`),
so those are covered at the match() level instead: the filter is built for
real through c7n (same loader/schema path `c7n_kit.testing._build` uses),
and `.match()` is called directly on the dict c7n would hand it after its
own network call. That's the same principle `run_policy` uses -- exercise
the real c7n object, never a reimplementation of its logic -- just applied
below the point where the module's own session guard would otherwise stop
the test.
"""
from c7n.resources.rds import ParameterFilter
from c7n_kit.testing import _build, _find, run_policy

OPENSEARCH = 'policies/aws/opensearch.yml'
WAF = 'policies/aws/waf.yml'
KMS = 'policies/aws/kms.yml'
RDS = 'policies/aws/rds.yml'


# --------------------------------------------------------- behavioural ---

def test_opensearch_outdated_tls_policy_absent_guard():
    resources = [
        {'DomainName': 'enforce-https-false',
         'DomainEndpointOptions': {
             'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-PFS-2023-10',
             'EnforceHTTPS': False}},
        # DomainEndpointOptions never configured at all
        {'DomainName': 'options-absent'},
        # DomainEndpointOptions present, but EnforceHTTPS itself never set
        {'DomainName': 'enforce-https-key-absent',
         'DomainEndpointOptions': {
             'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-PFS-2023-10'}},
        {'DomainName': 'clean',
         'DomainEndpointOptions': {
             'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-PFS-2023-10',
             'EnforceHTTPS': True}},
    ]
    matched = sorted(
        r['DomainName']
        for r in run_policy(OPENSEARCH, 'opensearch-outdated-tls-policy', resources))
    assert matched == [
        'enforce-https-false', 'enforce-https-key-absent', 'options-absent']


def test_wafv2_rules_without_cloudwatch_metrics_regional():
    resources = [
        # standalone rule, metrics disabled -> reported
        {'Id': 'metrics-disabled', 'Name': 'metrics-disabled', 'ARN': 'arn:x:1',
         'DefaultAction': {'Allow': {}},
         'Rules': [{'Name': 'r1', 'Priority': 0,
                     'VisibilityConfig': {'CloudWatchMetricsEnabled': False}}]},
        # metrics enabled -> clean
        {'Id': 'metrics-enabled', 'Name': 'metrics-enabled', 'ARN': 'arn:x:2',
         'DefaultAction': {'Allow': {}},
         'Rules': [{'Name': 'r1', 'Priority': 0,
                     'VisibilityConfig': {'CloudWatchMetricsEnabled': True}}]},
        # Rules missing entirely -> nothing to report on, not a finding
        {'Id': 'rules-absent', 'Name': 'rules-absent', 'ARN': 'arn:x:3',
         'DefaultAction': {'Allow': {}}},
        # two rules, only one with metrics disabled -> ACL still reported
        {'Id': 'mixed', 'Name': 'mixed', 'ARN': 'arn:x:4',
         'DefaultAction': {'Allow': {}},
         'Rules': [
             {'Name': 'r1', 'Priority': 0,
              'VisibilityConfig': {'CloudWatchMetricsEnabled': True}},
             {'Name': 'r2', 'Priority': 1,
              'VisibilityConfig': {'CloudWatchMetricsEnabled': False}},
         ]},
    ]
    matched = sorted(r['Id'] for r in run_policy(
        WAF, 'wafv2-rules-without-cloudwatch-metrics-regional', resources))
    assert matched == ['metrics-disabled', 'mixed']


# --------------------------------------------------------- match-level ---
# kms-cmk-rotation-disabled and the two rds *-not-encrypted-in-transit
# policies need an AWS session to enumerate (key-rotation-status calls
# kms:GetKeyRotationStatus, db-parameter calls rds:DescribeDBParameters),
# so run_policy can't exercise them end to end offline. Instead: build the
# real policy the same way c7n_kit.testing._build does (same loader, same
# schema validation), pull out the ValueFilter instance, and call .match()
# directly on the dict c7n would hand it after its own network call.

def _last_filter(file, name):
    policy = _build(_find(file, name))
    return policy.resource_manager.filters[-1]


def test_kms_cmk_rotation_disabled_match():
    filt = _last_filter(KMS, 'kms-cmk-rotation-disabled')
    # {} is what a swallowed AccessDenied/UnsupportedOperation leaves behind
    # (KeyRotationStatus.process: r.get('KeyRotationEnabled', {}))
    assert filt.match({}) is True
    assert filt.match({'KeyRotationEnabled': False}) is True
    assert filt.match({'KeyRotationEnabled': True}) is False


def test_rds_sqlserver_not_encrypted_in_transit_match():
    filt = _last_filter(RDS, 'rds-sqlserver-instance-not-encrypted-in-transit')
    # {} is what an untouched default parameter group leaves behind
    # (ParameterFilter.handle_paramgroup_cache drops params with no
    # ParameterValue, which is what an unmodified default looks like)
    assert filt.match({}) is True
    assert filt.match({'rds.force_ssl': False}) is True
    assert filt.match({'rds.force_ssl': True}) is False
    # recast() leaves an unrecognised string like 'OFF' as a string, not a
    # bool -- `ne true` still reports it, `value: false` never would
    assert filt.match({'rds.force_ssl': 'OFF'}) is True


def test_rds_mariadb_not_encrypted_in_transit_match():
    filt = _last_filter(RDS, 'rds-mariadb-instance-not-encrypted-in-transit')
    assert filt.match({}) is True
    assert filt.match({'require_secure_transport': False}) is True
    assert filt.match({'require_secure_transport': True}) is False
    assert filt.match({'require_secure_transport': 'OFF'}) is True


# ------------------------------------------------------------- recast() ---

def test_parameter_filter_recast_boolean():
    assert ParameterFilter.recast('0', 'boolean') is False
    assert ParameterFilter.recast('1', 'boolean') is True
    # AWS/Oracle-style string values ('OFF') that aren't '0'/'1'/'TRUE'/'FALSE'
    # pass through recast() untouched as a string -- this is exactly why
    # `value: false` on a db-parameter filter is not enough: 'OFF' != False,
    # only `op: ne, value: true` catches it.
    assert ParameterFilter.recast('OFF', 'boolean') == 'OFF'
