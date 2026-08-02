"""Behavioural tests for policies/aws/elb.yml.

Offline: no AWS credentials, no network.

Every test asserts the REAL behaviour of the policy as written, including the
cases where a resource that is missing the key escapes the filter (or, in a
couple of these, is over-reported because of it). Those are marked with a
`# KNOWN LIMITATION` comment. Nothing here fixes a policy.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/elb.yml'


def ids(matched, key='LoadBalancerName'):
    """Matched identifiers in the order c7n returned them.

    Valid for a flat `and` chain of value filters and for c7n's `and` group,
    both of which preserve the input order (only `or` / `not` go through a
    set -- see `sids`).
    """
    return [r[key] for r in matched]


def listener(protocol, cert=None, policy_names=None, port=None):
    """One entry of a classic ELB's `ListenerDescriptions`."""
    ssl = protocol in ('HTTPS', 'SSL')
    desc = {
        'Protocol': protocol,
        'LoadBalancerPort': port if port is not None else (443 if ssl else 80),
        'InstanceProtocol': 'HTTP',
        'InstancePort': 80,
    }
    if cert:
        desc['SSLCertificateId'] = cert
    return {'Listener': desc, 'PolicyNames': policy_names or []}


ACM_CERT = 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555'
IAM_CERT = 'arn:aws:iam::123456789012:server-certificate/legacy-cert'


# ---------------------------------------------------------------- aws.elb ---

def test_elb_classic_ssl_listener_non_acm_cert():
    resources = [
        {'LoadBalancerName': 'matches', 'ListenerDescriptions': [listener('HTTPS', IAM_CERT)]},
        {'LoadBalancerName': 'clean', 'ListenerDescriptions': [listener('HTTPS', ACM_CERT)]},
        {'LoadBalancerName': 'http-only', 'ListenerDescriptions': [listener('HTTP')]},
        # An absent ListenerDescriptions makes the first `not-null` guard
        # fail, so the load balancer is not reported.
        {'LoadBalancerName': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'elb-classic-ssl-listener-non-acm-cert', resources))
    assert matched == ['matches']


def test_elb_classic_listener_not_tls():
    resources = [
        {'LoadBalancerName': 'matches', 'ListenerDescriptions': [listener('HTTP')]},
        {'LoadBalancerName': 'matches-mixed', 'ListenerDescriptions': [
            listener('HTTPS', ACM_CERT), listener('HTTP')]},
        {'LoadBalancerName': 'clean', 'ListenerDescriptions': [listener('HTTPS', ACM_CERT)]},
        {'LoadBalancerName': 'clean-ssl', 'ListenerDescriptions': [listener('SSL', ACM_CERT)]},
        # KNOWN LIMITATION: an absent (or empty) ListenerDescriptions fails
        # the first `not-null` guard, so a load balancer whose listeners
        # never came back is reported as compliant.
        {'LoadBalancerName': 'empty-listeners', 'ListenerDescriptions': []},
        {'LoadBalancerName': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'elb-classic-listener-not-tls', resources))
    assert matched == ['matches', 'matches-mixed']


def test_elb_classic_ssl_policy_not_recommended():
    resources = [
        {'LoadBalancerName': 'matches', 'ListenerDescriptions': [
            listener('HTTPS', ACM_CERT, ['ELBSecurityPolicy-2016-08'])]},
        {'LoadBalancerName': 'matches-no-policy', 'ListenerDescriptions': [
            listener('HTTPS', ACM_CERT, [])]},
        {'LoadBalancerName': 'clean', 'ListenerDescriptions': [
            listener('HTTPS', ACM_CERT, ['ELBSecurityPolicy-TLS-1-2-2017-01'])]},
        {'LoadBalancerName': 'http-only', 'ListenerDescriptions': [listener('HTTP')]},
        # An absent ListenerDescriptions fails the first `not-null` guard.
        {'LoadBalancerName': 'key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'elb-classic-ssl-policy-not-recommended', resources))
    assert matched == ['matches', 'matches-no-policy']


def test_elb_classic_single_az():
    resources = [
        {'LoadBalancerName': 'matches', 'AvailabilityZones': ['us-east-1a']},
        {'LoadBalancerName': 'clean', 'AvailabilityZones': ['us-east-1a', 'us-east-1b']},
        # KNOWN LIMITATION (over-reporting, not under-reporting): with
        # `value_type: size` an absent key resolves to size 0, and 0 < 2 is
        # True, so a load balancer whose AvailabilityZones never came back
        # is reported as single-AZ. The empty list behaves the same way.
        {'LoadBalancerName': 'empty-list-matches', 'AvailabilityZones': []},
        {'LoadBalancerName': 'key-absent-matches'},
    ]
    matched = ids(run_policy(POLICIES, 'elb-classic-single-az', resources))
    assert matched == ['matches', 'empty-list-matches', 'key-absent-matches']


def test_elb_classic_desync_mitigation_not_recommended():
    def attrs(mode):
        return {'Attributes': {'AdditionalAttributes': [
            {'Key': 'elb.http.desyncmitigationmode', 'Value': mode}]}}

    resources = [
        dict({'LoadBalancerName': 'matches'}, **attrs('monitor')),
        dict({'LoadBalancerName': 'clean-defensive'}, **attrs('defensive')),
        dict({'LoadBalancerName': 'clean-strictest'}, **attrs('strictest')),
        # KNOWN LIMITATION (over-reporting): `op: not-in` against an absent
        # key is True (None is in no list), so every load balancer whose
        # Attributes block is missing is reported. DescribeLoadBalancers
        # does not return Attributes at all -- they come from a separate
        # DescribeLoadBalancerAttributes call -- so in a real run this
        # filter flags classic ELBs on missing data rather than on a bad
        # desync mode.
        {'LoadBalancerName': 'attributes-absent-matches'},
    ]
    matched = ids(run_policy(
        POLICIES, 'elb-classic-desync-mitigation-not-recommended', resources))
    assert matched == ['matches', 'attributes-absent-matches']


def test_clb_internet_facing():
    resources = [
        {'LoadBalancerName': 'matches', 'Scheme': 'internet-facing'},
        {'LoadBalancerName': 'clean', 'Scheme': 'internal'},
        # KNOWN LIMITATION (over-reporting): `op: not-equal` against an
        # absent key is True, so a load balancer whose Scheme never came
        # back is reported as internet-facing.
        {'LoadBalancerName': 'key-absent-matches'},
    ]
    matched = ids(run_policy(POLICIES, 'clb-internet-facing', resources))
    assert matched == ['matches', 'key-absent-matches']


def test_inventory_clb_with_tls():
    resources = [
        {'LoadBalancerName': 'matches-https', 'ListenerDescriptions': [
            listener('HTTPS', ACM_CERT)]},
        {'LoadBalancerName': 'matches-ssl', 'ListenerDescriptions': [
            listener('SSL', ACM_CERT)]},
        {'LoadBalancerName': 'clean-http', 'ListenerDescriptions': [listener('HTTP')]},
        # The `is-ssl` filter indexes ListenerDescriptions directly and
        # raises KeyError when it is absent, so the key-absent case is not
        # reachable for this policy. An empty list is the real-world
        # equivalent and is not reported.
        {'LoadBalancerName': 'empty-listeners', 'ListenerDescriptions': []},
    ]
    matched = ids(run_policy(POLICIES, 'inventory-clb-with-tls', resources))
    assert matched == ['matches-https', 'matches-ssl']


# ------------------------------------------------------------ aws.app-elb ---

def test_elbv2_single_az():
    def az(*names):
        return [{'ZoneName': n, 'SubnetId': 'subnet-%s' % n} for n in names]

    resources = [
        {'LoadBalancerArn': 'arn-matches', 'AvailabilityZones': az('us-east-1a')},
        {'LoadBalancerArn': 'arn-clean',
         'AvailabilityZones': az('us-east-1a', 'us-east-1b')},
        # KNOWN LIMITATION (over-reporting): same `value_type: size`
        # coercion as the classic case, an absent key resolves to 0 < 2.
        {'LoadBalancerArn': 'arn-key-absent-matches'},
    ]
    matched = ids(run_policy(POLICIES, 'elbv2-single-az', resources), 'LoadBalancerArn')
    assert matched == ['arn-matches', 'arn-key-absent-matches']


def test_alb_and_nlb_internet_facing():
    resources = [
        {'LoadBalancerArn': 'arn-matches', 'Scheme': 'internet-facing',
         'Type': 'application'},
        {'LoadBalancerArn': 'arn-clean', 'Scheme': 'internal', 'Type': 'application'},
        # KNOWN LIMITATION (over-reporting): `op: not-equal` against an
        # absent Scheme is True.
        {'LoadBalancerArn': 'arn-key-absent-matches', 'Type': 'network'},
    ]
    matched = ids(run_policy(POLICIES, 'alb-and-nlb-internet-facing', resources),
                  'LoadBalancerArn')
    assert matched == ['arn-matches', 'arn-key-absent-matches']


# ----------------------------------------------- aws.app-elb-target-group ---

def test_elbv2_target_group_healthcheck_not_encrypted():
    resources = [
        {'TargetGroupArn': 'arn-matches', 'TargetType': 'instance',
         'HealthCheckProtocol': 'HTTP'},
        {'TargetGroupArn': 'arn-clean', 'TargetType': 'instance',
         'HealthCheckProtocol': 'HTTPS'},
        {'TargetGroupArn': 'arn-lambda-excluded', 'TargetType': 'lambda',
         'HealthCheckProtocol': 'HTTP'},
        # KNOWN LIMITATION (over-reporting): both filters use `op:
        # not-equal`, and None never equals anything, so a target group
        # missing both keys is reported on missing data.
        {'TargetGroupArn': 'arn-key-absent-matches'},
    ]
    matched = ids(run_policy(
        POLICIES, 'elbv2-target-group-healthcheck-not-encrypted', resources),
        'TargetGroupArn')
    assert matched == ['arn-matches', 'arn-key-absent-matches']


def test_elbv2_target_group_protocol_not_encrypted():
    resources = [
        {'TargetGroupArn': 'arn-matches', 'TargetType': 'instance', 'Protocol': 'HTTP'},
        {'TargetGroupArn': 'arn-clean-https', 'TargetType': 'instance',
         'Protocol': 'HTTPS'},
        {'TargetGroupArn': 'arn-clean-tls', 'TargetType': 'ip', 'Protocol': 'TLS'},
        {'TargetGroupArn': 'arn-lambda-excluded', 'TargetType': 'lambda',
         'Protocol': 'HTTP'},
        {'TargetGroupArn': 'arn-alb-excluded', 'TargetType': 'alb', 'Protocol': 'HTTP'},
        {'TargetGroupArn': 'arn-geneve-excluded', 'TargetType': 'instance',
         'Protocol': 'GENEVE'},
        # KNOWN LIMITATION (over-reporting): `not-in` / `not-equal` against
        # absent keys are all True, so a target group missing both keys is
        # reported on missing data.
        {'TargetGroupArn': 'arn-key-absent-matches'},
    ]
    matched = ids(run_policy(
        POLICIES, 'elbv2-target-group-protocol-not-encrypted', resources),
        'TargetGroupArn')
    assert matched == ['arn-matches', 'arn-key-absent-matches']
