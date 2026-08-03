"""Behavioural tests for policies/aws/elb.yml.

Offline: no AWS credentials, no network.

Every test asserts the REAL behaviour of the policy as written. Most of this
file's absent-key cases went the OVER-reporting way rather than the usual
under-reporting one (`op: not-equal` and `op: not-in` are both True against a
missing key, and `value_type: size` turns one into 0), so the corrections here
mostly add a `present` / `not-null` guard on the key that DECIDES, and leave
the keys that only SCOPE a rule alone.

Where the escape is deliberate, the fixture says why. Where it was a bug, the
test runs `verify_mutation` to prove the assertion depends on the guard.
"""
import pytest

from c7n_kit.testing import FilterNeedsNetwork, run_policy, verify_mutation

POLICIES = 'policies/aws/elb.yml'


def drop_filter(index):
    """Mutation factory: remove `filters[index]`, i.e. the guard under test."""
    def mutate(policy):
        del policy['filters'][index]
        return policy
    return mutate


def drop_guard_in_and(index):
    """Same, for a guard that lives inside the leading `and` group."""
    def mutate(policy):
        del policy['filters'][0]['and'][index]
        return policy
    return mutate


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
        # DELIBERATE, and left alone: an absent or empty ListenerDescriptions
        # fails the `not-null` guard and is not reported. A load balancer
        # with no listener is not serving anything in the clear, which is
        # what this control measures -- widening it would report a load
        # balancer that has no plaintext listener BECAUSE it has no listener.
        # DescribeLoadBalancers returns ListenerDescriptions for every
        # classic LB (empty list when there are none), so the absent-key
        # variant is not reachable either.
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
        # The correction here runs the OTHER way: with `value_type: size` an
        # absent key resolves to length 0, and 0 < 2 matched, so both of
        # these were reported as single-AZ on missing data. A load balancer
        # cannot live in zero AZs, so the `not-null` guard now excludes them.
        {'LoadBalancerName': 'empty-list', 'AvailabilityZones': []},
        {'LoadBalancerName': 'key-absent'},
    ]

    def expected(matched):
        assert ids(matched) == ['matches']

    expected(run_policy(POLICIES, 'elb-classic-single-az', resources))
    verify_mutation(POLICIES, 'elb-classic-single-az', resources,
                    mutate=drop_filter(0), assertions=expected)


def test_elb_classic_desync_mitigation_not_recommended_needs_the_attributes_call():
    """This one cannot be judged from DescribeLoadBalancers, and now says so.

    The policy used to read `Attributes.AdditionalAttributes[...]` with a
    plain `type: value` filter. DescribeLoadBalancers never returns
    `Attributes` -- they come from DescribeLoadBalancerAttributes -- and
    `op: not-in` against a missing key is True, so it reported EVERY classic
    load balancer, always, on data that was never fetched. No `absent`
    branch fixes that; the data has to be fetched.

    It now uses c7n's `attributes` filter, which makes that call, exactly
    like the ALB sibling. The offline cost is this test: the filter reaches
    for a client before it evaluates anything, so the kit refuses it with
    FilterNeedsNetwork instead of returning a result nobody measured. That
    is the assertion -- a green "no findings" here would be the same lie the
    policy used to tell in the other direction.
    """
    resources = [
        {'LoadBalancerName': 'http-lb',
         'ListenerDescriptions': [listener('HTTP')],
         # Even with the attribute block already in the fixture: the filter
         # builds the client up front, so there is no offline path.
         'Attributes': {'AdditionalAttributes': [
             {'Key': 'elb.http.desyncmitigationmode', 'Value': 'monitor'}]}},
    ]
    with pytest.raises(FilterNeedsNetwork):
        run_policy(POLICIES, 'elb-classic-desync-mitigation-not-recommended',
                   resources)


def test_elb_classic_desync_mitigation_skips_l4_only_load_balancers():
    """The listener guard runs first, and a TCP/SSL-only classic LB never
    reaches the attributes call: it has no HTTP layer to smuggle through.
    That is the same scoping the ALB policy needed (`Type: application`)
    after it matched every NLB on the absent branch alone.
    """
    resources = [
        {'LoadBalancerName': 'tcp-only', 'ListenerDescriptions': [
            listener('TCP', port=3306)]},
        {'LoadBalancerName': 'ssl-only', 'ListenerDescriptions': [
            listener('SSL', ACM_CERT)]},
        {'LoadBalancerName': 'no-listeners', 'ListenerDescriptions': []},
    ]
    # No FilterNeedsNetwork: the guard empties the set before the attributes
    # filter is reached, which is also what keeps the extra API call off the
    # load balancers this control does not apply to.
    assert run_policy(
        POLICIES, 'elb-classic-desync-mitigation-not-recommended', resources) == []


def test_clb_internet_facing():
    resources = [
        {'LoadBalancerName': 'matches', 'Scheme': 'internet-facing'},
        {'LoadBalancerName': 'clean', 'Scheme': 'internal'},
        # `op: not-equal` against an absent key is True, so this used to be
        # inventoried as internet-facing without the field ever arriving.
        # The `present` guard drops it. (Scheme is documented as "valid only
        # for load balancers in a VPC": the absence was real on EC2-Classic,
        # which is retired.)
        {'LoadBalancerName': 'key-absent'},
    ]

    def expected(matched):
        assert ids(matched) == ['matches']

    expected(run_policy(POLICIES, 'clb-internet-facing', resources))
    verify_mutation(POLICIES, 'clb-internet-facing', resources,
                    mutate=drop_guard_in_and(0), assertions=expected)


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
        # Same `value_type: size` coercion as the classic case: an absent key
        # resolved to 0 < 2 and was reported. Excluded by the `not-null`
        # guard now.
        {'LoadBalancerArn': 'arn-key-absent'},
    ]

    def expected(matched):
        assert ids(matched, 'LoadBalancerArn') == ['arn-matches']

    expected(run_policy(POLICIES, 'elbv2-single-az', resources))
    verify_mutation(POLICIES, 'elbv2-single-az', resources,
                    mutate=drop_filter(0), assertions=expected)


def test_alb_and_nlb_internet_facing():
    resources = [
        {'LoadBalancerArn': 'arn-matches', 'Scheme': 'internet-facing',
         'Type': 'application'},
        {'LoadBalancerArn': 'arn-clean', 'Scheme': 'internal', 'Type': 'application'},
        # `op: not-equal` against an absent Scheme is True; the `present`
        # guard is what stops the rule concluding "internet-facing" from a
        # field that never arrived.
        {'LoadBalancerArn': 'arn-key-absent', 'Type': 'network'},
    ]

    def expected(matched):
        assert ids(matched, 'LoadBalancerArn') == ['arn-matches']

    expected(run_policy(POLICIES, 'alb-and-nlb-internet-facing', resources))
    verify_mutation(POLICIES, 'alb-and-nlb-internet-facing', resources,
                    mutate=drop_guard_in_and(0), assertions=expected)


# ----------------------------------------------- aws.app-elb-target-group ---

def test_elbv2_target_group_healthcheck_not_encrypted():
    resources = [
        {'TargetGroupArn': 'arn-matches', 'TargetType': 'instance',
         'HealthCheckProtocol': 'HTTP'},
        {'TargetGroupArn': 'arn-clean', 'TargetType': 'instance',
         'HealthCheckProtocol': 'HTTPS'},
        {'TargetGroupArn': 'arn-lambda-excluded', 'TargetType': 'lambda',
         'HealthCheckProtocol': 'HTTP'},
        # `op: not-equal` is True against a missing key, so this used to be
        # reported for having no health check protocol at all. A Lambda
        # target group with health checks disabled is exactly that shape,
        # and it is the case the control excludes: the `present` guard now
        # requires the deciding key to have arrived.
        {'TargetGroupArn': 'arn-healthcheck-absent', 'TargetType': 'lambda'},
        {'TargetGroupArn': 'arn-key-absent'},
        # TargetType only SCOPES the rule, so it stays unguarded: an HTTP
        # health check is a finding whether or not the type came back.
        {'TargetGroupArn': 'arn-targettype-absent', 'HealthCheckProtocol': 'HTTP'},
    ]

    def expected(matched):
        assert ids(matched, 'TargetGroupArn') == ['arn-matches', 'arn-targettype-absent']

    expected(run_policy(POLICIES, 'elbv2-target-group-healthcheck-not-encrypted',
                        resources))
    verify_mutation(
        POLICIES, 'elbv2-target-group-healthcheck-not-encrypted', resources,
        mutate=drop_filter(1), assertions=expected)


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
        # `not-in` and `not-equal` are both True against a missing key, so
        # these were reported for having no protocol. DescribeTargetGroups
        # returns no Protocol for a Lambda target group AT ALL: the rule was
        # flagging "unencrypted" the target groups with nothing to encrypt.
        {'TargetGroupArn': 'arn-protocol-absent', 'TargetType': 'lambda'},
        {'TargetGroupArn': 'arn-key-absent'},
        # TargetType only scopes the rule; an HTTP protocol is a finding
        # whether or not the type came back.
        {'TargetGroupArn': 'arn-targettype-absent', 'Protocol': 'HTTP'},
    ]

    def expected(matched):
        assert ids(matched, 'TargetGroupArn') == ['arn-matches', 'arn-targettype-absent']

    expected(run_policy(POLICIES, 'elbv2-target-group-protocol-not-encrypted',
                        resources))
    verify_mutation(
        POLICIES, 'elbv2-target-group-protocol-not-encrypted', resources,
        mutate=drop_filter(1), assertions=expected)
