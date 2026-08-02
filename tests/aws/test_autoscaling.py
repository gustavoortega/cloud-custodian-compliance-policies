"""Behavioural tests for policies/aws/autoscaling.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/autoscaling.yml'


def test_asg_elb_health_check_not_used():
    resources = [
        {'AutoScalingGroupName': 'matches', 'LoadBalancerNames': ['classic-lb'],
         'TargetGroupARNs': [], 'HealthCheckType': 'EC2',
         'AvailabilityZones': ['us-east-1a']},
        {'AutoScalingGroupName': 'clean-elb-hc', 'LoadBalancerNames': [],
         'TargetGroupARNs': ['arn:aws:elasticloadbalancing:::targetgroup/tg/1'],
         'HealthCheckType': 'ELB', 'AvailabilityZones': ['us-east-1a']},
        # no LB and no target group: out of the control's scope
        {'AutoScalingGroupName': 'clean-no-lb', 'LoadBalancerNames': [],
         'TargetGroupARNs': [], 'HealthCheckType': 'EC2',
         'AvailabilityZones': ['us-east-1a']},
        # HealthCheckType absent: `op: ne ELB` on None is True, so the ASG
        # IS captured once the LB gate passes. Absence is caught here.
        {'AutoScalingGroupName': 'key-absent',
         'TargetGroupARNs': ['arn:aws:elasticloadbalancing:::targetgroup/tg/2'],
         'AvailabilityZones': ['us-east-1a']},
    ]
    # the leading `or` resolves via set union; sort before asserting.
    matched = sorted(r['AutoScalingGroupName'] for r in run_policy(
        POLICIES, 'asg-elb-health-check-not-used', resources))
    assert matched == ['key-absent', 'matches']


def test_asg_single_availability_zone():
    resources = [
        {'AutoScalingGroupName': 'matches', 'AvailabilityZones': ['us-east-1a']},
        {'AutoScalingGroupName': 'clean',
         'AvailabilityZones': ['us-east-1a', 'us-east-1b']},
        # AvailabilityZones absent: `value_type: size` on None resolves to 0,
        # which is < 2, so the ASG IS captured. Absence is caught here.
        {'AutoScalingGroupName': 'key-absent'},
    ]
    matched = [r['AutoScalingGroupName'] for r in run_policy(
        POLICIES, 'asg-single-availability-zone', resources)]
    assert matched == ['matches', 'key-absent']


def test_asg_single_instance_type_single_az():
    mixed = {'LaunchTemplate': {'Overrides': [{'InstanceType': 'm5.large'},
                                              {'InstanceType': 'm6i.large'}]}}
    resources = [
        # spans 2 AZs but pins a single instance type
        {'AutoScalingGroupName': 'matches-one-type',
         'AvailabilityZones': ['us-east-1a', 'us-east-1b']},
        # mixed instance types but a single AZ
        {'AutoScalingGroupName': 'matches-one-az',
         'AvailabilityZones': ['us-east-1a'], 'MixedInstancesPolicy': mixed},
        # both keys absent: captured, because the `not` wrapper turns each
        # failed positive assertion into a match.
        {'AutoScalingGroupName': 'key-absent'},
        {'AutoScalingGroupName': 'clean',
         'AvailabilityZones': ['us-east-1a', 'us-east-1b'],
         'MixedInstancesPolicy': mixed},
    ]
    # `not` resolves via set difference; sort before asserting.
    matched = sorted(r['AutoScalingGroupName'] for r in run_policy(
        POLICIES, 'asg-single-instance-type-single-az', resources))
    assert matched == ['key-absent', 'matches-one-az', 'matches-one-type']


def test_asg_not_using_launch_template():
    resources = [
        # KEY-ABSENT CASE AND THE MATCH ARE THE SAME THING HERE: the policy
        # is built out of two `value: absent` checks, so the ASG created from
        # a deprecated Launch Configuration -- which has neither key -- is
        # exactly what it reports.
        {'AutoScalingGroupName': 'matches', 'LaunchConfigurationName': 'lc-legacy'},
        {'AutoScalingGroupName': 'clean-launch-template',
         'LaunchTemplate': {'LaunchTemplateId': 'lt-1',
                            'LaunchTemplateName': 'app', 'Version': '3'}},
        {'AutoScalingGroupName': 'clean-mixed-instances',
         'MixedInstancesPolicy': {'LaunchTemplate': {
             'LaunchTemplateSpecification': {'LaunchTemplateId': 'lt-2',
                                             'Version': '$Latest'}}}},
    ]
    matched = [r['AutoScalingGroupName'] for r in run_policy(
        POLICIES, 'asg-not-using-launch-template', resources)]
    assert matched == ['matches']
