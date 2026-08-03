"""Behavioural tests for policies/aws/ec2.yml.

Offline: no AWS credentials, no network.

Every test asserts the REAL behaviour of the policy as written, including the
cases where a resource that is missing the key escapes the filter. Those are
marked with a `# KNOWN LIMITATION` comment. Nothing here fixes a policy.
"""
from datetime import datetime, timedelta, timezone

from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/ec2.yml'


def ids(matched, key='InstanceId'):
    """Matched identifiers in the order c7n returned them.

    Only valid for a flat `and` chain of value filters, which preserves the
    input order.
    """
    return [r[key] for r in matched]


def sids(matched, key='InstanceId'):
    """Matched identifiers, sorted.

    c7n's `or` and `not` filters union their branches through a Python `set`
    (c7n/filters/core.py, `Or.process_set` / `Not.process_set`), so the order
    they return is the set's iteration order, not the input order, and it
    varies with PYTHONHASHSEED between runs. For any policy that contains a
    boolean group, the identifier SET is the observable behaviour.
    """
    return sorted(r[key] for r in matched)


def sg(group_id, permissions):
    """A DescribeSecurityGroups-shaped group.

    `IpPermissions` is never omitted: c7n's `ingress` filter indexes it
    directly and raises KeyError if it is absent, so the "key absent" case
    is not reachable for these policies (an empty list is the real-world
    equivalent AWS returns).
    """
    return {
        'GroupId': group_id,
        'GroupName': group_id,
        'OwnerId': '123456789012',
        'VpcId': 'vpc-0a1b2c3d',
        'IpPermissions': permissions,
        'IpPermissionsEgress': [],
    }


def perm(protocol, from_port=None, to_port=None, cidr=None, cidr_v6=None):
    """One entry of `IpPermissions`."""
    p = {
        'IpProtocol': protocol,
        'IpRanges': [{'CidrIp': cidr}] if cidr else [],
        'Ipv6Ranges': [{'CidrIpv6': cidr_v6}] if cidr_v6 else [],
        'UserIdGroupPairs': [],
        'PrefixListIds': [],
    }
    if from_port is not None:
        p['FromPort'] = from_port
        p['ToPort'] = to_port if to_port is not None else from_port
    return p


def stopped_since(days):
    """`StateTransitionReason` as EC2 formats it, N days in the past."""
    when = datetime.now(timezone.utc) - timedelta(days=days)
    return 'User initiated (%s GMT)' % when.strftime('%Y-%m-%d %H:%M:%S')


# ---------------------------------------------------------------- aws.ec2 ---

def test_ec2_internet_facing_instance_profile_with_imdsv1():
    resources = [
        {'InstanceId': 'i-matches', 'State': {'Name': 'running'},
         'PublicIpAddress': '203.0.113.10',
         'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/app',
                                'Id': 'AIPAEXAMPLE'},
         'MetadataOptions': {'HttpTokens': 'optional', 'HttpEndpoint': 'enabled'}},
        {'InstanceId': 'i-clean-imdsv2', 'State': {'Name': 'running'},
         'PublicIpAddress': '203.0.113.11',
         'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/app',
                                'Id': 'AIPAEXAMPLE'},
         'MetadataOptions': {'HttpTokens': 'required', 'HttpEndpoint': 'enabled'}},
        {'InstanceId': 'i-no-public-ip', 'State': {'Name': 'running'},
         'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/app',
                                'Id': 'AIPAEXAMPLE'},
         'MetadataOptions': {'HttpTokens': 'optional'}},
        {'InstanceId': 'i-no-profile', 'State': {'Name': 'running'},
         'PublicIpAddress': '203.0.113.12',
         'MetadataOptions': {'HttpTokens': 'optional'}},
        {'InstanceId': 'i-stopped', 'State': {'Name': 'stopped'},
         'PublicIpAddress': '203.0.113.13',
         'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/app',
                                'Id': 'AIPAEXAMPLE'},
         'MetadataOptions': {'HttpTokens': 'optional'}},
        # KNOWN LIMITATION: an instance whose MetadataOptions block never came
        # back reads as compliant (None == 'optional' is False).
        {'InstanceId': 'i-metadata-absent', 'State': {'Name': 'running'},
         'PublicIpAddress': '203.0.113.14',
         'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/app',
                                'Id': 'AIPAEXAMPLE'}},
    ]
    matched = ids(run_policy(
        POLICIES, 'ec2-internet-facing-instance-profile-with-imdsv1', resources))
    assert matched == ['i-matches']


def test_ec2_imdsv2_not_enforced():
    resources = [
        {'InstanceId': 'i-matches', 'State': {'Name': 'running'},
         'MetadataOptions': {'HttpTokens': 'optional', 'HttpEndpoint': 'enabled'}},
        {'InstanceId': 'i-clean', 'State': {'Name': 'running'},
         'MetadataOptions': {'HttpTokens': 'required', 'HttpEndpoint': 'enabled'}},
        {'InstanceId': 'i-stopped', 'State': {'Name': 'stopped'},
         'MetadataOptions': {'HttpTokens': 'optional'}},
        # KNOWN LIMITATION: MetadataOptions absent reads as compliant.
        {'InstanceId': 'i-metadata-absent', 'State': {'Name': 'running'}},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-imdsv2-not-enforced', resources))
    assert matched == ['i-matches']


def test_ec2_stopped_instance_not_removed():
    resources = [
        {'InstanceId': 'i-matches', 'State': {'Name': 'stopped'},
         'StateTransitionReason': stopped_since(120)},
        {'InstanceId': 'i-recently-stopped', 'State': {'Name': 'stopped'},
         'StateTransitionReason': stopped_since(5)},
        {'InstanceId': 'i-running', 'State': {'Name': 'running'},
         'StateTransitionReason': ''},
        # A stopped instance with no StateTransitionReason has no parseable
        # date, so `state-age` cannot age it and it is never reported.
        {'InstanceId': 'i-reason-absent', 'State': {'Name': 'stopped'}},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-stopped-instance-not-removed', resources))
    assert matched == ['i-matches']


def test_ec2_instance_multiple_enis():
    resources = [
        {'InstanceId': 'i-matches', 'NetworkInterfaces': [
            {'NetworkInterfaceId': 'eni-1'}, {'NetworkInterfaceId': 'eni-2'}]},
        {'InstanceId': 'i-clean', 'NetworkInterfaces': [{'NetworkInterfaceId': 'eni-1'}]},
        # `value_type: size` over an absent key resolves to size 0, and
        # 0 > 1 is False, so the instance is not reported. (Note the sign
        # matters: the same coercion makes an absent key MATCH a
        # `size less-than` filter -- see test_elb_classic_single_az.)
        {'InstanceId': 'i-key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-instance-multiple-enis', resources))
    assert matched == ['i-matches']


def test_ec2_paravirtual_instance_type():
    resources = [
        {'InstanceId': 'i-matches', 'VirtualizationType': 'paravirtual'},
        {'InstanceId': 'i-clean', 'VirtualizationType': 'hvm'},
        # An absent VirtualizationType is not reported.
        {'InstanceId': 'i-key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-paravirtual-instance-type', resources))
    assert matched == ['i-matches']


def test_ec2_instances_with_public_ip():
    resources = [
        {'InstanceId': 'i-matches', 'PublicIpAddress': '203.0.113.10',
         'State': {'Name': 'running'}},
        {'InstanceId': 'i-stopped', 'PublicIpAddress': '203.0.113.11',
         'State': {'Name': 'stopped'}},
        # An explicit null and an absent key behave identically here: the
        # filter is `not-equal: null`, and None != None is False.
        {'InstanceId': 'i-explicit-null', 'PublicIpAddress': None,
         'State': {'Name': 'running'}},
        {'InstanceId': 'i-key-absent', 'State': {'Name': 'running'}},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-instances-with-public-ip', resources))
    assert matched == ['i-matches']


# ---------------------------------------------------------------- aws.ami ---

def test_ec2_ami_public():
    resources = [
        {'ImageId': 'ami-matches', 'Public': True},
        {'ImageId': 'ami-clean', 'Public': False},
        # `value: true` over an absent key does not match: an image whose
        # Public flag never came back is not inventoried as public.
        {'ImageId': 'ami-key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'ec2-ami-public', resources), 'ImageId')
    assert matched == ['ami-matches']


# ---------------------------------------------------------------- aws.ebs ---

def test_ebs_volume_unencrypted():
    resources = [
        {'VolumeId': 'vol-matches', 'Encrypted': False},
        {'VolumeId': 'vol-clean', 'Encrypted': True},
        # This policy DOES carry the `absent` branch, so the key-less volume
        # is correctly caught.
        {'VolumeId': 'vol-key-absent'},
    ]
    matched = sids(run_policy(POLICIES, 'ebs-volume-unencrypted', resources), 'VolumeId')
    assert matched == ['vol-key-absent', 'vol-matches']


# ------------------------------------------------------- aws.security-group ---

def test_inventory_security_group_sensitive_port_open():
    resources = [
        sg('sg-matches-ipv4', [perm('tcp', 22, 22, cidr='0.0.0.0/0')]),
        sg('sg-matches-ipv6', [perm('tcp', 3306, 3306, cidr_v6='::/0')]),
        sg('sg-matches-range', [perm('tcp', 1, 65535, cidr='0.0.0.0/0')]),
        sg('sg-clean-https', [perm('tcp', 443, 443, cidr='0.0.0.0/0')]),
        sg('sg-clean-internal', [perm('tcp', 22, 22, cidr='10.0.0.0/8')]),
        sg('sg-no-permissions', []),
    ]
    matched = sids(run_policy(
        POLICIES, 'inventory-security-group-sensitive-port-open', resources), 'GroupId')
    assert matched == ['sg-matches-ipv4', 'sg-matches-ipv6', 'sg-matches-range']


def test_security_group_unrestricted_ingress_ports():
    resources = [
        sg('sg-matches-ipv4', [perm('tcp', 22, 22, cidr='0.0.0.0/0')]),
        sg('sg-matches-ipv6', [perm('tcp', 443, 443, cidr_v6='::/0')]),
        sg('sg-clean-internal', [perm('tcp', 22, 22, cidr='10.0.0.0/8')]),
        sg('sg-no-permissions', []),
    ]
    matched = sids(run_policy(
        POLICIES, 'security-group-unrestricted-ingress-ports', resources), 'GroupId')
    assert matched == ['sg-matches-ipv4', 'sg-matches-ipv6']


def test_security_group_unauthorized_port_open_to_internet():
    resources = [
        sg('sg-matches-ssh', [perm('tcp', 22, 22, cidr='0.0.0.0/0')]),
        sg('sg-matches-udp', [perm('udp', 53, 53, cidr='0.0.0.0/0')]),
        sg('sg-matches-all-protocols', [perm('-1', cidr='0.0.0.0/0')]),
        sg('sg-matches-ipv6-ssh', [perm('tcp', 22, 22, cidr_v6='::/0')]),
        sg('sg-clean-http', [perm('tcp', 80, 80, cidr='0.0.0.0/0')]),
        sg('sg-clean-https', [perm('tcp', 443, 443, cidr='0.0.0.0/0')]),
        sg('sg-clean-internal-ssh', [perm('tcp', 22, 22, cidr='10.0.0.0/8')]),
        sg('sg-no-permissions', []),
    ]
    matched = sids(run_policy(
        POLICIES, 'security-group-unauthorized-port-open-to-internet', resources), 'GroupId')
    assert matched == ['sg-matches-all-protocols', 'sg-matches-ipv6-ssh',
                       'sg-matches-ssh', 'sg-matches-udp']


# ------------------------------------------------------------- aws.subnet ---

def test_subnet_auto_assigns_public_ip_non_default_vpc():
    resources = [
        {'SubnetId': 'subnet-matches', 'MapPublicIpOnLaunch': True, 'DefaultForAz': False},
        {'SubnetId': 'subnet-clean', 'MapPublicIpOnLaunch': False, 'DefaultForAz': False},
        {'SubnetId': 'subnet-default-az', 'MapPublicIpOnLaunch': True, 'DefaultForAz': True},
        # KNOWN LIMITATION: `DefaultForAz` absent does not satisfy the
        # `value: false` guard, so a subnet missing that key escapes even
        # though it auto-assigns public IPs.
        {'SubnetId': 'subnet-defaultforaz-absent', 'MapPublicIpOnLaunch': True},
    ]
    matched = ids(run_policy(
        POLICIES, 'subnet-auto-assigns-public-ip-non-default-vpc', resources), 'SubnetId')
    assert matched == ['subnet-matches']


# -------------------------------------------------------- aws.network-acl ---

def test_nacl_unused_non_default():
    resources = [
        {'NetworkAclId': 'acl-matches', 'Associations': [], 'IsDefault': False},
        {'NetworkAclId': 'acl-clean-associated', 'IsDefault': False, 'Associations': [
            {'NetworkAclAssociationId': 'aclassoc-1', 'SubnetId': 'subnet-1'}]},
        {'NetworkAclId': 'acl-default', 'Associations': [], 'IsDefault': True},
        # `Associations` absent is not equal to the empty list, so it escapes.
        {'NetworkAclId': 'acl-associations-absent', 'IsDefault': False},
        # KNOWN LIMITATION: `IsDefault` absent does not satisfy `value: false`.
        {'NetworkAclId': 'acl-isdefault-absent', 'Associations': []},
    ]
    matched = ids(run_policy(POLICIES, 'nacl-unused-non-default', resources), 'NetworkAclId')
    assert matched == ['acl-matches']


# ---------------------------------------------------- aws.transit-gateway ---

def test_transit_gateway_auto_accepts_shared_attachments():
    resources = [
        {'TransitGatewayId': 'tgw-matches',
         'Options': {'AutoAcceptSharedAttachments': 'enable'}},
        {'TransitGatewayId': 'tgw-clean',
         'Options': {'AutoAcceptSharedAttachments': 'disable'}},
        # An absent Options block is not reported.
        {'TransitGatewayId': 'tgw-key-absent'},
    ]
    matched = ids(run_policy(
        POLICIES, 'transit-gateway-auto-accepts-shared-attachments', resources),
        'TransitGatewayId')
    assert matched == ['tgw-matches']


# ---------------------------------------------------- aws.vpn-connection ---

def test_vpn_tunnel_logging_disabled():
    resources = [
        {'VpnConnectionId': 'vpn-matches', 'Options': {'TunnelOptions': [
            {'OutsideIpAddress': '203.0.113.1',
             'LogOptions': {'CloudWatchLogOptions': {'LogEnabled': False}}},
            {'OutsideIpAddress': '203.0.113.2',
             'LogOptions': {'CloudWatchLogOptions': {'LogEnabled': True}}}]}},
        {'VpnConnectionId': 'vpn-clean', 'Options': {'TunnelOptions': [
            {'OutsideIpAddress': '203.0.113.3',
             'LogOptions': {'CloudWatchLogOptions': {'LogEnabled': True}}}]}},
        # An absent Options block IS caught by the `absent` branch: the
        # jmespath expression resolves to None.
        {'VpnConnectionId': 'vpn-options-absent'},
        # KNOWN LIMITATION: when TunnelOptions exists but carries no
        # LogOptions, the flattening projection `TunnelOptions[]...` yields
        # an EMPTY LIST, not None. `absent` therefore does not fire and
        # `contains []` is False, so an unlogged tunnel escapes.
        {'VpnConnectionId': 'vpn-logoptions-absent', 'Options': {'TunnelOptions': [
            {'OutsideIpAddress': '203.0.113.4'}]}},
    ]
    matched = sids(run_policy(POLICIES, 'vpn-tunnel-logging-disabled', resources),
                   'VpnConnectionId')
    assert matched == ['vpn-matches', 'vpn-options-absent']


# ------------------------------------------------ aws.client-vpn-endpoint ---

def test_client_vpn_connection_logging_disabled():
    resources = [
        {'ClientVpnEndpointId': 'cvpn-matches',
         'ConnectionLogOptions': {'Enabled': False}},
        {'ClientVpnEndpointId': 'cvpn-clean',
         'ConnectionLogOptions': {'Enabled': True,
                                  'CloudwatchLogGroup': '/aws/clientvpn'}},
        # This policy DOES carry the `absent` branch, so the endpoint whose
        # ConnectionLogOptions never came back is correctly caught.
        {'ClientVpnEndpointId': 'cvpn-key-absent'},
    ]
    matched = sids(run_policy(
        POLICIES, 'client-vpn-connection-logging-disabled', resources),
        'ClientVpnEndpointId')
    assert matched == ['cvpn-key-absent', 'cvpn-matches']


# ---------------------------------------------------------------- aws.eni ---

def test_eni_source_dest_check_disabled():
    resources = [
        {'NetworkInterfaceId': 'eni-matches', 'InterfaceType': 'interface',
         'SourceDestCheck': False},
        {'NetworkInterfaceId': 'eni-clean', 'InterfaceType': 'interface',
         'SourceDestCheck': True},
        {'NetworkInterfaceId': 'eni-nat-excluded', 'InterfaceType': 'nat_gateway',
         'SourceDestCheck': False},
        # KNOWN LIMITATION: no `absent` branch, so an ENI whose
        # SourceDestCheck never came back reads as compliant.
        {'NetworkInterfaceId': 'eni-key-absent', 'InterfaceType': 'interface'},
    ]
    matched = ids(run_policy(POLICIES, 'eni-source-dest-check-disabled', resources),
                  'NetworkInterfaceId')
    assert matched == ['eni-matches']


def test_inventory_public_ip():
    resources = [
        {'NetworkInterfaceId': 'eni-matches',
         'Association': {'PublicIp': '203.0.113.10', 'PublicDnsName': 'ec2-203-0-113-10'}},
        {'NetworkInterfaceId': 'eni-clean-no-public-ip', 'Association': {}},
        # An absent Association block is not inventoried.
        {'NetworkInterfaceId': 'eni-key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'inventory-public-ip', resources),
                  'NetworkInterfaceId')
    assert matched == ['eni-matches']


# -------------------------------------------------------- aws.launch-config ---

def test_launch_configuration_imdsv2_not_required():
    resources = [
        {'LaunchConfigurationName': 'lc-matches',
         'MetadataOptions': {'HttpTokens': 'optional'}},
        {'LaunchConfigurationName': 'lc-clean',
         'MetadataOptions': {'HttpTokens': 'required'}},
        # Caught twice over: `op: ne` against an absent key is True (None is
        # never 'required'), AND the explicit `MetadataOptions absent` branch
        # fires. This is the correct shape for this trap.
        {'LaunchConfigurationName': 'lc-key-absent'},
    ]
    matched = sids(run_policy(
        POLICIES, 'launch-configuration-imdsv2-not-required', resources),
        'LaunchConfigurationName')
    assert matched == ['lc-key-absent', 'lc-matches']


def test_launch_configuration_assigns_public_ip():
    resources = [
        {'LaunchConfigurationName': 'lc-matches', 'AssociatePublicIpAddress': True},
        {'LaunchConfigurationName': 'lc-clean', 'AssociatePublicIpAddress': False},
        # `value: true` over an absent key does not match.
        {'LaunchConfigurationName': 'lc-key-absent'},
    ]
    matched = ids(run_policy(
        POLICIES, 'launch-configuration-assigns-public-ip', resources),
        'LaunchConfigurationName')
    assert matched == ['lc-matches']


# ---------------------------------------------------- aws.internet-gateway ---

def test_internet_gateway_attached():
    resources = [
        {'InternetGatewayId': 'igw-matches', 'Attachments': [
            {'State': 'available', 'VpcId': 'vpc-0a1b2c3d'}]},
        {'InternetGatewayId': 'igw-detached', 'Attachments': []},
        # An absent Attachments list is not reported.
        {'InternetGatewayId': 'igw-key-absent'},
    ]
    matched = ids(run_policy(POLICIES, 'internet-gateway-attached', resources),
                  'InternetGatewayId')
    assert matched == ['igw-matches']
