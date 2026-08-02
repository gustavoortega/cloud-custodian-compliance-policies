"""`internet-exposed` filter for aws.security-group.

WHY THIS NEEDS CODE
-------------------
A security group with 0.0.0.0/0 on a database or admin port is only a real
exposure if something reachable is actually behind it. c7n ships a `used`
filter, but "attached to something" is not the same as "reachable from the
internet": most attached groups sit on instances in private subnets with no
public address.

A rule that flags world-open database and admin ports therefore reports three
populations at once: groups attached to nothing, groups attached to private
resources, and the few that something on a public address actually answers on.
Only the last one is a finding; the other two dominate the count.

Correlating a group with the addresses of its network interfaces cannot be done
declaratively: c7n has no filter that walks from a security group to its ENIs
and back.

WHAT IT DOES
------------
Matches only groups attached to at least one network interface carrying a public
IPv4 address (or an IPv6 address, when `include_ipv6` is on). One call to
describe_network_interfaces per batch, filtered server-side by group-id.

Matches are annotated with `c7n:ExposedVia`, listing the interfaces and the
resource they belong to, so the finding says what is behind the group.

LIMITATION, STATED PLAINLY
--------------------------
A public address on an interface is the dominant path from the internet, not the
only one. This does not model route tables, NAT, or load balancer target groups.
An instance with no public IP sitting behind an internet-facing load balancer is
reachable through the balancer, and the balancer's own interfaces do carry public
IPs — so the balancer's group is caught, but the instance's is not.

USAGE
-----
    - name: security-group-database-port-open-to-internet
      resource: aws.security-group
      filters:
        - type: ingress
          Cidr: {value: "0.0.0.0/0"}
          Ports: [22, 3306, 5432]
        - type: internet-exposed
"""
from c7n.filters import Filter
from c7n.resources.vpc import SecurityGroup
from c7n.utils import chunks, local_session, type_schema


@SecurityGroup.filter_registry.register("internet-exposed")
class InternetExposed(Filter):
    """Security groups attached to an interface that has a public address."""

    schema = type_schema("internet-exposed", include_ipv6={"type": "boolean"})
    permissions = ("ec2:DescribeNetworkInterfaces",)
    annotation = "c7n:ExposedVia"

    def process(self, resources, event=None):
        if not resources:
            return []
        exposure = self._interfaces_by_group(resources)
        matched = []
        for r in resources:
            found = exposure.get(r["GroupId"])
            if found:
                r[self.annotation] = found
                matched.append(r)
        return matched

    def _client(self):
        return local_session(self.manager.session_factory).client("ec2")

    def _interfaces_by_group(self, resources):
        """group id -> the public interfaces attached to it."""
        client = self._client()
        want_v6 = self.data.get("include_ipv6", False)
        out = {}
        for batch in chunks([r["GroupId"] for r in resources], 200):
            paginator = client.get_paginator("describe_network_interfaces")
            pages = paginator.paginate(
                Filters=[{"Name": "group-id", "Values": list(batch)}])
            for page in pages:
                for eni in page["NetworkInterfaces"]:
                    public_ip = (eni.get("Association") or {}).get("PublicIp")
                    v6 = eni.get("Ipv6Addresses") or []
                    if not public_ip and not (want_v6 and v6):
                        continue
                    detail = {
                        "NetworkInterfaceId": eni["NetworkInterfaceId"],
                        "PublicIp": public_ip,
                        "Ipv6": [a.get("Ipv6Address") for a in v6] or None,
                        # Says what is behind the group: an instance, a load
                        # balancer, a NAT gateway... The description is what AWS
                        # fills in for managed interfaces.
                        "AttachedTo": (eni.get("Attachment") or {}).get("InstanceId"),
                        "InterfaceType": eni.get("InterfaceType"),
                        "Description": eni.get("Description"),
                    }
                    for g in eni.get("Groups") or []:
                        gid = g.get("GroupId")
                        if gid in batch:
                            out.setdefault(gid, []).append(detail)
        return out
