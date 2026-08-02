"""`internet-reachable` filter for aws.rds.

WHY THIS NEEDS CODE
-------------------
`PubliclyAccessible: true` does not prove exposure. It means the instance has a
public DNS name and IP. Whether anything can actually reach it is decided by the
security group.

That cannot be expressed declaratively. c7n's `security-group` filter evaluates
against the security group and never sees the instance's port, so there is no
way to write "a security group that opens 0.0.0.0/0 ON THIS DATABASE'S PORT".
The closest declarative approximation is "any port open", and that lies in a
very common shape: a shared or `default` security group that opens, say, 3306
to the world, attached to a PostgreSQL instance listening on 5432. The group is
world-open and the instance is publicly accessible, yet nothing can reach the
database, because the open port is not its port. "Any port open" reports it;
this filter does not.

WHAT IT DOES
------------
Cross-references Endpoint.Port against the ingress rules of every attached
security group, and matches only when a rule from 0.0.0.0/0 or ::/0 covers that
port. It handles the three cases people usually miss:

  - IpProtocol "-1"       -> every protocol and port
  - FromPort/ToPort None  -> same, even with an explicit protocol
  - ranges                -> FromPort <= port <= ToPort

Matches are annotated with `c7n:ReachableVia` so the finding states WHICH rule
exposes it — otherwise remediating means investigating from scratch.

USAGE
-----
    - name: rds-internet-reachable
      resource: aws.rds
      filters:
        - type: internet-reachable
"""
from c7n.filters import Filter
from c7n.resources.rds import RDS
from c7n.utils import chunks, local_session, type_schema

OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"


def _rule_covers(permission, port):
    """True if the permission covers `port`. A null FromPort means 'all ports'."""
    if permission.get("IpProtocol") == "-1":
        return True
    start, end = permission.get("FromPort"), permission.get("ToPort")
    if start is None or end is None:
        return True
    return start <= port <= end


def _open_sources(permission):
    """Return the world-open CIDRs present in the permission."""
    found = []
    for r in permission.get("IpRanges") or []:
        if r.get("CidrIp") == OPEN_V4:
            found.append(OPEN_V4)
    for r in permission.get("Ipv6Ranges") or []:
        if r.get("CidrIpv6") == OPEN_V6:
            found.append(OPEN_V6)
    return found


@RDS.filter_registry.register("internet-reachable")
class InternetReachable(Filter):
    """RDS instances with a public endpoint AND a security group opening their port."""

    schema = type_schema("internet-reachable", require_public_endpoint={"type": "boolean"})
    permissions = ("ec2:DescribeSecurityGroups",)
    annotation = "c7n:ReachableVia"

    def process(self, resources, event=None):
        # Without a public endpoint there is no route from the internet even if
        # the security group is wide open, because the group is only evaluated
        # inside the VPC. Can be disabled to audit permissive groups on private
        # instances.
        if self.data.get("require_public_endpoint", True):
            candidates = [r for r in resources if r.get("PubliclyAccessible")]
        else:
            candidates = list(resources)
        if not candidates:
            return []

        groups = self._describe_groups(candidates)
        matched = []
        for r in candidates:
            port = (r.get("Endpoint") or {}).get("Port")
            if port is None:
                # No endpoint yet (creating, or restoring). Nothing can be
                # asserted, so skip rather than guess.
                continue
            reasons = []
            for ref in r.get("VpcSecurityGroups") or []:
                if ref.get("Status") != "active":
                    continue
                sg = groups.get(ref.get("VpcSecurityGroupId"))
                if not sg:
                    continue
                for permission in sg.get("IpPermissions") or []:
                    if not _rule_covers(permission, port):
                        continue
                    for cidr in _open_sources(permission):
                        reasons.append({
                            "GroupId": sg["GroupId"],
                            "GroupName": sg.get("GroupName"),
                            "Cidr": cidr,
                            "FromPort": permission.get("FromPort"),
                            "ToPort": permission.get("ToPort"),
                            "IpProtocol": permission.get("IpProtocol"),
                            "Port": port,
                        })
            if reasons:
                r[self.annotation] = reasons
                matched.append(r)
        return matched

    def _client(self):
        return local_session(self.manager.session_factory).client("ec2")

    def _describe_groups(self, resources):
        ids = {
            g["VpcSecurityGroupId"]
            for r in resources
            for g in (r.get("VpcSecurityGroups") or [])
            if g.get("VpcSecurityGroupId")
        }
        if not ids:
            return {}
        client = self._client()
        out = {}
        # describe_security_groups caps at 1000 ids per call; chunk anyway so we
        # don't build huge requests in accounts with many instances.
        for batch in chunks(sorted(ids), 200):
            paginator = client.get_paginator("describe_security_groups")
            for page in paginator.paginate(GroupIds=list(batch)):
                for sg in page["SecurityGroups"]:
                    out[sg["GroupId"]] = sg
        return out
