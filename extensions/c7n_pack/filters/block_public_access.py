"""`vpc-block-public-access` and `ebs-snapshot-block-public-access` filters,
both on aws.account.

WHY THIS NEEDS CODE
-------------------
Two FSBP controls have no declarative path at all, native or ours:

  EC2.172 -- VPC Block Public Access
    ec2:DescribeVpcBlockPublicAccessOptions -> VpcBlockPublicAccessOptions
    .InternetGatewayBlockMode, one of "off" / "block-ingress" /
    "block-bidirectional".

  EC2.182 -- EBS snapshots Block Public Access
    ec2:GetSnapshotBlockPublicAccessState -> State, one of "unblocked" /
    "block-new-sharing" / "block-all-sharing".

c7n has no `value`-filter-reachable key for either -- there is no c7n.account
resource attribute that carries them, and unlike `default-ebs-encryption` or
`ami-block-public-access` (see c7n/resources/account.py, both call an
account-wide Get*/Describe* API the same shape as these two), nobody has
wired these two calls into the filter registry yet. That absence is what this
module fixes -- not a defect in how c7n evaluates a key, this time, but a gap
in what it knows how to ask AWS for.

Both settings are per REGION, not per account: querying the same account in
different regions can return different values, so this deliberately does NOT
carry the `region == us-east-1` guard that genuinely account-wide settings
(root MFA, password policy) are scanned with. It sits next to
`default-ebs-encryption` in that respect, which is also asked once per
region for exactly this reason.

WHAT A MATCH MEANS
------------------
Both features ship OFF: `InternetGatewayBlockMode` defaults to "off" and
snapshot BPA defaults to "unblocked", and neither is turned on by any other
AWS action. A policy asking for `state: false` therefore describes the whole
fleet until somebody explicitly opts in, region by region -- it is a METRIC,
not a per-resource ticket queue, which is why the accompanying policies carry
`severity: info`.

That both calls normally succeed is not a reason to skip the failure path
below: a denied
`ec2:DescribeVpcBlockPublicAccessOptions`/`ec2:GetSnapshotBlockPublicAccessState`,
or a partition/region that has not yet rolled out the feature and answers
with some 4xx, are both reachable, and the two questions are independent.

WHAT IT DOES
------------
One API call per filter invocation (these are account/region settings, not
per-resource), then a strict three-way read of the result:

    enabled   -- the call succeeded and the mode/state is anything other
                 than the "off" value.
    disabled  -- the call succeeded and returned exactly the "off" value.
    unverified -- the call raised, or succeeded but the expected key was
                 missing from the response.

Only `enabled` and `disabled` can satisfy the filter's `state:` parameter.
`unverified` NEVER matches, in either direction: a policy asking for
`state: false` (looking for disabled -- the non-conformant case) does not
match an account it could not check, and neither does one asking for
`state: true`. A failed call is not evidence of anything; treating it as
"not enabled" would manufacture a finding out of a permissions problem or an
outage, which is the exact bug class these filters exist to remove (see
`launch_template_refs.py` for the same principle applied elsewhere).

The unverified case is logged via `self.log.warning`, naming the account id,
region and the underlying error/response, so a coverage gap is visible in
the run's log instead of silently vanishing as "compliant" or reappearing as
a false "non-compliant" finding.

Each processed resource is annotated with `c7n:VpcBlockPublicAccess` /
`c7n:EbsSnapshotBlockPublicAccess` (`{"Verified": bool, "Mode"/"State": str
or None, "Enabled": bool or None, "Error": str or None}`) whether or not it
ends up in the matched set, for anyone reading the raw resource off S3.

USAGE
-----
    - name: vpc-block-public-access-disabled
      resource: aws.account
      filters:
        - type: vpc-block-public-access
          state: false

    - name: ebs-snapshot-block-public-access-disabled
      resource: aws.account
      filters:
        - type: ebs-snapshot-block-public-access
          state: false
"""
from botocore.exceptions import ClientError
from c7n.filters import Filter
from c7n.resources.account import Account
from c7n.utils import local_session, type_schema


class _AccountBlockPublicAccessFilter(Filter):
    """Shared machinery for a single account/region Get*/Describe* call that
    reports a tri-state (enabled / disabled / unverified) rather than a plain
    boolean.

    Subclasses provide the client call, how to read "enabled" out of the
    response, and the "off" sentinel that means disabled.
    """

    #: overridden per subclass
    permissions = ()
    annotation = None
    off_value = None

    def _call(self, client):
        """Return (mode_or_state, error) -- error is a string reason when
        the call failed or the expected key was absent, else None."""
        raise NotImplementedError

    def _client(self):
        return local_session(self.manager.session_factory).client("ec2")

    def process(self, resources, event=None):
        if not resources:
            return []
        want_enabled = self.data.get("state", False)
        client = self._client()

        value, error = self._call(client)
        verified = error is None
        enabled = None if not verified else (value != self.off_value)

        matched = []
        for r in resources:
            r[self.annotation] = {
                "Verified": verified,
                "Value": value,
                "Enabled": enabled,
                "Error": error,
            }
            if verified and enabled == want_enabled:
                matched.append(r)

        if not verified:
            self.log.warning(
                "%s: could not determine state for account=%s region=%s: %s",
                self.annotation, self.manager.config.account_id,
                self.manager.config.region, error,
            )
        return matched


@Account.filter_registry.register("vpc-block-public-access")
class VpcBlockPublicAccess(_AccountBlockPublicAccessFilter):
    """Accounts/regions by their VPC Block Public Access
    (InternetGatewayBlockMode) setting. FSBP EC2.172."""

    schema = type_schema("vpc-block-public-access", state={"type": "boolean"})
    permissions = ("ec2:DescribeVpcBlockPublicAccessOptions",)
    annotation = "c7n:VpcBlockPublicAccess"
    off_value = "off"

    def _call(self, client):
        try:
            resp = client.describe_vpc_block_public_access_options()
        except ClientError as e:
            return None, e.response.get("Error", {}).get("Code", str(e))
        mode = (resp.get("VpcBlockPublicAccessOptions") or {}).get("InternetGatewayBlockMode")
        if mode is None:
            return None, "InternetGatewayBlockMode missing from response"
        return mode, None


@Account.filter_registry.register("ebs-snapshot-block-public-access")
class EbsSnapshotBlockPublicAccess(_AccountBlockPublicAccessFilter):
    """Accounts/regions by their EBS snapshot Block Public Access
    (GetSnapshotBlockPublicAccessState) setting. FSBP EC2.182."""

    schema = type_schema("ebs-snapshot-block-public-access", state={"type": "boolean"})
    permissions = ("ec2:GetSnapshotBlockPublicAccessState",)
    annotation = "c7n:EbsSnapshotBlockPublicAccess"
    off_value = "unblocked"

    def _call(self, client):
        try:
            resp = client.get_snapshot_block_public_access_state()
        except ClientError as e:
            return None, e.response.get("Error", {}).get("Code", str(e))
        state = resp.get("State")
        if state is None:
            return None, "State missing from response"
        return state, None
