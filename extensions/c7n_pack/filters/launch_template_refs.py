"""`referenced-version` filter for aws.launch-template-version.

WHY THIS NEEDS CODE
-------------------
`DefaultVersion: true` is the declarative approximation everyone reaches for,
and it is wrong in a specific way: Auto Scaling (and every other consumer of a
launch template) can point at `$Latest`, `$Default`, or an explicit numbered
version. A template whose DEFAULT version is clean can still be launching
brand new instances from a version that is not -- pinning a consumer to a
numbered version, or leaving it on `$Latest` while the default stays behind,
are both ordinary configurations, and both are invisible to `DefaultVersion`.

Dropping the filter entirely is not the fix either: with no filter c7n
enumerates every version ever created (the sum of every template's
`LatestVersionNumber`, since versions are never garbage-collected), which is
an order of magnitude more rows than the fleet has templates, most of them
inert history nothing will ever launch again.

The actual fix is to keep only the versions something can actually launch,
and that cannot be expressed declaratively -- there is no c7n filter that
walks from a launch template version to the Auto Scaling groups, EKS
nodegroups, or fleets that reference it.

WHAT IT DOES
------------
For every version handed to it, resolves what a consumer's reference ACTUALLY
means:

    consumer declares ......... real version
    "$Default" or absent ...... DefaultVersionNumber
    "$Latest" .................. LatestVersionNumber
    "20" ........................ 20

Both DefaultVersionNumber and LatestVersionNumber come back on the template
object itself (`describe_launch_templates`), so resolving them costs one call
per batch of template ids, not one call per version or per consumer.

CONSUMERS SWEPT
---------------
  - Auto Scaling groups: the top-level `LaunchTemplate`, AND
    `MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification` together
    with its `Overrides` -- each override MAY carry its own
    LaunchTemplateSpecification (a different template or version entirely, used
    to mix instance families), and when it does not, the override falls back to
    the base spec that was already recorded. This shape is exactly what a
    declarative filter cannot see, and it is easy to forget by hand too.
  - EKS managed nodegroups: `launchTemplate.{id,version}` off
    `describe_nodegroup`. There is no bulk "describe every nodegroup" call, so
    this walks list_clusters -> list_nodegroups -> describe_nodegroup, one call
    per nodegroup in the account.
  - EC2 Fleet: `describe_fleets` -> `LaunchTemplateConfigs[].LaunchTemplateSpecification`.
    Fleet `Overrides` only vary InstanceType/subnet/price/placement -- the ec2
    service model (FleetLaunchTemplateOverrides) has no LaunchTemplateSpecification
    field, so there is nothing to walk inside them.
  - Spot Fleet: `describe_spot_fleet_requests` -> the same
    LaunchTemplateConfigs shape, same reasoning on Overrides.

Anything declaring a template by name instead of id is resolved against the
name -> id map built while fetching DefaultVersionNumber/LatestVersionNumber.

ANNOTATION
----------
Matches are annotated with `c7n:ReferencedBy`, a list of `{Consumer, Declares,
Resolved}` entries. `Consumer` names WHAT would launch it (`asg/<name>`,
`asg/<name> (override <InstanceType>)`, `eks-nodegroup/<cluster>/<nodegroup>`,
`fleet/<id>`, `spot-fleet/<id>`, or `none` for a default version kept with no
consumer at all). `Declares` is what the consumer actually wrote --
`$Latest`, `$Default`, or the pinned number -- because "version 20 has
IMDSv1" and "whatever $Latest points to right now has IMDSv1" are different
severities: the first is a known, presumably intentional pin; the second gets
worse on every scale-out with no code change at all. Without this the finding
says "template X version 20 is bad" and nobody knows what to turn off.

INCOMPLETE SWEEPS: absent != 0
-------------------------------
A consumer sweep can fail partway (a describe_nodegroup denied on one cluster)
or entirely (DescribeAutoScalingGroups denied outright). Either way, "we found
no reference to this version" stops being evidence of anything the moment a
sweep for that consumer type has failed -- the ASG that references version 20
may simply live on the page, or behind the call, that errored.

Silently treating that gap as "unreferenced, drop it" would resurrect the
exact false negative this filter exists to remove, except now hidden behind a
filter that LOOKS like it did the analysis. So the decision here is:

    a ClientError anywhere in a consumer type's sweep marks that consumer type
    incomplete for this run. Every version that has no positive reference from
    a WORKING consumer, and is not already kept as the default, is kept
    anyway -- annotated `Declares: sweep-incomplete` naming which consumer
    type(s) failed and the underlying error, instead of being dropped.

This trades noise for correctness on the (expected to be rare) day a describe
call is denied or throttled: worst
case, that run looks like the filter was never applied for the affected scope,
loudly, in the annotation -- not like a clean, confident, wrong answer. The
alternative (raising and failing the whole policy) was rejected because it
would drop the ENTIRE account from that day's report over one denied call
against one cluster; this way every other template's finding still ships.

`include_default: true` (the default) keeps a template's default version
whether or not any consumer references it, because a manual `RunInstances`
with no LaunchTemplate.Version specified also resolves to the default -- there
is no consumer to sweep for that.

LIMITATION, STATED PLAINLY
--------------------------
This does not cover self-managed EC2 instances launched directly with
`RunInstances --launch-template Version=20` outside of any of the four
consumers above; there is no inventory of "what humans typed into the CLI
last Tuesday". `include_default` covers the common manual case (no version
given); a manual launch that pins a specific non-default version is invisible
to any static analysis, custodian included.

USAGE
-----
    - name: launch-template-imdsv1-allowed
      resource: aws.launch-template-version
      filters:
        - type: referenced-version
        - type: value
          key: LaunchTemplateData.MetadataOptions.HttpTokens
          value: optional
"""
import logging

from botocore.exceptions import ClientError
from c7n.filters import Filter
from c7n.resources.ec2 import LaunchTemplate
from c7n.utils import chunks, local_session, type_schema

log = logging.getLogger("custodian.c7n_pack.launch_template_refs")

ALL_CONSUMERS = ("asg", "eks-nodegroup", "ec2-fleet", "spot-fleet")


@LaunchTemplate.filter_registry.register("referenced-version")
class ReferencedVersion(Filter):
    """Launch template versions that something can actually launch."""

    schema = type_schema(
        "referenced-version",
        include_default={"type": "boolean"},
        consumers={"type": "array", "items": {"enum": list(ALL_CONSUMERS)}},
    )
    permissions = (
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeFleets",
        "ec2:DescribeSpotFleetRequests",
        "autoscaling:DescribeAutoScalingGroups",
        "eks:ListClusters",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
    )
    annotation = "c7n:ReferencedBy"

    def process(self, resources, event=None):
        if not resources:
            return []
        template_ids = {r["LaunchTemplateId"] for r in resources}
        by_id, by_name, errors = self._describe_templates(template_ids)

        consumers = self.data.get("consumers", list(ALL_CONSUMERS))
        include_default = self.data.get("include_default", True)

        refs = {}          # (template id, version number) -> [ref dict, ...]
        incomplete = set()  # consumer type names whose sweep hit an error
        # A failed describe means some templates could not be resolved at all,
        # so `$Latest`/`$Default` cannot be turned into a number for them. That
        # is an incomplete sweep of EVERY consumer type, not of one.
        if errors:
            incomplete.update(ALL_CONSUMERS)

        sweeps = {
            "asg": self._sweep_asg,
            "eks-nodegroup": self._sweep_eks,
            "ec2-fleet": self._sweep_ec2_fleet,
            "spot-fleet": self._sweep_spot_fleet,
        }
        for name in consumers:
            sweep = sweeps.get(name)
            if sweep is None:
                continue
            before = len(errors)
            sweep(by_id, by_name, refs, errors)
            if len(errors) > before:
                incomplete.add(name)

        if errors:
            log.warning(
                "referenced-version: %d error(s) sweeping consumers %s -- "
                "affected versions are kept, not dropped: %s",
                len(errors), sorted(incomplete), errors)

        matched = []
        for r in resources:
            tid, vnum = r["LaunchTemplateId"], r["VersionNumber"]
            tmpl = by_id.get(tid)
            reasons = list(refs.get((tid, vnum)) or [])

            if not reasons and include_default and tmpl and vnum == tmpl["DefaultVersionNumber"]:
                reasons.append({
                    "Consumer": "none", "Declares": "default-version", "Resolved": vnum,
                })

            if not reasons and incomplete:
                # See "INCOMPLETE SWEEPS" above. An empty `reasons` here does
                # not mean "nothing launches this version" -- it means "of the
                # consumers we could fully sweep, none does", and at least one
                # consumer type could not be fully swept. Kept, not dropped.
                # The error text goes in the annotation, not only the log: a
                # reader of the finding has to be able to tell AccessDenied
                # from throttling without opening the run log.
                reasons.append({
                    "Consumer": "unknown", "Declares": "sweep-incomplete",
                    "IncompleteConsumers": sorted(incomplete),
                    "Errors": errors[:5],
                })

            if reasons:
                r[self.annotation] = reasons
                matched.append(r)
        return matched

    def _client(self, service):
        return local_session(self.manager.session_factory).client(service)

    # ── resolving what consumers actually reference ─────────────────────

    def _describe_templates(self, template_ids):
        """template id -> {LaunchTemplateName, DefaultVersionNumber, LatestVersionNumber},
        plus the reverse name -> id map, for consumers that reference by name.
        """
        by_id, by_name, errors = {}, {}, []
        if not template_ids:
            return by_id, by_name, errors
        client = self._client("ec2")
        for batch in chunks(sorted(template_ids), 200):
            # Guarded like every consumer sweep, and for the same reason. This
            # was the ONE unguarded call: a template deleted between c7n's
            # enumeration and this filter raises InvalidLaunchTemplateId.NotFound,
            # and a denied ec2:DescribeLaunchTemplates raises AccessDenied --
            # either one escaped `process` and took down the whole policy, which
            # drops the entire account from that day's report. Exactly the
            # outcome this module's docstring rejects for the consumer sweeps.
            #
            # NotFound fails the whole 200-id batch, not just the stale id, so
            # one deleted template blinded up to 200 of them. The batch is
            # retried one id at a time to salvage the rest.
            try:
                paginator = client.get_paginator("describe_launch_templates")
                for page in paginator.paginate(LaunchTemplateIds=list(batch)):
                    for t in page["LaunchTemplates"]:
                        by_id[t["LaunchTemplateId"]] = {
                            "LaunchTemplateName": t["LaunchTemplateName"],
                            "DefaultVersionNumber": t["DefaultVersionNumber"],
                            "LatestVersionNumber": t["LatestVersionNumber"],
                        }
                        by_name[t["LaunchTemplateName"]] = t["LaunchTemplateId"]
                continue
            except ClientError as e:
                errors.append(f"describe_launch_templates(batch of {len(batch)}): "
                              f"{e.response.get('Error', {}).get('Code', e)}")

            for tid in batch:
                try:
                    r = client.describe_launch_templates(LaunchTemplateIds=[tid])
                except ClientError:
                    # Unresolved: the caller treats it as an incomplete sweep and
                    # KEEPS the version rather than assuming it is unreferenced.
                    continue
                for t in r["LaunchTemplates"]:
                    by_id[t["LaunchTemplateId"]] = {
                        "LaunchTemplateName": t["LaunchTemplateName"],
                        "DefaultVersionNumber": t["DefaultVersionNumber"],
                        "LatestVersionNumber": t["LatestVersionNumber"],
                    }
                    by_name[t["LaunchTemplateName"]] = t["LaunchTemplateId"]
        return by_id, by_name, errors

    def _apply_ref(self, tid, tname, version, consumer, by_id, by_name, refs):
        """Resolve one consumer's (id-or-name, version) into a real version
        number and record it. Silently ignores a reference to a template
        outside `by_id` (deleted, or out of this run's scope) -- there is
        nothing to check it against.
        """
        if not tid and tname:
            tid = by_name.get(tname)
        if not tid:
            return
        tmpl = by_id.get(tid)
        if not tmpl:
            return
        if not version or version == "$Default":
            resolved, declares = tmpl["DefaultVersionNumber"], "$Default"
        elif version == "$Latest":
            resolved, declares = tmpl["LatestVersionNumber"], "$Latest"
        else:
            try:
                resolved = int(version)
            except (TypeError, ValueError):
                return
            declares = str(resolved)
        refs.setdefault((tid, resolved), []).append({
            "Consumer": consumer, "Declares": declares, "Resolved": resolved,
        })

    # ── consumer sweeps ──────────────────────────────────────────────────

    def _sweep_asg(self, by_id, by_name, refs, errors):
        client = self._client("autoscaling")
        try:
            for page in client.get_paginator("describe_auto_scaling_groups").paginate():
                for a in page["AutoScalingGroups"]:
                    consumer = f"asg/{a['AutoScalingGroupName']}"
                    lt = a.get("LaunchTemplate")
                    if lt:
                        self._apply_ref(lt.get("LaunchTemplateId"), lt.get("LaunchTemplateName"),
                                        lt.get("Version"), consumer, by_id, by_name, refs)
                    mip = (a.get("MixedInstancesPolicy") or {}).get("LaunchTemplate")
                    if not mip:
                        continue
                    base = mip.get("LaunchTemplateSpecification") or {}
                    if base:
                        self._apply_ref(base.get("LaunchTemplateId"), base.get("LaunchTemplateName"),
                                        base.get("Version"), consumer, by_id, by_name, refs)
                    # Overrides can each carry their own LaunchTemplateSpecification
                    # to mix instance families off different templates/versions.
                    # One that does not carry one falls back to `base`, already
                    # recorded above -- adding it again would just duplicate the
                    # same (tid, version) key harmlessly, so it is skipped instead.
                    for ov in mip.get("Overrides") or []:
                        ov_spec = ov.get("LaunchTemplateSpecification")
                        if not ov_spec:
                            continue
                        ov_consumer = f"{consumer} (override {ov.get('InstanceType', '?')})"
                        self._apply_ref(ov_spec.get("LaunchTemplateId"), ov_spec.get("LaunchTemplateName"),
                                        ov_spec.get("Version"), ov_consumer, by_id, by_name, refs)
        except ClientError as e:
            errors.append({"Consumer": "asg", "Error": str(e)})

    def _sweep_eks(self, by_id, by_name, refs, errors):
        client = self._client("eks")
        try:
            clusters = []
            for page in client.get_paginator("list_clusters").paginate():
                clusters.extend(page["clusters"])
        except ClientError as e:
            errors.append({"Consumer": "eks-nodegroup", "Error": str(e)})
            return
        for cluster in clusters:
            try:
                nodegroups = []
                for page in client.get_paginator("list_nodegroups").paginate(clusterName=cluster):
                    nodegroups.extend(page["nodegroups"])
            except ClientError as e:
                errors.append({"Consumer": "eks-nodegroup", "Error": f"{cluster}: {e}"})
                continue
            # No bulk "describe every nodegroup" call exists: one call each.
            for ng in nodegroups:
                try:
                    detail = client.describe_nodegroup(
                        clusterName=cluster, nodegroupName=ng)["nodegroup"]
                except ClientError as e:
                    errors.append({"Consumer": "eks-nodegroup", "Error": f"{cluster}/{ng}: {e}"})
                    continue
                lt = detail.get("launchTemplate")
                if lt:
                    self._apply_ref(lt.get("id"), lt.get("name"), lt.get("version"),
                                    f"eks-nodegroup/{cluster}/{ng}", by_id, by_name, refs)

    def _sweep_ec2_fleet(self, by_id, by_name, refs, errors):
        client = self._client("ec2")
        try:
            for page in client.get_paginator("describe_fleets").paginate():
                for fleet in page["Fleets"]:
                    consumer = f"fleet/{fleet['FleetId']}"
                    for cfg in fleet.get("LaunchTemplateConfigs") or []:
                        spec = cfg.get("LaunchTemplateSpecification") or {}
                        if not spec:
                            continue
                        self._apply_ref(spec.get("LaunchTemplateId"), spec.get("LaunchTemplateName"),
                                        spec.get("Version"), consumer, by_id, by_name, refs)
                        # Overrides here only vary InstanceType/subnet/price/
                        # placement/InstanceRequirements -- FleetLaunchTemplateOverrides
                        # has no LaunchTemplateSpecification field in the ec2
                        # service model, so there is no alternate template/version
                        # hiding inside them (unlike ASG's MixedInstancesPolicy).
        except ClientError as e:
            errors.append({"Consumer": "ec2-fleet", "Error": str(e)})

    def _sweep_spot_fleet(self, by_id, by_name, refs, errors):
        client = self._client("ec2")
        try:
            for page in client.get_paginator("describe_spot_fleet_requests").paginate():
                for req in page["SpotFleetRequestConfigs"]:
                    consumer = f"spot-fleet/{req['SpotFleetRequestId']}"
                    cfg_root = req.get("SpotFleetRequestConfig") or {}
                    for cfg in cfg_root.get("LaunchTemplateConfigs") or []:
                        spec = cfg.get("LaunchTemplateSpecification") or {}
                        if not spec:
                            continue
                        self._apply_ref(spec.get("LaunchTemplateId"), spec.get("LaunchTemplateName"),
                                        spec.get("Version"), consumer, by_id, by_name, refs)
                        # Same reasoning as EC2 Fleet: SpotFleetLaunchTemplateOverrides
                        # cannot point at a different template/version either.
        except ClientError as e:
            errors.append({"Consumer": "spot-fleet", "Error": str(e)})
