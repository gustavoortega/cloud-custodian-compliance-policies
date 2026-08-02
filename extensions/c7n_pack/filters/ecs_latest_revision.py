"""`latest-revision` filter for aws.ecs-task-definition.

WHY THIS NEEDS CODE
--------------------
FSBP's text for ECS.3, ECS.4, ECS.5, ECS.8, ECS.9 and ECS.20 all say the same
thing: the control "only evaluates the LATEST active revision" of a task
definition family. c7n's `aws.ecs-task-definition` resource does not honor
that. Its `enum_spec` is `list_task_definitions`, which returns every
revision whose status is ACTIVE -- and ECS never auto-deprecates a revision,
so once one exists it stays ACTIVE and in scope forever, including the ones
nobody deploys anymore.

A family registered N times therefore yields N rows, one per revision, where
FSBP -- and the Security Hub finding it produces -- would yield exactly one:
the revision ECS actually hands out to new tasks today. The gap is not a
rounding error, because the revision count of a family only ever grows: the
real population is one row per (account, region, family), while
`list_task_definitions` returns the entire registration history of every
family that was never explicitly deprecated.

Writing ECS.3/.4/.5/.8/.9/.20 directly against `aws.ecs-task-definition`
would not just inflate the count, it would let a single stale family with a
long revision history dominate every one of those six controls' finding
lists with rows that describe nothing anyone runs.

There is no stock c7n filter that groups resources by an attribute and keeps
only the max of another field within each group -- that is a cross-resource
aggregation a per-resource `value` filter cannot express. Hence this filter.

WHAT IT DOES
------------
Groups the task definitions c7n already enumerated by (account, region,
family) -- parsed straight out of `taskDefinitionArn`, i.e.
`arn:aws:ecs:<region>:<account-id>:task-definition/<family>:<revision>` --
and keeps only the entry with the highest `revision` in each group. A policy
scan is always scoped to one account and one region already, so in practice
the grouping key collapses to `family`; the account/region components are
kept anyway so the filter behaves correctly even if resources from more than
one scope are ever handed to it together (as happens in the test double
below, and would happen if this filter were ever reused outside c7n-org's
one-account-one-region-per-run model).

Every non-matching revision of a family is dropped silently by design: they
are not findings, they are history. A resource this filter cannot identify
(malformed ARN, and no usable `family`/`revision` pair either) is KEPT rather
than dropped -- an unparsed resource must not vanish the way a real gap
would; see the "failed sweep is not an empty result" rule this package already
applies in `launch_template_refs.py`.

USAGE
-----
    - name: ecs-task-definition-privileged-container
      resource: aws.ecs-task-definition
      filters:
        - type: latest-revision
        - type: value
          key: "length(containerDefinitions[?privileged==`true`])"
          op: greater-than
          value: 0
"""
import re

from c7n.filters import Filter
from c7n.resources.ecs import TaskDefinition
from c7n.utils import type_schema

# arn:aws:ecs:<region>:<account>:task-definition/<family>:<revision>
_ARN_RE = re.compile(
    r"^arn:aws[a-z0-9-]*:ecs:(?P<region>[^:]*):(?P<account>\d*):"
    r"task-definition/(?P<family>[^:]+):(?P<revision>\d+)$"
)


@TaskDefinition.filter_registry.register("latest-revision")
class LatestRevision(Filter):
    """Keeps only the highest ACTIVE revision of each task-definition family."""

    schema = type_schema("latest-revision")
    permissions = ()

    def process(self, resources, event=None):
        best = {}
        unidentified = []
        for r in resources:
            key, revision = self._identity(r)
            if key is None:
                unidentified.append(r)
                continue
            current = best.get(key)
            if current is None or revision > current[1]:
                best[key] = (r, revision)
        return [r for r, _ in best.values()] + unidentified

    def _identity(self, r):
        arn = r.get("taskDefinitionArn") or ""
        m = _ARN_RE.match(arn)
        if m:
            key = (m.group("account"), m.group("region"), m.group("family"))
            return key, int(m.group("revision"))
        # The ARN did not parse (unexpected shape, or a test double). Fall
        # back to the family/revision fields directly; if either is unusable
        # the resource cannot be grouped at all, and _identity signals that
        # with key=None so the caller keeps it instead of guessing.
        family, revision = r.get("family"), r.get("revision")
        if family is None or not isinstance(revision, int):
            return None, None
        return (None, None, family), revision
