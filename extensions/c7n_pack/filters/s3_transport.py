"""`insecure-transport` filter for aws.s3.

WHY THIS NEEDS CODE
--------------------
"Does this bucket policy deny non-TLS traffic" looks like a `value` or
`missing-policy-statement` job. Both are wrong:

  - `missing-policy-statement` matches by `Sid`. A bucket that denies
    insecure transport under a Sid other than the one the policy expects
    (e.g. "DenyInsecureTransport" vs "AllowSSLRequestsOnly" -- both are
    common spellings, and the Sid is free text anyway) is reported as
    missing the control it actually has.

  - A `value` filter with `op: contains` over the raw policy text is a
    substring match: `aws:SecureTransport` or the bucket's own ARN can
    appear inside an `Allow` statement, inside a `NotPrincipal`, or inside an
    unrelated `Condition` block, and the filter has no idea which one it
    matched. That is the same class of bug the KMS key-policy check in this
    package exists to avoid.

Getting it right needs to walk `Statement[]`, and for each one check Effect,
Principal, Condition AND Resource together -- which is exactly the four-way
join none of c7n's declarative primitives do in one shot.

WHAT COUNTS AS AN EFFECTIVE DENY
---------------------------------
A statement only counts if ALL of these hold:

  - `Effect: Deny`.
  - A `Bool` condition on `aws:SecureTransport` evaluating to false. The
    condition key is matched case-insensitively (IAM itself is
    case-sensitive on the key name, but hand-written policies drift), and
    the value is accepted as either the JSON boolean `false` or the string
    `"false"` (any casing) -- both shapes occur in real bucket policies and
    AWS enforces both.
  - `Principal` is `"*"` or `{"AWS": "*"}`. A deny bounded to one principal
    does not stop insecure requests from anyone else; it is not a control on
    the bucket, so it is reported as if there were none (`scoped-principal`).
  - `Action` covers `s3:*` or `*`. A deny on one narrow action (say,
    `s3:GetObject`) leaves every other S3 API reachable over plain HTTP.

Statements that pass all four are pooled, and their `Resource` entries are
unioned (fnmatch-compared, so a wildcard bucket ARN still matches) against
`arn:aws:s3:::<bucket>` AND `arn:aws:s3:::<bucket>/*`. Splitting bucket- and
object-level denies across two separate statements is common and is treated
as one combined control, not two partial ones. Only if BOTH ARNs are covered
does the bucket count as protected.

`Action` written as `NotAction` (Deny-with-NotAction is a valid but rare
shape) is treated as not covering `s3:*`/`*` -- deliberately conservative:
resolving what a NotAction Deny actually excludes would need to enumerate
every S3 action, and getting that wrong silently clears a bucket that should
have been flagged.

ANNOTATION: c7n:InsecureTransport
-----------------------------------
Every match is annotated `{"Reason": ..., ...}` with one of:

  - `no-policy`      -- no bucket policy at all (NoSuchBucketPolicy).
  - `no-deny`        -- a policy exists, but no statement denies on
                         aws:SecureTransport at all.
  - `scoped-principal` -- such a statement exists, but every one of them is
                         bound to a specific principal, not "*".
  - `narrow-action`  -- principal is unbound, but no qualifying statement's
                         Action covers s3:*/*.
  - `partial-resource` -- a fully qualifying statement (or set of them)
                         exists, but the Resource union misses the bucket
                         ARN, the `/*` object ARN, or both. The annotation
                         carries `Missing: [...]` naming which one -- a deny
                         written only on `bucket/*` is the single most common
                         version of this and leaves every bucket-level
                         operation (e.g. GetBucketAcl) unprotected.

These are the CLOSEST-cause classification, evaluated in this order: a
statement one step short of qualifying wins over reporting "no-deny" for a
policy that in fact tried and got one condition wrong.

`absent != 0`: AccessDenied vs. "no policy"
--------------------------------------------
c7n's own S3 augment (`assemble_bucket` in c7n.resources.s3) already fetches
`Policy` for every bucket, and on ClientError it makes exactly this
distinction: `NoSuchBucketPolicy`/`*NotFound*` sets `Policy` to `None` (no
policy, a real finding); anything else -- notably `AccessDenied` -- leaves
`Policy` unset and appends `'get_bucket_policy'` to `c7n:DeniedMethods`
instead. That second case is NOT "no policy". It is "we don't know" -- and
it is reachable in practice, e.g. in a region where the auditing role does
not hold the same read access it has elsewhere, which makes both
GetBucketEncryption and GetBucketPolicy fail on the same bucket.

Treating an AccessDenied bucket as `no-policy` would be actively wrong in
the paranoid direction: a bucket policy strict enough to also block the
account's own scanning role from reading it is not evidence of an open
bucket. This filter's decision: a bucket carrying `get_bucket_policy` in
`c7n:DeniedMethods` is EXCLUDED from the match entirely -- neither counted
as protected nor as a finding. It does not get `c7n:InsecureTransport`.
Anyone auditing coverage gaps should separately query for
`c7n:DeniedMethods` containing `get_bucket_policy`, which c7n already
populates with no extra code here.

LIMITATION, STATED PLAINLY
---------------------------
This only looks at the bucket policy. `aws:SecureTransport` deny is the
standard control, but it is not the only theoretical path to the same
guarantee (e.g. an SCP-level deny at the org level would also work and is
invisible here). It also does not evaluate `NotPrincipal` or `NotResource`
forms of the same statement -- both are legal IAM, both are rare, and
resolving what they exclude is the same open-ended enumeration problem as
`NotAction` above. Left out deliberately rather than approximated.

USAGE
-----
    - name: s3-insecure-transport
      resource: aws.s3
      filters:
        - type: insecure-transport
"""
import fnmatch
import json

from c7n.filters import Filter
from c7n.resources.s3 import S3
from c7n.utils import type_schema

BUCKET_ARN_TMPL = "arn:aws:s3:::{}"
OBJECT_ARN_TMPL = "arn:aws:s3:::{}/*"


def _as_list(value):
    """IAM lets Principal/Action/Resource be a scalar or a list. Normalize."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_false(value):
    """True for the JSON boolean False or the string "false" (any casing).
    Condition values can also legally be a one-item list of either.
    """
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() == "false"
    if isinstance(value, list):
        return any(_is_false(v) for v in value)
    return False


def _secure_transport_deny_condition(condition):
    """True if `condition` is a Bool check on aws:SecureTransport == false.

    Matched case-insensitively on both the operator ("Bool") and the
    condition key ("aws:SecureTransport"): IAM itself requires exact case,
    but hand-edited policies do not always agree with each other, and a
    filter that only catches the canonical casing would miss a deny that AWS
    enforces just fine.
    """
    if not isinstance(condition, dict):
        return False
    for op, kv in condition.items():
        if not isinstance(op, str) or op.lower() != "bool":
            continue
        if not isinstance(kv, dict):
            continue
        for key, val in kv.items():
            if isinstance(key, str) and key.lower() == "aws:securetransport" and _is_false(val):
                return True
    return False


def _principal_is_wildcard(principal):
    """Principal "*" or {"AWS": "*"} (including inside a list)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _action_is_broad(statement):
    """s3:* or * in Action. NotAction is deliberately NOT treated as broad --
    see the module docstring's LIMITATION section.
    """
    if "Action" not in statement:
        return False
    return any(a in ("*", "s3:*") for a in _as_list(statement.get("Action")))


def _resource_coverage(statements, bucket_arn, object_arn):
    """Union, across `statements`, of which of (bucket_arn, object_arn) is
    covered by at least one Resource entry. fnmatch handles wildcarded ARNs
    (e.g. "arn:aws:s3:::my-bucket*") as well as exact ones.
    """
    covers_bucket = covers_objects = False
    for st in statements:
        for pattern in _as_list(st.get("Resource")):
            if not isinstance(pattern, str):
                continue
            if fnmatch.fnmatchcase(bucket_arn, pattern):
                covers_bucket = True
            if fnmatch.fnmatchcase(object_arn, pattern):
                covers_objects = True
    return covers_bucket, covers_objects


@S3.filter_registry.register("insecure-transport")
class InsecureTransport(Filter):
    """S3 buckets whose policy does not effectively deny non-TLS traffic."""

    schema = type_schema("insecure-transport")
    permissions = ()  # Policy is already fetched by c7n's own S3 augment.
    annotation = "c7n:InsecureTransport"

    def process(self, resources, event=None):
        matched = []
        for r in resources:
            reason = self._evaluate(r)
            if reason:
                r[self.annotation] = reason
                matched.append(r)
        return matched

    def _evaluate(self, r):
        # AccessDenied reading the policy is NOT "no policy" -- see the
        # "absent != 0" section of the module docstring. Excluded, not
        # flagged either way.
        if "get_bucket_policy" in (r.get("c7n:DeniedMethods") or []):
            return None

        raw = r.get("Policy")
        if raw is None:
            return {"Reason": "no-policy"}

        try:
            policy = json.loads(raw)
            # `json.loads` succeeding does NOT mean we got an object: a policy that is
            # valid JSON but an array, a string or a number parses fine and then blows
            # up on `.get`. Treated as unreadable, not as "no deny" -- claiming a bucket
            # is unprotected because we could not parse its policy is a made-up finding.
            if not isinstance(policy, dict):
                return None
        except (TypeError, ValueError):
            # Malformed policy text is not something a bucket can actually
            # have (S3 validates on PutBucketPolicy), but if it somehow
            # shows up, treat it the conservative way: unknown, not a match.
            return None

        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        elif not isinstance(statements, list):
            statements = []

        secure_transport_denies = [
            st for st in statements
            if st.get("Effect") == "Deny"
            and _secure_transport_deny_condition(st.get("Condition"))
        ]
        if not secure_transport_denies:
            return {"Reason": "no-deny"}

        unbound_principal = [
            st for st in secure_transport_denies
            if _principal_is_wildcard(st.get("Principal"))
        ]
        if not unbound_principal:
            return {"Reason": "scoped-principal"}

        broad_action = [st for st in unbound_principal if _action_is_broad(st)]
        if not broad_action:
            return {"Reason": "narrow-action"}

        bucket_arn = BUCKET_ARN_TMPL.format(r["Name"])
        object_arn = OBJECT_ARN_TMPL.format(r["Name"])
        covers_bucket, covers_objects = _resource_coverage(broad_action, bucket_arn, object_arn)
        if covers_bucket and covers_objects:
            return None

        missing = []
        if not covers_bucket:
            missing.append("bucket")
        if not covers_objects:
            missing.append("objects")
        return {"Reason": "partial-resource", "Missing": missing}
