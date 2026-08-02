"""`cross-account-tolerant` and `unauditable` filters, both on aws.kms-key.

WHY THIS NEEDS CODE
-------------------
c7n's own `cross-account` filter on aws.kms-key (`KMSCrossAccountAccessFilter`
in c7n/resources/kms.py) fetches every key's policy like this:

    def _augment(r):
        r['Policy'] = client.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
        return r
    resources = list(filter(None, w.map(_augment, resources)))

No try/except. `w.map` is a ThreadPoolExecutor map; the first `ClientError`
raised by any worker is re-raised the moment `list()` consumes it, which
aborts the whole filter -- and with it the whole policy invocation, before a
single result is written. A denied `GetKeyPolicy` on ONE key produces:

    botocore.exceptions.ClientError: An error occurred (AccessDeniedException)
    when calling the GetKeyPolicy operation: ... because no resource-based
    policy allows the kms:GetKeyPolicy action
    custodian.commands:ERROR Error while executing policy
    kms-key-policy-publicly-accessible, continuing

No `resources.json` is written at all. So one unreadable key blinds the
ENTIRE account+region to `cross-account`, including every key that was
perfectly readable. That is not a "some keys we cannot see" problem, it is a
"this control does not run here at all" problem.

A key can deny `kms:GetKeyPolicy` to a caller holding ReadOnlyAccess +
SecurityAudit through its OWN key policy: customer-managed keys created with
a deliberately restrictive policy (often by a third-party integration that
provisions its own key) do exactly that. It is not a credentials problem on
the caller's side, and no amount of IAM granted to the auditing role fixes
it.

THE DENIAL IS THE FINDING, NOT A HOLE
-------------------------------------
A key policy that denies `kms:GetKeyPolicy`/`kms:DescribeKey` to a role with
SecurityAudit is itself worth knowing about -- and there is a real irony
here: `kms-key-policy-publicly-accessible` exists to catch key policies that
are too permissive, and a key that cannot be read could just as easily BE
public without anyone finding out. So a denied key is reported as its own
finding (`unauditable`), annotated with why, instead of silently vanishing
from the cross-account sweep.

THE GUARD: MINORITY DENIAL IS A FINDING, MASS DENIAL IS A FAILURE
------------------------------------------------------------------
Without a cap, this design is an anesthesia machine: if an SCP starts
blocking `kms:*` for a whole account, or the role loses `SecurityAudit`,
EVERY key in that account+region flips to "unauditable". The finding becomes
noise (hundreds of identical rows) and the run exits 0 -- a total loss of
visibility dressed up as a clean, boring result.

DENIED_FRACTION_THRESHOLD draws the line between "a handful of
vendor-locked keys" (a finding) and "we lost read access here" (a coverage
gap that has to propagate, same as if `ListKeys` itself had failed).

The threshold works because the two regimes it separates are far apart, not
because a measurement put a line between them:

  - Individually locked keys are, by construction, the exception. Each one
    exists because somebody wrote a restrictive policy for that specific
    key, so they accumulate a key at a time and stay a small minority of an
    account's key ring.
  - The failure modes worth aborting for are all-or-nothing. An SCP that
    blocks `kms:*`, a role that lost `SecurityAudit`, a broken credential:
    every one of them denies effectively 100% of the keys in the
    account+region, not a slice of them.

So any cutoff comfortably above "a handful" and well below "all of them"
tells the two apart. 25% is that: a quarter of an account's keys rejecting
the read is no longer "some vendor-owned keys", it is an
account/permission-level failure, and reporting it as a page of
clean-looking `unauditable` rows would be strictly worse than the bug this
filter replaces. The exact value is a judgement call, not a derived
constant, and it is a module-level name precisely so it can be retuned in
one place if an account's key ring genuinely looks different.

When the threshold trips, the propagated error carries the literal string
"AccessDeniedException", so a runner that classifies errors by code sees a
real coverage gap (a missing permission) and fails the run, rather than
recording a clean one.

Any OTHER error code (throttling, a 5xx, `ListKeys` failing during
enumeration before this filter even runs) is not this case at all and is
never caught here -- it propagates immediately, exactly as it did before
this filter existed. Folding those into the denial fraction would be the
classic too-broad `except`: a transient outage would be averaged into a
number that exists to describe a permissions problem.

WHAT IT DOES
------------
`_fetch_key_policies` calls `GetKeyPolicy` per key, tolerating a per-resource
`AccessDeniedException` (annotating the key and continuing) while letting
any other exception raise immediately, and applies the fraction guard once
the full sweep for this account+region is done:

  - `cross-account-tolerant` (on aws.kms-key / aws.kms): runs the same
    cross-account check as c7n's own `cross-account` filter -- reusing
    `KMSCrossAccountAccessFilter`'s class (whitelist_orgids, whitelist,
    KMSPolicyChecker) rather than reimplementing it -- but only over the
    keys it could actually read.
  - `unauditable` (on aws.kms-key / aws.kms): returns exactly the keys that
    denied `GetKeyPolicy`, annotated with `c7n:KMSPolicyUnauditable`, so the
    absence has an owner instead of disappearing.

USAGE
-----
    - name: kms-key-policy-publicly-accessible
      resource: aws.kms-key
      filters:
        - type: cross-account-tolerant
          whitelist_orgids: [o-xxxxxxxxxx]
          whitelist: [...]

    - name: kms-key-unauditable
      resource: aws.kms-key
      filters:
        - type: unauditable
"""
from botocore.exceptions import ClientError

from c7n.filters import Filter
from c7n.resources.kms import Key, KeyAlias, KMSCrossAccountAccessFilter
from c7n.utils import local_session, type_schema

# See "THE GUARD" above. High enough that a growing number of legitimately
# locked-down keys does not start misfiring the guard, low enough to trip
# well before "most keys in the account" -- which is what an SCP change or a
# lost SecurityAudit grant looks like (they deny effectively 100%). Tune here.
DENIED_FRACTION_THRESHOLD = 0.25

DENIED_ANNOTATION = "c7n:KMSPolicyUnauditable"


class _TolerantKeyPolicyFetch:
    """Shared by both filters below: one GetKeyPolicy sweep, tolerant of a
    per-key AccessDeniedException, guarded against mass denial.

    Kept as a mixin (not duplicated) so the fetch-and-guard logic --
    including the threshold -- exists in exactly one place.
    """

    def _client(self):
        return local_session(self.manager.session_factory).client("kms")

    def _fetch_key_policies(self, resources):
        """Returns (readable, denied).

        `readable` resources have `Policy` populated, same as c7n's own
        `cross-account` filter would set it. `denied` resources are
        annotated with `DENIED_ANNOTATION` instead of being dropped.

        Raises the underlying ClientError -- unmodified -- when:
          - any single GetKeyPolicy call fails with something OTHER than
            AccessDeniedException (narrow the exception: a throttle or a
            5xx is not "a locked key" and must not be folded into the
            denied count), or
          - the fraction of denied keys exceeds DENIED_FRACTION_THRESHOLD
            once the whole resource set has been swept (mass denial, see
            module docstring).
        """
        client = self._client()
        readable, denied = [], []
        last_denied_error = None

        for r in resources:
            key_id = r.get("TargetKeyId", r.get("KeyId"))
            try:
                r["Policy"] = client.get_key_policy(
                    KeyId=key_id, PolicyName="default")["Policy"]
                readable.append(r)
            except ClientError as e:
                if e.response["Error"]["Code"] != "AccessDeniedException":
                    # Not this case: a real outage (throttling, 5xx, ...)
                    # must propagate immediately, not get averaged into a
                    # denial fraction that exists for a different failure mode.
                    raise
                last_denied_error = e
                r[DENIED_ANNOTATION] = {
                    "Error": "AccessDeniedException",
                    "Message": e.response["Error"].get("Message", str(e)),
                }
                denied.append(r)

        total = len(readable) + len(denied)
        if total and (len(denied) / total) > DENIED_FRACTION_THRESHOLD:
            self.log.error(
                "kms:GetKeyPolicy denied on %d/%d keys (%.1f%%) in this "
                "account/region -- exceeds the %.0f%% threshold, treating "
                "this as a coverage gap (propagating) instead of reporting "
                "a partial, misleadingly-clean result",
                len(denied), total, 100.0 * len(denied) / total,
                100.0 * DENIED_FRACTION_THRESHOLD)
            raise last_denied_error

        return readable, denied


@Key.filter_registry.register("cross-account-tolerant")
@KeyAlias.filter_registry.register("cross-account-tolerant")
class KMSCrossAccountTolerant(_TolerantKeyPolicyFetch, KMSCrossAccountAccessFilter):
    """Same check as c7n's `cross-account` on aws.kms-key, over only the
    keys whose policy we could actually read.

    :example:

    .. code-block:: yaml

            policies:
              - name: kms-key-policy-publicly-accessible
                resource: aws.kms-key
                filters:
                  - type: cross-account-tolerant
                    whitelist_orgids: [o-xxxxxxxxxx]
    """

    schema = type_schema(
        "cross-account-tolerant",
        rinherit=KMSCrossAccountAccessFilter.schema)

    def process(self, resources, event=None):
        readable, _denied = self._fetch_key_policies(resources)
        # Skip KMSCrossAccountAccessFilter.process (it re-fetches every
        # policy itself, intolerant of a single AccessDenied) and go
        # straight to the generic CrossAccountAccessFilter.process, reusing
        # its whitelist/org/vpc handling and this class's KMSPolicyChecker
        # (checker_factory, inherited, unchanged) without reimplementing
        # any of it. `readable` already carries `Policy`, which is all that
        # base class needs.
        return super(KMSCrossAccountAccessFilter, self).process(readable, event)


@Key.filter_registry.register("unauditable")
@KeyAlias.filter_registry.register("unauditable")
class KMSUnauditable(_TolerantKeyPolicyFetch, Filter):
    """KMS keys whose policy could not be read (GetKeyPolicy denied by the
    key's OWN policy, to a role with SecurityAudit) -- see module docstring
    for why that is itself a finding and not a gap to paper over.

    :example:

    .. code-block:: yaml

            policies:
              - name: kms-key-unauditable
                resource: aws.kms-key
                filters:
                  - type: unauditable
    """

    schema = type_schema("unauditable")
    permissions = ("kms:GetKeyPolicy",)

    def process(self, resources, event=None):
        _readable, denied = self._fetch_key_policies(resources)
        return denied
