"""`external-trust` filter for aws.iam-role.

WHY THIS NEEDS CODE
-------------------
c7n's `cross-account` filter on aws.iam-role reports every trust naming an
account other than the one being scanned, regardless of the conditions attached
to it. In an organisation, most of those trusts are bounded by
`aws:PrincipalOrgID` and are not cross-account exposure at all, so the finding
is dominated by rows nobody can act on.

That cannot be narrowed declaratively: the `cross-account` filter on
aws.iam-role accepts only `whitelist` -- alone among the resources it has no
`whitelist_conditions` -- so a trust bounded by aws:PrincipalOrgID cannot be
excluded. Hence this filter.

WHAT COUNTS AS BOUNDED
----------------------
A statement is only treated as scoped when a POSITIVE condition ties it to an
account or organisation the operator declared as their own (`whitelist` /
`whitelist_orgids`). Two mistakes are easy here and this filter made both in
its first version:

  POLARITY. `StringNotEquals` with aws:PrincipalOrgID means "anyone EXCEPT this
  org" -- the opposite of scoped. Only the operators c7n itself normalises as
  positive are honoured (see normalize_conditions in c7n/filters/iamaccess.py);
  anything else, negative operators included, does not bind.

  VALUE. Checking that the key `aws:PrincipalOrgID` is merely PRESENT is not
  enough: `{"aws:PrincipalOrgID": "o-someone-elses-org"}` is scoped to a
  different, possibly attacker-controlled organisation and is genuinely
  external. The value is compared against the configured org ids and account
  ids.

FEDERATED PRINCIPALS
--------------------
A `Principal.Federated` trust (OIDC, SAML) names a provider that lives in the
account being scanned, so account comparison says nothing. What matters is
whether the
subject is pinned: a GitHub Actions provider with no condition on `:sub` is
assumable from ANY repository on GitHub, which is one of the most common real
external-trust holes. Those are reported; a provider with a subject condition is
not.

USAGE
-----
    - name: iam-role-assumable-from-outside-the-org
      resource: aws.iam-role
      filters:
        - type: external-trust
          whitelist: ["<your-account-id>", ...]   # your own accounts
          whitelist_orgids: ["o-xxxxxxxxxx"]      # your own org ids
"""
import re

from c7n.filters import Filter
from c7n.resolver import ValuesFrom
from c7n.resources.iam import Role
from c7n.utils import type_schema

ACCOUNT_RE = re.compile(r"(\d{12})")

# Only these bind. They are the operators c7n's own PolicyChecker normalises;
# every negative form (StringNotEquals, ArnNotLike, ...) is deliberately absent,
# because "everyone except X" does not scope a grant to X.
POSITIVE_OPS = (
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
    "arnequals",
    "arnlike",
)

# Condition keys naming an organisation.
ORG_KEYS = ("aws:principalorgid", "aws:resourceorgid")
ORG_PATH_KEYS = ("aws:principalorgpaths",)
# Condition keys naming an account, directly or inside an ARN.
ACCOUNT_KEYS = (
    "aws:principalarn",
    "aws:principalaccount",
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
)
# Subject-pinning keys for federated providers. The prefix varies with the
# provider (token.actions.githubusercontent.com:sub, oidc.eks...:sub), so these
# are matched as suffixes.
SUBJECT_SUFFIXES = (":sub", ":aud", ":oud", "saml:aud", "saml:sub")


def _account_of(value):
    """Account id in an ARN, or the value itself when it already is one."""
    m = ACCOUNT_RE.search(str(value))
    return m.group(1) if m else None


def _positive_blocks(statement):
    """(key, values) of every condition under a POSITIVE operator."""
    condition = statement.get("Condition") or {}
    for operator, block in condition.items():
        if not isinstance(block, dict):
            continue
        # ForAnyValue:StringEquals / ForAllValues:StringLike keep their operator
        # after the colon; the set prefix does not change polarity.
        base = str(operator).split(":")[-1].lower()
        if base not in POSITIVE_OPS:
            continue
        for key, values in block.items():
            yield key.lower(), (list(values) if isinstance(values, list) else [values])


def _bound_to_us(statement, accounts, orgids):
    """True when a positive condition ties the statement to us, by VALUE."""
    for key, values in _positive_blocks(statement):
        if key in ORG_KEYS:
            if orgids and all(str(v) in orgids for v in values):
                return True
        elif key in ORG_PATH_KEYS:
            if orgids and all(str(v).split("/")[0] in orgids for v in values):
                return True
        elif key in ACCOUNT_KEYS:
            found = {_account_of(v) for v in values}
            if found and None not in found and found <= accounts:
                return True
    return False


def _has_external_id(statement):
    """True when the trust requires sts:ExternalId."""
    return any(k == "sts:externalid" for k, _ in _positive_blocks(statement))


def _has_subject_condition(statement):
    """True when a federated trust pins the subject or audience."""
    for key, _ in _positive_blocks(statement):
        if key.endswith(SUBJECT_SUFFIXES):
            return True
    return False


def _aws_principals(statement):
    principal = statement.get("Principal")
    if not principal:
        return []
    if isinstance(principal, str):
        return [principal]
    values = principal.get("AWS")
    if values is None:
        return []
    return values if isinstance(values, list) else [values]


def _federated_principals(statement):
    principal = statement.get("Principal")
    if not isinstance(principal, dict):
        return []
    values = principal.get("Federated")
    if values is None:
        return []
    return values if isinstance(values, list) else [values]


@Role.filter_registry.register("external-trust")
class ExternalTrust(Filter):
    """IAM roles assumable from outside the organisation, conditions honoured."""

    schema = type_schema(
        "external-trust",
        whitelist={"type": "array", "items": {"type": "string"}},
        whitelist_from={"$ref": "#/definitions/filters_common/value_from"},
        whitelist_orgids={"type": "array", "items": {"type": "string"}},
        include_conditioned={"type": "boolean"},
        check_federated={"type": "boolean"},
        third_parties={"type": "array", "items": {"type": "string"}},
        require_external_id={"type": "boolean"},
    )
    permissions = ()
    annotation = "c7n:ExternalTrust"

    def _allowed_accounts(self):
        allowed = set(self.data.get("whitelist") or [])
        if "whitelist_from" in self.data:
            allowed |= set(ValuesFrom(self.data["whitelist_from"], self.manager).get_values())
        # The account being scanned is always its own, whatever the config says.
        own = getattr(self.manager.config, "account_id", None)
        if own:
            allowed.add(own)
        return allowed

    def process(self, resources, event=None):
        propias = self._allowed_accounts()
        # APPROVED third parties. Kept separate from `whitelist` on purpose: a
        # vendor account is not one of your own. Merging the two makes it
        # impossible to ask "which approved vendors get in without an
        # ExternalId", which is exactly the question `require_external_id`
        # below exists to answer.
        terceros = set(self.data.get("third_parties") or ())
        accounts = propias | terceros
        orgids = set(self.data.get("whitelist_orgids") or ())
        honour = not self.data.get("include_conditioned", False)
        check_federated = self.data.get("check_federated", True)
        exigir_eid = self.data.get("require_external_id", False)

        matched = []
        for r in resources:
            findings = []
            document = r.get("AssumeRolePolicyDocument") or {}
            for statement in document.get("Statement") or []:
                if statement.get("Effect") != "Allow":
                    continue
                if exigir_eid:
                    # Dedicated mode: ONLY the ExternalId gap. Without this the
                    # policy duplicates the general rule and reports every
                    # unapproved vendor, which is already reported elsewhere.
                    if not _has_external_id(statement):
                        findings.extend(self._sin_external_id(statement, propias))
                    continue
                bounded = honour and _bound_to_us(statement, accounts, orgids)
                if not bounded:
                    findings.extend(self._aws_findings(statement, accounts))
                if check_federated:
                    findings.extend(self._federated_findings(statement))
            if findings:
                r[self.annotation] = findings
                matched.append(r)
        return matched

    def _aws_findings(self, statement, accounts):
        out = []
        for principal in _aws_principals(statement):
            principal = str(principal)
            if principal == "*":
                out.append({
                    "Principal": "*",
                    "Sid": statement.get("Sid"),
                    "Action": statement.get("Action"),
                    "Reason": "any principal, not bounded to our org by a condition",
                })
                continue
            account = _account_of(principal)
            if account and account not in accounts:
                out.append({
                    "Principal": principal,
                    "Account": account,
                    "Sid": statement.get("Sid"),
                    "Action": statement.get("Action"),
                    "Reason": "account outside the organisation",
                })
        return out

    def _sin_external_id(self, statement, propias):
        """ANY trust out of the organisation without sts:ExternalId.

        Approved and unapproved vendors alike. The first version only looked at
        the approved ones, reasoning that the general rule already reports the
        rest. That is a bad argument: the two rules answer different questions
        -- "who gets in without approval" and "which grants have no confused
        deputy protection" -- and the second one applies to everybody. An
        unapproved vendor with no ExternalId is WORSE, not better.

        Tying it to the approved list also meant the gap would surface as a NEW
        finding the day the vendor got approved, when it had been there all
        along. What a rule means must not depend on a list.
        """
        out = []
        for principal in _aws_principals(statement):
            principal = str(principal)
            cuenta = _account_of(principal)
            # `*` has no account to extract, and it is the WORST case: anyone
            # can assume it. Skipping it for lack of a parseable account meant
            # ignoring the most open trust there is.
            if principal != "*":
                # inside the organisation the confused deputy does not apply
                if not cuenta or cuenta in propias:
                    continue
            out.append({
                "Principal": principal,
                "Account": cuenta,
                "Sid": statement.get("Sid"),
                "Action": statement.get("Action"),
                "Reason": "external trust without sts:ExternalId",
            })
        return out

    def _federated_findings(self, statement):
        """A federated provider with no subject condition is assumable by anyone
        that provider will issue a token for -- for GitHub Actions, every repo
        on GitHub."""
        if _has_subject_condition(statement):
            return []
        return [{
            "Principal": str(p),
            "Sid": statement.get("Sid"),
            "Action": statement.get("Action"),
            "Reason": "federated provider with no sub/aud condition",
        } for p in _federated_principals(statement)]
