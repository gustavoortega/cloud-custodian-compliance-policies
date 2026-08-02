"""`aws.backup-recovery-point` resource type, plus its `unencrypted` filter.

WHY THIS NEEDS CODE
-------------------
FSBP Backup.1 requires every AWS Backup recovery point to be encrypted at
rest. c7n 0.9.51 has NO resource type for `AWS::Backup::RecoveryPoint` --
`c7n/resources/backup.py` registers only `backup-plan` and `backup-vault`.
`aws.backup-vault` wraps `list_backup_vaults`, which describes the VAULT's own
settings (its default `EncryptionKeyArn`, its lock state). It says nothing
about what is actually sitting inside it: a recovery point can be unencrypted
even in a vault that looks fine today, because it was created before the
account turned on EBS-default-encryption, or because the source resource
itself was unencrypted at backup time. Backup.1 is written against the
recovery point, so the finding has to be the recovery point, not the vault
that happens to contain it.

TWO WAYS TO COVER THIS, AND WHY THE RESOURCE TYPE WON
------------------------------------------------------
Option A: a filter on `aws.backup-vault` that calls
`list_recovery_points_by_backup_vault` per vault and flags the VAULT if any
recovery point inside it is unencrypted.

Option B (this file): a real `aws.backup-recovery-point` resource type, with
its own `unencrypted` filter, so each row in the findings table IS the
recovery point that needs re-backing-up.

Unencrypted recovery points are a small minority of any vault's contents, so
the finding is triageable -- but only if each row already names the resource.
Option A reports the vault, and a single vault routinely holds hundreds of
recovery points. Whoever triages "this vault has an unencrypted recovery
point somewhere in it" has to re-run the exact same
`list_recovery_points_by_backup_vault` call by hand to find which one --
the filter would have done the expensive part of the work and then thrown the
answer away. Option B costs more code up front (there is no single
"list every recovery point in the account" API; it is scoped one vault at a
time, so a real describe `Source` is needed instead of a stock `enum_spec`)
but the resulting row is `<account, region, BackupVaultName, RecoveryPointArn>`
-- the exact resource whoever owns it needs to look at.

ABSENCE IS NOT A ZERO
---------------------
`IsEncrypted` is normally present (True or False) on every recovery point,
but that is the API's current behaviour, not a guarantee of its shape -- a
recovery point still being created, or one for a resource type that does not
carry the concept of at-rest encryption, could in principle omit the key.
`UnencryptedRecoveryPoint.process` below treats an ABSENT `IsEncrypted` as
UNDETERMINED, never as "encrypted" and never as a finding: it is annotated
`c7n:BackupEncryptionUnknown` so it is visible on inspection, but it is not
returned as a match. Silently treating a missing key as "encrypted" would
recreate, on a brand-new control, the exact bug these filters exist to catch
in the stock ones.

COST OF THE ENUMERATION
------------------------
`list_recovery_points_by_backup_vault` is only called for vaults whose
`NumberOfRecoveryPoints` is > 0 -- that field is already present on the
`list_backup_vaults` response, so checking it costs nothing extra and skips
every empty vault, several of which would otherwise cost a paginated call
each. An (account, region) pair that owns no vault at all does one cheap
`list_backup_vaults` call and stops, which matters because this resource type
is enumerated in every account and region a run covers, whether or not AWS
Backup is used there. A daily cadence is the right choice for the
accompanying policy: a slow drift like a stale unencrypted recovery point
does not need hourly visibility, and a daily run avoids paying the
per-vault enumeration cost several times a day to catch something that is
well inside any reasonable remediation window either way.

USAGE
-----
    - name: backup-recovery-point-unencrypted
      resource: aws.backup-recovery-point
      filters:
        - type: unencrypted
"""
from botocore.exceptions import ClientError

from c7n.filters import Filter
from c7n.manager import resources
from c7n.query import DescribeSource, QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema


class DescribeRecoveryPoints(DescribeSource):
    """Enumerates recovery points vault by vault.

    There is no "list every recovery point in the account" API --
    `ListRecoveryPointsByBackupVault` is scoped to a single `BackupVaultName`
    per call, same shape as `DescribeVault.get_resources` in
    `c7n/resources/backup.py` doing one `describe_backup_vault` per name. So
    `resources()` is overridden outright instead of relying on the stock
    `enum_spec` machinery, which only knows how to call one operation with no
    per-item fan-out.
    """

    def get_permissions(self):
        return ("backup:ListBackupVaults", "backup:ListRecoveryPointsByBackupVault")

    def _client(self):
        return local_session(self.manager.session_factory).client("backup")

    def resources(self, query):
        client = self._client()
        out = []
        for vault_name in self._non_empty_vaults(client):
            out.extend(self._recovery_points(client, vault_name))
        return out

    def _non_empty_vaults(self, client):
        """Only vaults reporting NumberOfRecoveryPoints > 0 are worth a
        ListRecoveryPointsByBackupVault call -- that field comes for free on
        list_backup_vaults, no extra API call needed to check it, and empty
        vaults are common enough that skipping them removes most of the
        per-vault (often paginated) calls.
        """
        out = []
        for page in client.get_paginator("list_backup_vaults").paginate():
            for v in page.get("BackupVaultList", []):
                if v.get("NumberOfRecoveryPoints", 0) > 0:
                    out.append(v["BackupVaultName"])
        return out

    def _recovery_points(self, client, vault_name):
        out = []
        try:
            pages = client.get_paginator(
                "list_recovery_points_by_backup_vault").paginate(
                    BackupVaultName=vault_name)
            for page in pages:
                out.extend(page.get("RecoveryPoints", []))
        except ClientError as e:
            # A vault can be deleted between list_backup_vaults and this call.
            # That is churn (the resource stopped existing), not a coverage
            # gap -- everything else (AccessDenied, throttling, ...) must
            # propagate so the runner's gap classification sees it, the same
            # distinction the other filters in this package make explicit.
            if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return out
            raise
        return out

    def get_resources(self, resource_ids, cache=True):
        # No API resolves a recovery point by ARN alone without already
        # knowing its vault. Only used for --resource-ids / related-resource
        # lookups, not the normal policy run, so re-enumerating and filtering
        # is fine.
        ids = set(resource_ids)
        return [r for r in self.resources({}) if r.get("RecoveryPointArn") in ids]


@resources.register("backup-recovery-point")
class BackupRecoveryPoint(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "backup"
        enum_spec = ("list_recovery_points_by_backup_vault", "RecoveryPoints", None)
        id = "RecoveryPointArn"
        name = "ResourceName"
        date = "CreationDate"
        arn = "RecoveryPointArn"
        arn_type = "recovery-point"
        config_type = cfn_type = "AWS::Backup::RecoveryPoint"

    source_mapping = {"describe": DescribeRecoveryPoints}


# `resources.register` above only adds the class to the DYNAMIC registry
# (`AWS.resources`, a PluginRegistry). `custodian validate` and policy loading
# go through `Provider.get_resource_class`, which checks membership in the
# STATIC `AWS.resource_map` dict instead (c7n/resources/resource_map.py) and
# raises "Invalid resource" if the name isn't there -- it never looks at the
# dynamic registry for that check. Every one of c7n's own resource types is
# pre-listed in that dict; a type registered only through this package's
# import-time decorator is invisible to that specific lookup. Adding the
# class itself (not a dotted-path string) to the same dict is enough --
# `import_resource_classes` already special-cases a `type` value there and
# skips the module import it would otherwise need.
from c7n.resources.aws import AWS  # noqa: E402
AWS.resource_map["aws.backup-recovery-point"] = BackupRecoveryPoint


@BackupRecoveryPoint.filter_registry.register("unencrypted")
class UnencryptedRecoveryPoint(Filter):
    """Recovery points where `IsEncrypted` is present and false.

    An ABSENT `IsEncrypted` is not read as "encrypted": it is annotated
    `c7n:BackupEncryptionUnknown` and left out of the match, i.e. treated as
    undetermined rather than as a clean result or as a finding. See the
    module docstring for why: the key is normally present, but the filter has
    to hold on the day it is not.
    """

    schema = type_schema("unencrypted")
    permissions = ()
    annotation = "c7n:BackupUnencrypted"

    def process(self, resources, event=None):
        matched = []
        for r in resources:
            valor = r.get("IsEncrypted")
            if valor is None:
                r["c7n:BackupEncryptionUnknown"] = True
                continue
            if valor is False:
                r[self.annotation] = {
                    "BackupVaultName": r.get("BackupVaultName"),
                    "ResourceType": r.get("ResourceType"),
                    "ResourceArn": r.get("ResourceArn"),
                }
                matched.append(r)
        return matched
