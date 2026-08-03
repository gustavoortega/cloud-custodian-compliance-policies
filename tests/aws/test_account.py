"""Behavioural tests for policies/aws/account.yml.

Offline: no AWS credentials, no network.

`emr-account-block-public-access-disabled` uses c7n's
`emr-block-public-access` filter, which is a ValueFilter that first
ANNOTATES the account with the response of
`elasticmapreduce:GetBlockPublicAccessConfiguration` and then evaluates
its `key`/`value` against that annotation, not against the account dict.
Its `process()` builds the emr client unconditionally -- even when every
resource already carries the annotation -- so the fetch has to be
neutralised for the filter to be evaluable offline. `_no_augment` below
does exactly that and nothing else: the annotation is written by hand in
the fixture, and the part under test (the JMESPath and the comparison,
which is where the bug lives) is c7n's real code, unmodified.
"""
import pytest

from c7n.resources.account import EMRBlockPublicAccessConfiguration
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/account.yml'
EMR_BPA = 'c7n:emr-block-public-access'


@pytest.fixture(autouse=True)
def _no_augment(monkeypatch):
    """Stops the filter from calling GetBlockPublicAccessConfiguration.

    Only the AWS round trip is replaced. Every fixture below supplies the
    annotation the real call would have written, so the filter evaluates
    exactly the data a live run would have handed it.
    """
    monkeypatch.setattr(
        EMRBlockPublicAccessConfiguration, 'augment', lambda self, resources: None)


def account(**config):
    """An aws.account resource already annotated with an EMR BPA config."""
    return {'account_id': '000000000000',
            EMR_BPA: {'BlockPublicAccessConfiguration': config}}


RANGES = 'PermittedPublicSecurityGroupRuleRanges'
POLICY = 'emr-account-block-public-access-disabled'


def test_emr_account_block_public_access_disabled():
    resources = [
        # block-public-access switched off: the first branch of the `or`.
        account(BlockPublicSecurityGroupRules=False,
                **{RANGES: [{'MinRange': 22, 'MaxRange': 22}]}),
    ]
    assert len(run_policy(POLICIES, POLICY, resources)) == 1


def test_emr_account_block_public_access_permits_a_port_other_than_22():
    resources = [
        account(BlockPublicSecurityGroupRules=True,
                **{RANGES: [{'MinRange': 22, 'MaxRange': 22},
                            {'MinRange': 8088, 'MaxRange': 8088}]}),
    ]
    assert len(run_policy(POLICIES, POLICY, resources)) == 1


def test_emr_account_block_public_access_on_with_only_22_is_clean():
    resources = [
        account(BlockPublicSecurityGroupRules=True,
                **{RANGES: [{'MinRange': 22, 'MaxRange': 22}]}),
    ]
    assert run_policy(POLICIES, POLICY, resources) == []


def test_emr_account_no_permitted_ranges_is_not_fatal():
    """`length(null)` used to abort the run; the guard turns it into a skip.

    `PermittedPublicSecurityGroupRuleRanges` is optional in the EMR API
    model and is an ALLOW-list: no list means nothing is permitted through,
    which is the safest state and not a finding. Without the `not-null`
    guard inside the second branch this raises `In function length(),
    invalid type for value: None` and the whole account/region run stops
    producing output.
    """
    resources = [account(BlockPublicSecurityGroupRules=True)]
    assert run_policy(POLICIES, POLICY, resources) == []


def test_emr_account_block_public_access_off_and_no_ranges_still_reported():
    """The guard must not swallow the critical case.

    An account with block-public-access OFF is the finding this control
    exists for, and it is the one whose response is most likely to carry no
    permitted-range list at all. The guard sits inside the second branch of
    the `or`, so the first branch still fires here. A guard placed in front
    of the `or` would turn this account into a silent pass.
    """
    resources = [account(BlockPublicSecurityGroupRules=False)]
    assert len(run_policy(POLICIES, POLICY, resources)) == 1
