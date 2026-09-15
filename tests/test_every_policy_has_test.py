"""The list of policies with no test can only get shorter.

104 of the 325 policies are not named in any test. The README says every
policy is tested offline, and for two thirds of them that is true; for the
rest it was a claim nobody had measured. Deleting the claim would be
dishonest in the other direction, and writing 104 tests before shipping
anything else is not going to happen.

So the gap is written down, in tests/untested_policies.txt, and this test
holds it as a ratchet:

    a policy added without a test        -> fails, the file would have to grow
    a policy that gained a test          -> fails until it leaves the file
    the file matching reality exactly    -> passes

The failure message says what to do in each direction. The point is that
the number is visible and can only move one way.
"""
from __future__ import annotations

import glob
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "tests" / "untested_policies.txt"


def policy_names() -> set[str]:
    names = set()
    for path in sorted((ROOT / "policies" / "aws").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for policy in document.get("policies") or []:
            names.add(policy["name"])
    return names


def names_mentioned_in_tests() -> str:
    """Every test file as one blob.

    A policy counts as tested when a test names it. That is a weaker
    statement than "a test exercises it", and it is the strongest one that
    can be checked without running c7n over every policy, which is what the
    behavioural suite already does for the ones it covers.
    """
    blob = []
    for path in glob.glob(str(ROOT / "tests" / "**" / "*.py"), recursive=True):
        if pathlib.Path(path).name == pathlib.Path(__file__).name:
            continue
        blob.append(pathlib.Path(path).read_text(encoding="utf-8"))
    return "\n".join(blob)


def test_the_untested_list_matches_the_repository():
    declared = {line.strip() for line in
                LEDGER.read_text(encoding="utf-8").splitlines() if line.strip()}
    blob = names_mentioned_in_tests()
    actual = {name for name in policy_names() if name not in blob}

    gained_a_test = sorted(declared - actual)
    newly_untested = sorted(actual - declared)

    assert not newly_untested, (
        "these policies have no test and are not in tests/untested_policies.txt:\n  "
        + "\n  ".join(newly_untested)
        + "\n\nWrite the test. The list is not where new policies go."
    )
    assert not gained_a_test, (
        "these policies now have a test and must leave "
        "tests/untested_policies.txt:\n  "
        + "\n  ".join(gained_a_test)
        + "\n\nRemove those lines: the list only shrinks."
    )
