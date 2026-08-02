"""Fails the build when a policy does not declare what it covers.

TWO KINDS OF CHECK, ON PURPOSE

Hard failures are things that are wrong no matter what: a severity that
isn't one of the five, a frequency the runner doesn't understand, a control
citation whose family doesn't exist. Those are typos and they fail the PR.

Everything else is measured against `ci/metadata-baseline.txt`, a frozen
list of the policies that are incomplete today. A policy on that list may
stay incomplete; a policy that is NOT on it must be complete. So the gap
can only shrink, and a new policy cannot arrive without declaring itself.

WHY `frameworks` IS NOT SIMPLY REQUIRED

Because requiring it is how you get invented citations. A policy can
legitimately implement a good practice that no framework covers, and the
honest answer there is to cite nothing. Forcing every policy to name a
control teaches people to reach for the nearest plausible ID, which is
precisely the orphan this repo's coverage gate exists to catch.
"""
import glob
import os
import sys

import yaml

REQUIRED = ("severity", "category", "frameworks", "frequency")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
FREQUENCIES = {"4h", "daily"}
FAMILIES = {"FSBP", "PCI", "CIS", "SOX"}
BASELINE = "ci/metadata-baseline.txt"

known_incomplete = set()
if os.path.exists(BASELINE):
    known_incomplete = {
        line.strip() for line in open(BASELINE)
        if line.strip() and not line.startswith("#")
    }

hard, regressions, still_incomplete = [], [], set()
total = 0

for path in sorted(glob.glob("policies/aws/*.yml")):
    for policy in yaml.safe_load(open(path))["policies"]:
        total += 1
        name = policy["name"]
        where = f"{path}:{name}"
        metadata = policy.get("metadata") or {}

        severity = metadata.get("severity")
        if severity is not None and severity not in SEVERITIES:
            hard.append(f"{where}: severity {severity!r} is not one of {sorted(SEVERITIES)}")
        frequency = metadata.get("frequency")
        if frequency is not None and frequency not in FREQUENCIES:
            hard.append(f"{where}: frequency {frequency!r} is not one of {sorted(FREQUENCIES)}")
        for cited in metadata.get("frameworks") or []:
            family = str(cited).split(None, 1)[0]
            if family not in FAMILIES:
                hard.append(f"{where}: {cited!r} does not start with a known family {sorted(FAMILIES)}")

        absent = [f for f in REQUIRED if not metadata.get(f)]
        if absent:
            still_incomplete.add(name)
            if name not in known_incomplete:
                regressions.append(f"{where}: missing {', '.join(absent)}")

print(f"{total} policies checked")
print(f"{len(still_incomplete)} incomplete, {len(known_incomplete)} allowed by the baseline")

if hard:
    print(f"\n{len(hard)} malformed value(s):\n")
    for problem in hard:
        print(f"  {problem}")
if regressions:
    print(f"\n{len(regressions)} new policy/policies without metadata:\n")
    for problem in regressions:
        print(f"  {problem}")
    print(f"\nFill them in. Do not add them to {BASELINE}: that list only shrinks.")

fixed = known_incomplete - still_incomplete
if fixed:
    print(f"\n{len(fixed)} policy/policies were completed and can leave the baseline:")
    for name in sorted(fixed):
        print(f"  {name}")

if hard or regressions:
    sys.exit(1)
print("\nno malformed values, no new policy without metadata")
