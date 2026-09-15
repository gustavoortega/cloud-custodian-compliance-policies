"""Counts, from the files, how many policies commit 8a93cc4 actually changed.

The write-up says 74 policies were silently broken. That number came from
counting by hand while the work was happening, and it cannot be
reproduced: the commit message itself says "Four never worked at all" and
then names three, and says "Nine were left alone on purpose" while
listing eight. A number in a published post is a claim, and this
repository's whole argument is that a claim you cannot recompute is worth
nothing.

So this recomputes it. For every policy present at both revisions it
compares the `filters` block, which is the thing that decides whether a
resource is reported:

    changed   the filters differ: the policy behaved differently before
    added     it did not exist before the commit
    untouched the filters are byte-identical

`left alone` is not derived from the diff, because a policy deliberately
left without an `absent` branch looks exactly like one nobody looked at.
It is read from the DELIBERATE markers the files carry today.

Usage, from the repository root:

    python ci/recount_fixed_policies.py [commit]
"""
from __future__ import annotations

import subprocess
import sys

import yaml

COMMIT = sys.argv[1] if len(sys.argv) > 1 else "8a93cc4"
POLICY_GLOB = "policies/aws"


def policies_at(rev: str) -> dict[str, dict]:
    """{policy name: its filters} for every policy file at `rev`."""
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", rev, POLICY_GLOB],
        capture_output=True, text=True, check=True).stdout.split()

    out: dict[str, dict] = {}
    for path in listing:
        if not path.endswith((".yml", ".yaml")):
            continue
        blob = subprocess.run(["git", "show", f"{rev}:{path}"],
                              capture_output=True, text=True, check=True).stdout
        for policy in (yaml.safe_load(blob) or {}).get("policies") or []:
            out[policy["name"]] = policy.get("filters")
    return out


def deliberate_today() -> int:
    """Policies that carry a DELIBERATE marker in the files right now.

    Counted per policy, not per comment line: two markers inside the same
    policy are one decision, and counting lines is how "eight" became
    "nine" and then "ten" in three different places.
    """
    names = set()
    for path in subprocess.run(
            ["git", "ls-files", POLICY_GLOB], capture_output=True,
            text=True, check=True).stdout.split():
        current = None
        for line in open(path, encoding="utf-8"):
            stripped = line.strip()
            if stripped.startswith("- name:"):
                current = stripped.split(":", 1)[1].strip()
            elif "DELIBERATE" in stripped and current:
                names.add(current)
    return len(names)


def main() -> int:
    before = policies_at(f"{COMMIT}~1")
    after = policies_at(COMMIT)

    changed = [n for n, f in after.items()
               if n in before and before[n] != f]
    added = [n for n in after if n not in before]
    removed = [n for n in before if n not in after]

    print(f"commit {COMMIT}")
    print(f"  policies before: {len(before)}")
    print(f"  policies after:  {len(after)}")
    print(f"  filters changed: {len(changed)}")
    print(f"  added:           {len(added)}")
    print(f"  removed:         {len(removed)}")
    print(f"  DELIBERATE today:{deliberate_today():>3}")
    print()
    print("changed:")
    for name in sorted(changed):
        print(f"  {name}")
    if added:
        print("added:")
        for name in sorted(added):
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
