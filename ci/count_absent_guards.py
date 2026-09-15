"""Counts the policies that compare a boolean to false without an absent guard.

In c7n a key missing from the resource dict is None, and `None == False` is
False, so `key: X, value: false` does NOT match a resource where AWS never
returned X: it reads as compliant. The shape this catalogue uses is an `or`
with a second `value: absent` branch.

This counts how many policies follow it and how many do not, from the files,
so the number in the write-up is one anybody can recompute rather than one
they have to believe.

Two details that change the answer and are easy to get wrong:

  - a guard on a PARENT path protects every child under it, so a policy
    comparing `A.B.C` to false is guarded by `value: absent` on `A`
  - filters nest under `attrs:` as well as under or/and/not (the list-item
    filters do this), and a walk that only follows the boolean operators
    misses them

Usage, from the repository root:

    python ci/count_absent_guards.py [--list]
"""
from __future__ import annotations

import glob
import sys

import yaml

POLICIES = "policies/aws/*.yml"


def leaves(node, found):
    """Every leaf filter under `node`, through operators and attrs alike."""
    if isinstance(node, list):
        for item in node:
            leaves(item, found)
        return
    if not isinstance(node, dict):
        return
    for operator in ("or", "and", "not"):
        if isinstance(node.get(operator), list):
            leaves(node[operator], found)
            return
    if isinstance(node.get("attrs"), list):
        leaves(node["attrs"], found)
        # the wrapper itself is not a comparison, only its attrs are
        return
    found.append(node)


def guarded(key, absent_keys):
    return any(key == a or key.startswith(a + ".") for a in absent_keys)


def audit():
    """[(policy name, file, [unguarded keys])] plus the total that compare false."""
    total = 0
    gaps = []
    for path in sorted(glob.glob(POLICIES)):
        document = yaml.safe_load(open(path, encoding="utf-8")) or {}
        for policy in document.get("policies") or []:
            found = []
            leaves(policy.get("filters") or [], found)
            compared = [f["key"] for f in found
                        if f.get("value") is False and f.get("key")]
            absent = [f["key"] for f in found
                      if f.get("value") == "absent" and f.get("key")]
            if not compared:
                continue
            total += 1
            missing = [k for k in compared if not guarded(k, absent)]
            if missing:
                gaps.append((policy["name"], path, missing))
    return total, gaps


def main() -> int:
    total, gaps = audit()
    print(f"policies comparing a boolean key to false: {total}")
    print(f"without an absent branch for that key:     {len(gaps)}")

    if "--list" in sys.argv:
        print()
        for name, path, keys in gaps:
            print(f"  {name}")
            print(f"    {path}")
            for key in keys:
                print(f"    key: {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
