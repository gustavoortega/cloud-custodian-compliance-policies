"""Runs `custodian validate` with this pack's custom filters registered.

WHY NOT `custodian validate` DIRECTLY

c7n discovers a filter when the module that registers it has been imported
into the *same* process. Putting `extensions/` on PYTHONPATH and importing
`c7n_pack` in one command does nothing for the `custodian` command that runs
after it: that is a second process, with its own registry, and the filters
this pack ships are unknown there.

WHY POLICIES GET SKIPPED

A few policies use a resource type or a filter that a given c7n release does
not have yet. `aws.transfer-connector` arrived in 0.9.50; the `addon` filter
on `aws.eks` in 0.9.51. Those policies declare `metadata.c7n_min`, and this
script drops them when the installed c7n is older, so the matrix can keep
testing the last three releases without one new resource type failing two of
them.

Skipped is printed, never silent. A policy that quietly disappears from
validation is how a broken one ships.
"""
import glob
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "extensions"))

import c7n_pack  # noqa: E402,F401  importing it is what registers the filters

from c7n.cli import main  # noqa: E402
from c7n.version import version as c7n_version  # noqa: E402


def as_tuple(text):
    return tuple(int(part) for part in str(text).split(".") if part.isdigit())


here = as_tuple(c7n_version)
files = sorted(glob.glob("policies/aws/*.yml"))
if not files:
    sys.exit("no policy files found under policies/aws/")

workdir = Path(tempfile.mkdtemp(prefix="c7n-validate-"))
skipped, kept, out_files = [], 0, []

for path in files:
    data = yaml.safe_load(open(path, encoding="utf-8"))
    keep = []
    for policy in data["policies"]:
        needs = (policy.get("metadata") or {}).get("c7n_min")
        if needs and as_tuple(needs) > here:
            skipped.append((policy["name"], needs))
        else:
            keep.append(policy)
    kept += len(keep)
    target = workdir / Path(path).name
    if keep:
        target.write_text(yaml.dump({"policies": keep}, sort_keys=False),
                          encoding="utf-8")
        out_files.append(str(target))

print(f"c7n {c7n_version}: validating {kept} policies in {len(out_files)} files")
for name, needs in skipped:
    print(f"  skipped {name}: needs c7n >= {needs}")

try:
    sys.argv = ["custodian", "validate", *out_files]
    main()
finally:
    shutil.rmtree(workdir, ignore_errors=True)
