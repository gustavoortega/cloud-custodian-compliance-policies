"""Runs `custodian validate` with this pack's custom filters registered.

WHY THIS EXISTS AND `custodian validate` ALONE DOES NOT WORK

c7n discovers a filter when the module that registers it has been imported
into the *same* process. Putting `extensions/` on PYTHONPATH and importing
`c7n_pack` in one command does nothing for the `custodian` command that runs
after it: that is a second process, with its own registry, and the filters
this pack ships are simply unknown there.

The failure is quiet in the worst way. `custodian validate` reports
`Invalid filter type` and exits non-zero, so at least it is loud. But the
same mistake in a `custodian run` would enumerate the resources, match
nothing, and write an empty result that reads as "no findings".

So validation goes through one process that imports first and validates
after.
"""
import glob
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "extensions"))

import c7n_pack  # noqa: E402,F401  importing it is what registers the filters

from c7n.cli import main  # noqa: E402

policies = sorted(glob.glob("policies/aws/*.yml"))
if not policies:
    sys.exit("no policy files found under policies/aws/")

print(f"validating {len(policies)} files with the pack's filters registered")
sys.argv = ["custodian", "validate", *policies]
main()
