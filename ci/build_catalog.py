"""Builds site/data/catalog.json and results.json for the browsable catalogue.

The frameworks pages (generate_frameworks.py) answer "how much of FSBP/PCI/
CIS do we cover". This script answers the question a page cannot: for ONE
policy, on ONE example resource, which branch of the filter tree is the
reason it matched or not. That is c7n_kit's trace() applied across the
whole repository, walked ahead of time and written to disk, because a
static site has no c7n engine to run in the browser.

Neither output is committed (see .gitignore): they are a snapshot of the
CURRENT tree -- a policy edited without regenerating them would make the
committed file lie about what the policy now does, which is the exact
failure this repository's generated pages exist to prevent (see the
docstring of generate_frameworks.py). So the catalogue is a build step,
run fresh, not a checked-in artifact.

WHERE THE EXAMPLE RESOURCES COME FROM
Nowhere new: the fixtures already living in tests/aws/test_*.py, each a
literal `resources = [...]` list a human wrote to nail down one behaviour
(see c7n_kit/testing.py's module docstring on why hand-written fixtures
matter more than real account data). Reusing them means the catalogue's
examples are exactly the cases someone thought worth a test, including the
absent-key ones that are the whole point of this repository, and it never
drifts from the suite: a fixture that stops representing real behaviour
fails its own test first.

Extraction goes through `ast` rather than importing the test modules,
because importing them would also run pytest collection machinery for no
reason and because `ast.literal_eval` is the correct tool for "is this
argument actually a fixture" -- a list built with a helper function (as
test_s3.py does) is not literal, and guessing its value would be exactly
the kind of invented data this repository argues against. Those functions
are skipped and counted, not silently dropped.
"""
import ast
import copy
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = "policies/aws"
TESTS_DIR = "tests/aws"
OUT_DIR = Path("site/data")

# Registers this pack's custom filters (internet-reachable, insecure-transport,
# ...) before anything builds a policy. Without this, every policy that uses
# one traces as `unknown` -- a real result, but a needlessly pessimistic one,
# since the filter DOES exist, c7n just hasn't heard of it in this process yet.
sys.path.insert(0, str(REPO_ROOT / "extensions"))
import c7n_pack  # noqa: E402,F401  importing it is what registers the filters

# generate_frameworks.py already answers "which controls exist, which are
# covered": reusing read_catalog/read_policies/CATALOGS is the point, not
# duplicating that logic here with room for the two to disagree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_frameworks as gf  # noqa: E402

from c7n_kit.policies import load as load_policies  # noqa: E402
from c7n_kit.trace import trace  # noqa: E402

# Preference order for the key an example is labelled with, most specific
# suffix first. "DBInstanceIdentifier" and "GroupId" both end in something
# from this list; a key that does not is not an obvious id and the example
# falls back to "example N" rather than a guess.
_ID_SUFFIXES = ("Identifier", "Name", "Id", "Arn")

NAME_LINE = re.compile(r"^(?P<indent>\s*)- name: (?P<name>\S.*)$")


def locate_yaml_block(path, name):
    """The exact bytes of policy `name`'s block inside `path`, or None.

    Deliberately not a re-dump of the parsed YAML: `yaml.safe_dump` reorders
    keys, rewraps folded scalars and drops comments, so a re-dump would show
    something a reader could not find by searching the file. This instead
    finds `- name: <name>` and takes every line up to the next sibling at
    the same indentation, i.e. exactly what's on disk.
    """
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    start, indent = None, None
    for i, line in enumerate(lines):
        match = NAME_LINE.match(line.rstrip("\n"))
        if match and match.group("name") == name:
            start, indent = i, match.group("indent")
            break
    if start is None:
        return None

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if NAME_LINE.match(lines[j]) and lines[j].startswith(f"{indent}- name: "):
            end = j
            break
    return "".join(lines[start:end]).rstrip()


def _id_key(resources):
    """The key shared by every dict in `resources` that looks like an id, or None."""
    if not resources or not all(isinstance(r, dict) for r in resources):
        return None
    for suffix in _ID_SUFFIXES:
        for key in resources[0]:
            if key.endswith(suffix) and all(key in r for r in resources):
                return key
    return None


def extract_fixtures():
    """Every test's literal `resources = [...]` fixture, keyed by policy name.

    Returns (fixtures, skipped): `fixtures[policy_name]` is a list of
    resource-lists (one per test function that exercises that policy),
    `skipped` is "file:function" for every test whose `resources` could not
    be read with ast.literal_eval -- built with a helper call, as
    test_s3.py's ACL and policy-document fixtures are, rather than written
    as a literal.
    """
    fixtures, skipped = {}, []

    for path in sorted(glob.glob(f"{TESTS_DIR}/test_*.py")):
        tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
        for func in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                     and n.name.startswith("test_")):
            assign = next(
                (n for n in ast.walk(func) if isinstance(n, ast.Assign)
                 and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id == "resources"),
                None)
            if assign is None:
                continue
            try:
                resources = ast.literal_eval(assign.value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                skipped.append(f"{path}:{func.name}")
                continue
            if not isinstance(resources, list):
                skipped.append(f"{path}:{func.name}")
                continue

            for call in ast.walk(func):
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == "run_policy"):
                    continue
                if len(call.args) < 3:
                    continue
                name_arg, resources_arg = call.args[1], call.args[2]
                if not (isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)):
                    continue
                if not (isinstance(resources_arg, ast.Name) and resources_arg.id == "resources"):
                    continue
                fixtures.setdefault(name_arg.value, []).append(resources)

    return fixtures, skipped


def build_examples(resource_lists):
    """Flattens `resource_lists` into (label, resource) pairs, one per resource."""
    examples, seen = [], 0
    for resources in resource_lists:
        id_key = _id_key(resources)
        for resource in resources:
            seen += 1
            value = resource.get(id_key) if id_key else None
            if isinstance(value, (str, int, float, bool)):
                label = str(value)
            else:
                label = f"example {seen}"
            examples.append((label, resource))
    return examples


def node_to_dict(node, path):
    return {"path": path, "kind": node.kind, "result": node.result, "raw": node.raw}


def flatten_with_paths(root):
    """`root`'s children, depth first, each carrying its dot-joined path.

    The root itself (the implicit `and` c7n treats `filters:` as) is not a
    node here: it has no line in the YAML to point at. Its own verdict is
    reported separately as "root", and "0", "0.0", "0.1", ... number the
    filters the policy actually wrote, in file order, so a viewer can walk
    the YAML and the trace in lockstep with no re-parsing.
    """
    out = []

    def walk(node, prefix):
        for i, child in enumerate(node.children):
            path = f"{prefix}{i}" if not prefix else f"{prefix}.{i}"
            out.append(node_to_dict(child, path))
            walk(child, path)

    walk(root, "")
    return out


def main():
    policies = load_policies(POLICIES_DIR)
    files = sorted(set(p.file for p in policies))

    fixtures, skipped_tests = extract_fixtures()

    catalog_policies = []
    results = {}
    yaml_missing = 0
    traced_ok = traced_error = examples_total = policies_with_examples = 0

    for policy in policies:
        metadata = policy.metadata or {}
        yaml_block = locate_yaml_block(policy.file, policy.name)
        if yaml_block is None:
            yaml_missing += 1

        resource_lists = fixtures.get(policy.name)
        has_examples = bool(resource_lists)
        if has_examples:
            policies_with_examples += 1

        catalog_policies.append({
            "name": policy.name,
            "resource": policy.resource,
            "file": policy.file,
            "severity": metadata.get("severity"),
            "category": metadata.get("category"),
            "frequency": metadata.get("frequency"),
            "frameworks": metadata.get("frameworks") or [],
            "yaml": yaml_block,
            "filters": policy.raw.get("filters") or [],
            "has_examples": has_examples,
        })

        if not has_examples:
            continue

        examples = []
        for label, resource in build_examples(resource_lists):
            examples_total += 1
            try:
                root = trace(policy.raw, copy.deepcopy(resource))
                examples.append({
                    "label": label,
                    "resource": resource,
                    "root": root.result,
                    "nodes": flatten_with_paths(root),
                })
                traced_ok += 1
            except Exception as exc:  # noqa: BLE001  a policy that cannot be
                # traced at all (an unregistered custom filter, a schema the
                # installed c7n doesn't know) is a result, not a crash: it
                # goes in as `unknown`, with the reason, instead of vanishing.
                examples.append({
                    "label": label,
                    "resource": resource,
                    "root": "unknown",
                    "nodes": [],
                    "error": str(exc),
                })
                traced_error += 1
        results[policy.name] = {"examples": examples}

    frameworks = {}
    by_control = gf.read_policies()
    for key, (path, _title, _prefix, _grouping) in gf.CATALOGS.items():
        if not os.path.exists(path):
            continue
        controls, complete = gf.read_catalog(path)
        covered = sum(1 for c in controls if by_control.get(c))
        frameworks[key] = {"covered": covered, "total": len(controls), "complete": bool(complete)}

    controls_out = []
    for key, (path, _title, _prefix, _grouping) in gf.CATALOGS.items():
        if not os.path.exists(path):
            continue
        controls, _complete = gf.read_catalog(path)
        for control in controls:
            entries = by_control.get(control) or []
            severities = {s for _, _, s in entries if s}
            severity = next((level for level in gf.ORDER if level in severities), None)
            controls_out.append({
                "framework": key,
                "id": control,
                "covered": bool(entries),
                "policies": [n for n, _, _ in entries],
                "severity": severity,
            })

    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT,
        capture_output=True, text=True, check=True).stdout.strip()

    catalog = {
        "commit": commit,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "policies": len(policies),
            "files": len(files),
            "frameworks": frameworks,
        },
        "policies": catalog_policies,
        "controls": controls_out,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "catalog.json", "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
    with open(OUT_DIR / "results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"{len(policies)} policies across {len(files)} files")
    print(f"{policies_with_examples} policies have examples, "
          f"{examples_total} examples total")
    print(f"traced: {traced_ok} ok, {traced_error} with error")
    print(f"{yaml_missing} yaml block(s) could not be located")
    print(f"{len(skipped_tests)} test function(s) skipped, fixtures not literal")

    if not policies:
        print("\nno policies written, that is not a valid catalogue")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
