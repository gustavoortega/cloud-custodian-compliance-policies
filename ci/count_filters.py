"""Counts the custom filters this repository registers.

The README said "Custom filters: 10". Ten is the number of .py files in
extensions/c7n_pack/filters/, and a file is not a filter: some register
more than one, and several register the same filter on more than one
resource type. Counting files and calling them filters is the same shape
of error as counting a policy that matched nothing and calling the account
clean.

This counts three different things and prints all three, because they are
genuinely different numbers and the README has to say which one it means:

    modules        files under extensions/c7n_pack/filters/
    filters        distinct filter names a policy can write
    registrations  (filter, resource type) pairs actually registered

Usage, from the repository root:

    python ci/count_filters.py
"""
from __future__ import annotations

import ast
import pathlib

FILTERS_DIR = pathlib.Path("extensions/c7n_pack/filters")


def registrations() -> list[tuple[str, str]]:
    """[(module, filter name)] for every `...register("name")` in the pack.

    Read with `ast` rather than by importing: the count must not depend on
    c7n's import side effects, and a module that fails to import for an
    unrelated reason would otherwise silently lower the number.
    """
    found: list[tuple[str, str]] = []
    for path in sorted(FILTERS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "register":
                continue
            if not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.append((path.stem, first.value))
    return found


def main() -> int:
    pairs = registrations()
    names = sorted({name for _, name in pairs})
    modules = len([p for p in FILTERS_DIR.glob("*.py") if p.name != "__init__.py"])

    print(f"modules:       {modules}")
    print(f"filters:       {len(names)}")
    print(f"registrations: {len(pairs)}")
    print()
    for name in names:
        times = sum(1 for _, n in pairs if n == name)
        print(f"  {name:<34} registered {times}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
