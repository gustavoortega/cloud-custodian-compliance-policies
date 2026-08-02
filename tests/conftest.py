"""Makes the pack's custom filters importable before any test runs.

Some policies use filters this pack ships itself (`latest-revision`,
`external-trust`, `insecure-transport`, the `aws.backup-recovery-point`
resource). c7n only knows about them once the module that registers them
has been imported, so it happens here, once, rather than in each test file.

`C7N_PACK_EXTENSIONS` overrides the location. It is read from the
environment so nobody has to edit a file to run the suite from a different
checkout.
"""
import os
import sys
from pathlib import Path

_DEFAULT = Path(__file__).resolve().parent.parent / "extensions"
_EXTENSIONS = Path(os.environ.get("C7N_PACK_EXTENSIONS", _DEFAULT))

if _EXTENSIONS.is_dir():
    sys.path.insert(0, str(_EXTENSIONS))
    try:
        import c7n_pack  # noqa: F401  (importing it is what registers the filters)
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            f"found {_EXTENSIONS} but could not import the custom filters from "
            f"it ({exc}). The policies that use them will fail to build."
        ) from exc
