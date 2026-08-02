"""Custom c7n extensions.

Modules are imported for their side effect: each one registers itself in the
filter_registry of the resource it extends. Importing this package is enough for
policies to be able to use them.
"""
from c7n_pack import filters  # noqa: F401
