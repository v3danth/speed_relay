"""Entry point for ``python -m torrelay``."""

# pylint: disable=invalid-name  # __main__ is mandated by Python.

import sys

from torrelay import cli

sys.exit(cli.main())
