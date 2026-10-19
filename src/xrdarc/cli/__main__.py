"""``python -m xrdarc.cli``: the same as the ``xrdarc`` command.

For a machine where the console script is not on ``PATH`` (a user install,
a batch node's bare virtual environment). ``main`` returns the exit status
rather than exiting itself, so tests can call it; this is where it becomes
the process's.
"""

import sys

from . import main

sys.exit(main())
