from __future__ import annotations

import sys


if sys.platform == "win32":
    from semgrep.console_scripts.pysemgrep import main
else:
    from semgrep.console_scripts.entrypoint import main


if __name__ == "__main__":
    main()
