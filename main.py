#!/usr/bin/env python3
"""Entry point for PGUPS Downloader CLI."""

import sys
from pathlib import Path

# Ensure project root is on sys.path so pgups package is importable
project_root = Path(__file__).parent.resolve()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from pgups.downloader import main

if __name__ == "__main__":
    main()
