#!/usr/bin/env python3
"""Print the single source-of-truth version (from iuk_netscope.py)."""
import re
from pathlib import Path

src = (Path(__file__).resolve().parent.parent / "iuk_netscope.py").read_text(encoding="utf-8")
print(re.search(r'__version__ = "([^"]+)"', src).group(1))
