"""Test configuration for the certificate validation exercises."""

from __future__ import annotations

import sys
from pathlib import Path

_SOURCE = Path(__file__).resolve().parents[1] / "src"
if _SOURCE.is_dir() and str(_SOURCE) not in sys.path:
    sys.path.insert(0, str(_SOURCE))