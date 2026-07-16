"""Shared pytest fixtures for the packpeek test suite.

The C integration tests need a compiled ``packpeek`` binary. This module
discovers a C compiler and builds the binary once per session into a temporary
directory. If no compiler is available (e.g. a docs-only dev box) the fixture
skips the dependent tests rather than failing — the pure-Python tests for the
SARIF/YARA/Markdown companion still run everywhere.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "packpeek.c"


def _find_compiler() -> str | None:
    for cc in ("cc", "gcc", "clang", "x86_64-w64-mingw32-gcc"):
        found = shutil.which(cc)
        if found:
            return found
    return None


@pytest.fixture(scope="session")
def packpeek_bin(tmp_path_factory) -> str:
    """Compile packpeek.c and return the path to the binary."""
    cc = _find_compiler()
    if not cc:
        pytest.skip("no C compiler available to build packpeek.c")
    out_dir = tmp_path_factory.mktemp("packpeek-build")
    exe = out_dir / ("packpeek.exe" if os.name == "nt" else "packpeek")
    cmd = [cc, "-O2", "-std=c99", "-Wall", "-Wextra",
           "-o", str(exe), str(SOURCE), "-lm"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(f"packpeek.c failed to compile with {cc}:\n{proc.stderr}")
    return str(exe)


@pytest.fixture(scope="session")
def sarif_module():
    """Import sarif.py from the repo root regardless of cwd."""
    sys.path.insert(0, str(ROOT))
    import sarif  # noqa: E402
    return sarif
