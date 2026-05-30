"""End-to-end test for scripts/tiny_transfers_demo.py.

Drives the demo via :mod:`subprocess` and asserts the conservation
markers appear in its output. The demo's assertions are also internal
(non-zero exit on violation), so this test exercises both the script's
correctness and its user-facing output.
"""

from __future__ import annotations

import os
import subprocess
import sys


_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_DEMO = os.path.join(_REPO, "scripts", "tiny_transfers_demo.py")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(_REPO, "src") + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, _DEMO, *args],
        capture_output=True, text=True, env=env, timeout=60,
        encoding="utf-8", errors="replace",
    )


def test_demo_default_run_exits_zero_and_prints_summary() -> None:
    proc = _run()
    assert proc.returncode == 0, f"demo exited {proc.returncode}; stderr={proc.stderr}"
    assert "Tiny-transfers demo" in proc.stdout
    assert "sub-satoshi transfers" in proc.stdout
    assert "Off-chain micro-unit balances" in proc.stdout
    assert "On-chain settlement via Q*" in proc.stdout
    assert "conservation           : OK" in proc.stdout
    assert "SUMMARY" in proc.stdout


def test_demo_small_run_is_quick() -> None:
    """A 50-transfer run finishes well under the test timeout."""
    proc = _run("--transfers", "50", "--seed", "7")
    assert proc.returncode == 0


def test_demo_larger_k_produces_finer_granularity_text() -> None:
    """Higher --k must propagate to the granularity line."""
    proc = _run("--k", "1000000", "--transfers", "10")
    assert proc.returncode == 0
    assert "1/1000000 satoshi" in proc.stdout


def test_demo_more_parties() -> None:
    proc = _run("--parties", "6", "--transfers", "30")
    assert proc.returncode == 0
    # One micro-unit-balance line per party (the off-chain section).
    micro_lines = [
        line for line in proc.stdout.splitlines()
        if "micro-units  =" in line and line.lstrip().startswith("party ")
    ]
    assert len(micro_lines) == 6, (
        f"expected 6 off-chain balance lines, got {len(micro_lines)}"
    )
