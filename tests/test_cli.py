"""G4 — CLI subprocess tests.

Drive each ``channel`` CLI subcommand via :mod:`subprocess` to confirm
exit codes, key output strings, and the integration boundary between
``argparse``, the lifecycle layer, and the on-disk JSON state file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, "..", "src"))


def _run_cli(*args: str, env: dict[str, str] | None = None,
             timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Invoke the CLI as ``python -m channel.cli <args>`` and capture output."""
    full_env = os.environ.copy()
    # Make src/ importable for the subprocess; equivalent to ``pip install -e .``
    full_env["PYTHONPATH"] = _SRC + os.pathsep + full_env.get("PYTHONPATH", "")
    if env:
        full_env.update(env)
    cmd = [sys.executable, "-m", "channel.cli", *args]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=full_env,
        encoding="utf-8", errors="replace",
    )


# ---------------------------------------------------------------------------
# Part I lifecycle commands
# ---------------------------------------------------------------------------


def test_cli_open_writes_state_file_and_exits_zero(tmp_path: Path) -> None:
    out_path = tmp_path / "ch.json"
    proc = _run_cli("open", "--parties", "3", "--k", "1000",
                    "--funded", "1", "--bond", "1", "--out", str(out_path))
    assert proc.returncode == 0, proc.stderr
    assert out_path.exists()
    assert "opened channel" in proc.stdout
    data = json.loads(out_path.read_text())
    assert data["cfg"]["n"] == 3
    assert data["cfg"]["k"] == 1000


def test_cli_transfer_applies_and_persists(tmp_path: Path) -> None:
    out_path = tmp_path / "ch.json"
    script_path = tmp_path / "transfers.json"
    _run_cli("open", "--parties", "3", "--k", "1000",
              "--funded", "1", "--bond", "1", "--out", str(out_path))
    script_path.write_text(json.dumps([[0, 1, 100], [0, 2, 50]]))
    proc = _run_cli("transfer", "--state", str(out_path),
                    "--script", str(script_path))
    assert proc.returncode == 0, proc.stderr
    assert "applied 2 transfers" in proc.stdout
    assert "new version=2" in proc.stdout


def test_cli_close_prints_payouts_summing_to_S_plus_bonds(tmp_path: Path) -> None:
    out_path = tmp_path / "ch.json"
    _run_cli("open", "--parties", "3", "--k", "1000",
              "--funded", "2", "--bond", "1", "--out", str(out_path))
    proc = _run_cli("close", "--state", str(out_path))
    assert proc.returncode == 0, proc.stderr
    assert "cooperative close" in proc.stdout
    # 3 parties * 1 bond + 2 satoshi funded = 5 sat total.
    assert "total settled: 5 satoshis" in proc.stdout


def test_cli_contested_prints_forfeit(tmp_path: Path) -> None:
    out_path = tmp_path / "ch.json"
    _run_cli("open", "--parties", "4", "--k", "1000",
              "--funded", "1", "--bond", "2", "--out", str(out_path))
    proc = _run_cli("contested", "--state", str(out_path), "--offender", "0")
    assert proc.returncode == 0, proc.stderr
    assert "contested close" in proc.stdout
    assert "offender=0" in proc.stdout
    assert "bond forfeited: 2 satoshis" in proc.stdout


def test_cli_close_on_missing_state_exits_nonzero(tmp_path: Path) -> None:
    proc = _run_cli("close", "--state", str(tmp_path / "does-not-exist.json"))
    assert proc.returncode != 0
    assert "error" in proc.stderr.lower() or proc.returncode == 2


def test_cli_bad_transfer_entry_rejected(tmp_path: Path) -> None:
    out_path = tmp_path / "ch.json"
    script_path = tmp_path / "transfers.json"
    _run_cli("open", "--parties", "3", "--k", "1000",
              "--funded", "1", "--bond", "1", "--out", str(out_path))
    script_path.write_text(json.dumps([[0, 1]]))  # length 2, not 3
    proc = _run_cli("transfer", "--state", str(out_path),
                    "--script", str(script_path))
    assert proc.returncode != 0
    assert "bad transfer entry" in proc.stderr.lower() or proc.returncode == 2


# ---------------------------------------------------------------------------
# Part II daemon commands (smoke; full surface is in test_daemon.py)
# ---------------------------------------------------------------------------


def test_cli_no_subcommand_prints_help() -> None:
    proc = _run_cli()
    assert proc.returncode != 0
    # argparse emits its usage to stderr.
    assert "usage" in proc.stderr.lower() or "error" in proc.stderr.lower()


def test_cli_log_level_flag_accepted(tmp_path: Path) -> None:
    """The global --log-level option does not interfere with subcommand exit."""
    out_path = tmp_path / "ch.json"
    proc = _run_cli("--log-level", "DEBUG", "open", "--parties", "3",
                    "--k", "1000", "--funded", "1", "--bond", "1",
                    "--out", str(out_path))
    assert proc.returncode == 0
    assert out_path.exists()
