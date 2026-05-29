"""P4 — safety gate and mainnet-mode opt-in tests.

The default mode is regtest. Switching to mainnet requires an explicit
keyword argument *and* (when via CLI) an explicit second flag. This
test suite verifies both surfaces.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from channel.safety import (  # noqa: E402
    MAINNET_BANNER,
    Mode,
    RESEARCH_BANNER,
    SafetyError,
    current_mode,
    is_mainnet,
    require_safe_mode,
    set_mode,
)


# ---------------------------------------------------------------------------
# In-process API
# ---------------------------------------------------------------------------


def test_default_mode_is_regtest() -> None:
    # Note: tests share the module-global; reset to regtest first to be safe.
    set_mode(Mode.REGTEST)
    assert current_mode() is Mode.REGTEST
    assert not is_mainnet()


def test_mainnet_switch_requires_explicit_ack() -> None:
    set_mode(Mode.REGTEST)
    with pytest.raises(SafetyError):
        set_mode(Mode.MAINNET)
    assert not is_mainnet()


def test_mainnet_switch_with_ack_works() -> None:
    try:
        set_mode(Mode.MAINNET, i_understand_this_is_research_code=True)
        assert is_mainnet()
        # require_safe_mode succeeds because we confirmed.
        require_safe_mode()
    finally:
        set_mode(Mode.REGTEST)
    assert not is_mainnet()


def test_research_banner_text_is_present() -> None:
    # The banner contains the warning phrase that downstream tooling
    # (grep, log scanners) can rely on.
    assert "RESEARCH CODE" in RESEARCH_BANNER
    assert "regtest" in RESEARCH_BANNER.lower()


def test_mainnet_banner_text_is_present() -> None:
    assert "MAINNET" in MAINNET_BANNER
    assert "RISK" in MAINNET_BANNER.upper()


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    src = os.path.abspath(os.path.join(_HERE, "..", "src"))
    env = os.environ.copy()
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "channel.cli", *args],
        capture_output=True, text=True, env=env, timeout=30,
        encoding="utf-8", errors="replace",
    )


def test_cli_emits_research_banner_by_default(tmp_path) -> None:
    proc = _run_cli("open", "--parties", "3", "--k", "1000",
                    "--funded", "1", "--bond", "1",
                    "--out", str(tmp_path / "ch.json"))
    assert proc.returncode == 0
    assert "RESEARCH CODE" in proc.stderr


def test_cli_no_banner_flag_suppresses_banner(tmp_path) -> None:
    proc = _run_cli("--no-banner", "open", "--parties", "3", "--k", "1000",
                    "--funded", "1", "--bond", "1",
                    "--out", str(tmp_path / "ch.json"))
    assert proc.returncode == 0
    assert "RESEARCH CODE" not in proc.stderr


def test_cli_mainnet_without_confirmation_rejected(tmp_path) -> None:
    proc = _run_cli("--mainnet", "open", "--parties", "3", "--k", "1000",
                    "--funded", "1", "--bond", "1",
                    "--out", str(tmp_path / "ch.json"))
    assert proc.returncode != 0
    assert "i-understand" in proc.stderr.lower()
