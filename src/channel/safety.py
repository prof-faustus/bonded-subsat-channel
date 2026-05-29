"""Safety gate and warning banners — research code, regtest by default.

This module is the single source of truth for the network-mode setting
and the matching warning banners. All other modules that touch keys or
funds should call :func:`require_safe_mode` at the entry points (the CLI,
the daemon, the wallet builder) so a misconfigured mainnet run is
impossible without explicit, deliberate opt-in.

The default mode is :data:`Mode.REGTEST` and corresponds to the
self-contained local network used in every test. Any code path that
attempts to operate on mainnet must:

1. Call :func:`set_mode(Mode.MAINNET)` from an entry point that has
   surfaced the warning banner to the operator.
2. Pass an explicit ``--mainnet --i-understand-this-is-research-code``
   pair of flags to the CLI.

Anything else aborts with :class:`SafetyError`. This is a defence in
depth, not a substitute for the user's judgement.
"""

from __future__ import annotations

import enum
import logging
import os
import sys
import typing
from typing import Final

from .errors import ChannelError


_log = logging.getLogger(__name__)


class SafetyError(ChannelError):
    """Raised when a code path attempts to operate without proper opt-in."""


class Mode(enum.Enum):
    REGTEST = "regtest"
    MAINNET = "mainnet"


# Process-wide mode. Defaults to REGTEST. Set via :func:`set_mode` from a
# CLI / daemon entry point that has surfaced the banner.
_mode: Mode = Mode.REGTEST
_mainnet_confirmed: bool = False


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


RESEARCH_BANNER: Final[str] = (
    "================================================================\n"
    "  WARNING — RESEARCH CODE, NOT FOR PRODUCTION USE\n"
    "  This is a reference implementation accompanying an academic\n"
    "  paper. It runs in regtest only by default. Do NOT connect it\n"
    "  to mainnet, do NOT put real funds in it, do NOT rely on it\n"
    "  for any production purpose. See LICENSE and docs/PRIVACY.md.\n"
    "================================================================"
)


MAINNET_BANNER: Final[str] = (
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    "  MAINNET MODE REQUESTED — this is RESEARCH CODE.\n"
    "  It has had NO independent security audit, NO production\n"
    "  hardening, NO formal verification. Operating it on mainnet\n"
    "  with real funds is at your sole risk and is NOT supported\n"
    "  by the authors.\n"
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
)


_BANNER_SHOWN_KEY = "_CHANNEL_BANNER_SHOWN"


def emit_banner_once(stream: "typing.TextIO" = sys.stderr) -> None:
    """Print the research-code banner once per process to ``stream``."""
    if os.environ.get(_BANNER_SHOWN_KEY) == "1":
        return
    print(RESEARCH_BANNER, file=stream)
    os.environ[_BANNER_SHOWN_KEY] = "1"


# ---------------------------------------------------------------------------
# Mode control
# ---------------------------------------------------------------------------


def current_mode() -> Mode:
    return _mode


def is_mainnet() -> bool:
    return _mode is Mode.MAINNET


def set_mode(mode: Mode, *, i_understand_this_is_research_code: bool = False) -> None:
    """Switch the process mode.

    Switching to :data:`Mode.MAINNET` requires
    ``i_understand_this_is_research_code=True``. The flag is named verbosely
    on purpose: an absent-minded call from a notebook or a script that
    accidentally passes through a config file will not by chance match
    the required keyword.
    """
    global _mode, _mainnet_confirmed
    if mode is Mode.MAINNET:
        if not i_understand_this_is_research_code:
            raise SafetyError(
                "switching to MAINNET requires explicit acknowledgement "
                "via i_understand_this_is_research_code=True"
            )
        _mainnet_confirmed = True
        print(MAINNET_BANNER, file=sys.stderr)
    _mode = mode
    _log.warning("safety: process mode set to %s", mode.value)


def require_safe_mode() -> None:
    """Assert the process is in a sane mode for fund-touching operations.

    Regtest: always OK. Mainnet: only OK if explicitly confirmed via
    :func:`set_mode`.
    """
    if _mode is Mode.MAINNET and not _mainnet_confirmed:
        raise SafetyError(
            "mainnet mode is set but was not explicitly confirmed; refusing "
            "to proceed. Use set_mode(Mode.MAINNET, "
            "i_understand_this_is_research_code=True) at the entry point."
        )


__all__ = [
    "Mode",
    "SafetyError",
    "RESEARCH_BANNER",
    "MAINNET_BANNER",
    "emit_banner_once",
    "current_mode",
    "is_mainnet",
    "set_mode",
    "require_safe_mode",
]
