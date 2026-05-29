"""Typed exception hierarchy.

All errors raised by the package descend from :class:`ChannelError` so that
callers can ``except`` cleanly without resorting to bare ``Exception``.
"""

from __future__ import annotations


class ChannelError(Exception):
    """Base class for all errors raised by this package."""


class ConfigError(ChannelError):
    """Invalid configuration (e.g. non-positive k, negative satoshis)."""


class AccountingError(ChannelError):
    """Violation of an accounting invariant (conservation, integrality)."""


class FractionalSatoshiError(AccountingError):
    """An attempt was made to use a non-integer or negative satoshi value."""


class StateError(ChannelError):
    """Operation invalid for the channel's current state."""


class UnconfirmedFundingError(StateError):
    """A signature on a child of an unconfirmed funding tx was requested."""


class ScriptBuildError(ChannelError):
    """A script could not be built (bad inputs, wrong shapes)."""


class VerificationError(ChannelError):
    """An interpreter-execution check failed (script rejected)."""


class RoutingError(ChannelError):
    """Routing constraint violated (path-length bound, missing hop)."""


class KeyReplacementError(ChannelError):
    """A key-replacement transfer operation was misused."""


class PersistenceError(ChannelError):
    """Loading or saving channel state failed."""
