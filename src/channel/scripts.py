"""Locking and unlocking script builders (post-Genesis BSV opcodes only).

Every locking script in this module is built from the following opcode set:

    OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_DUP,
    OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKMULTISIG, OP_0, OP_1 .. OP_16

These opcodes retain their original meaning on post-Genesis BSV. The
implementation deliberately **does not** use ``OP_CHECKLOCKTIMEVERIFY`` or
``OP_CHECKSEQUENCEVERIFY`` because, after the Genesis upgrade, they are
inert no-ops on BSV: any script that relies on them is broken by design.

Timing constraints in this protocol are enforced exclusively at the
transaction level by ``nSequence`` / ``nLockTime`` (the original
replacement rule). The hop's *return* branch is not gated by any in-script
timelock; the hold-back is enforced by the locktime on the return
transaction itself.

Opcode-vs-integer trap: pushing a computed opcode number requires wrapping
it in the :class:`bitcoinx.Ops` enum (e.g. ``Ops(int(Ops.OP_1) + n - 1)``).
Pushing the bare integer would emit a data push instead. The single helper
:func:`op_n` centralises this conversion.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from bitcoinx import Ops, PublicKey, Script

from .errors import ScriptBuildError


# ---------------------------------------------------------------------------
# Opcode helpers
# ---------------------------------------------------------------------------


def op_n(n: int) -> Ops:
    """Return ``OP_n`` for ``n`` in [0, 16] as a member of :class:`Ops`.

    The post-Genesis interpreter recognises the small-integer opcodes
    ``OP_0`` and ``OP_1..OP_16`` (values 0x00 and 0x51..0x60). We wrap the
    computation in :class:`Ops` so the encoder emits the opcode byte, not a
    data push of the integer ``n`` (which would leave the wrong value on the
    stack and is the central trap of this API).
    """
    if n == 0:
        return Ops.OP_0
    if not 1 <= n <= 16:
        raise ScriptBuildError(
            f"op_n only supports 0..16 (got {n}); use a data push for larger n"
        )
    return Ops(int(Ops.OP_1) + n - 1)


def _encode_script_num(n: int) -> bytes:
    """Minimal Script-number encoding (little-endian, sign-magnitude).

    Used to push integer counts larger than 16 onto the script stack (for
    CHECKMULTISIG ``m`` / ``n`` values beyond ``OP_16``). For ``n in [0, 16]``
    prefer :func:`op_n`; this helper handles the regime that small-integer
    opcodes cannot reach (e.g. 9000-party funding outputs).
    """
    if n == 0:
        return b""
    abs_n = abs(n)
    out = bytearray()
    while abs_n:
        out.append(abs_n & 0xFF)
        abs_n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if n < 0 else 0)
    elif n < 0:
        out[-1] |= 0x80
    return bytes(out)


def push_count(script: Script, n: int) -> Script:
    """Append a count ``n`` to ``script`` as either ``OP_n`` or a data push.

    ``n in [0, 16]`` is emitted as the small-integer opcode (the only form
    accepted by the strict pre-Genesis interpreter; under post-Genesis it is
    still preferred for size). Larger ``n`` is emitted as a minimal-encoded
    script number via a data push, which post-Genesis CHECKMULTISIG accepts.
    """
    if 0 <= n <= 16:
        return script << op_n(n)
    return script << _encode_script_num(n)


# ---------------------------------------------------------------------------
# §4.1 — Funding output (channel output): n-of-n CHECKMULTISIG
# ---------------------------------------------------------------------------


def channel_funding_script(pubkeys: Sequence[PublicKey]) -> Script:
    """Locking script for the n-of-n channel-funding output.

    Layout:

        <n>  <pk_1> <pk_2> ... <pk_n>  <n>  OP_CHECKMULTISIG

    For ``n in [1, 16]`` the count is emitted as the small-integer opcode
    ``OP_n``. For larger ``n``, it is pushed as a minimal-encoded script
    number; post-Genesis ``OP_CHECKMULTISIG`` accepts this form (the
    in-script script-number push is what permits the 9000-party scale
    regime).
    """
    n = len(pubkeys)
    if n < 1:
        raise ScriptBuildError(f"channel_funding_script needs >=1 pubkey (got {n})")
    s = push_count(Script(), n)
    for pk in pubkeys:
        s = s << pk.to_bytes()
    s = push_count(s, n) << Ops.OP_CHECKMULTISIG
    return s


def channel_funding_unlock(signatures: Sequence[bytes]) -> Script:
    """Unlocking script for the n-of-n channel output.

    Layout:

        OP_0  <sig_1> ... <sig_n>

    The leading ``OP_0`` accommodates the well-known ``OP_CHECKMULTISIG``
    off-by-one stack consumption. Signatures must appear in the same order
    as the pubkeys in the locking script (CHECKMULTISIG consumes them in
    order).
    """
    if not signatures:
        raise ScriptBuildError("channel_funding_unlock needs >=1 signatures")
    s = Script() << Ops.OP_0
    for sig in signatures:
        s = s << sig
    return s


# ---------------------------------------------------------------------------
# §4.2 — Hashlocked routing hop with return branch
# ---------------------------------------------------------------------------


def hop_script(image_h160: bytes, payee_pk: PublicKey, payer_pk: PublicKey) -> Script:
    """Locking script for a routing hop with a hashlocked claim branch.

    Layout:

        OP_IF
            OP_HASH160 <h> OP_EQUALVERIFY <payee_pk> OP_CHECKSIG
        OP_ELSE
            <payer_pk> OP_CHECKSIG
        OP_ENDIF

    Note: timing for the ELSE branch is enforced **outside** the script, by
    the ``nLockTime`` on the return transaction. The script itself contains
    no timelock opcode; this is required because OP_CLTV / OP_CSV are inert
    no-ops post-Genesis.
    """
    if len(image_h160) != 20:
        raise ScriptBuildError(
            f"image_h160 must be 20 bytes (got {len(image_h160)})"
        )
    return (
        Script()
        << Ops.OP_IF
        << Ops.OP_HASH160 << image_h160 << Ops.OP_EQUALVERIFY
        << payee_pk.to_bytes() << Ops.OP_CHECKSIG
        << Ops.OP_ELSE
        << payer_pk.to_bytes() << Ops.OP_CHECKSIG
        << Ops.OP_ENDIF
    )


def hop_claim_unlock(payee_sig: bytes, preimage: bytes) -> Script:
    """Unlocking script for the IF (claim) branch.

    Layout:

        <payee_sig> <preimage> OP_1

    The trailing ``OP_1`` selects the IF branch. ``preimage`` is hashed
    with ``HASH160`` by the interpreter and must equal the image embedded
    in the locking script.
    """
    return Script() << payee_sig << preimage << Ops.OP_1


def hop_return_unlock(payer_sig: bytes) -> Script:
    """Unlocking script for the ELSE (return) branch.

    Layout:

        <payer_sig> OP_0

    The trailing ``OP_0`` selects the ELSE branch. The transaction carrying
    this input must have an ``nLockTime`` matching the hop's return horizon
    (the script does not enforce this; consensus does).
    """
    return Script() << payer_sig << Ops.OP_0


# ---------------------------------------------------------------------------
# §4.3 — P2PKH payout (per-party output at close)
# ---------------------------------------------------------------------------


def p2pkh_script(pk: PublicKey) -> Script:
    """Locking script for a P2PKH payout (delegates to bitcoinx)."""
    return pk.P2PKH_script()


def p2pkh_unlock(sig: bytes, pk: PublicKey) -> Script:
    """Unlocking script for a P2PKH payout: ``<sig> <pk>``."""
    return Script() << sig << pk.to_bytes()


# ---------------------------------------------------------------------------
# §4.4 — Bond output
# ---------------------------------------------------------------------------


def bond_script(owner_pk: PublicKey, counterparty_pks: Sequence[PublicKey]) -> Script:
    """Locking script for a bond output.

    Layout:

        OP_IF
            <owner_pk> OP_CHECKSIG
        OP_ELSE
            OP_m <cp_1> ... <cp_m> OP_m OP_CHECKMULTISIG
        OP_ENDIF

    The IF (return) branch is taken on a cooperative close, by the owner
    co-signing the close transaction. The ELSE (forfeiture) branch requires
    every counterparty's signature; the honest counterparties hold the
    offender's superseded broadcast as the evidence justifying this branch,
    but the **script itself** enforces only that ``m`` counterparty
    signatures are present.
    """
    m = len(counterparty_pks)
    if m < 1:
        raise ScriptBuildError(f"bond_script needs >=1 counterparty (got {m})")
    s = (
        Script()
        << Ops.OP_IF
        << owner_pk.to_bytes() << Ops.OP_CHECKSIG
        << Ops.OP_ELSE
    )
    s = push_count(s, m)
    for pk in counterparty_pks:
        s = s << pk.to_bytes()
    s = push_count(s, m) << Ops.OP_CHECKMULTISIG << Ops.OP_ENDIF
    return s


def bond_return_unlock(owner_sig: bytes) -> Script:
    """Unlocking script for the bond's IF (return) branch: ``<owner_sig> OP_1``."""
    return Script() << owner_sig << Ops.OP_1


def bond_forfeit_unlock(counterparty_sigs: Sequence[bytes]) -> Script:
    """Unlocking script for the bond's ELSE (forfeiture) branch.

    Layout:

        OP_0  <cp_sig_1> ... <cp_sig_m>  OP_0

    The leading ``OP_0`` accommodates ``OP_CHECKMULTISIG`` off-by-one; the
    trailing ``OP_0`` selects the ELSE branch.
    """
    if not counterparty_sigs:
        raise ScriptBuildError("bond_forfeit_unlock needs >=1 signatures")
    s = Script() << Ops.OP_0
    for sig in counterparty_sigs:
        s = s << sig
    s = s << Ops.OP_0
    return s


__all__ = [
    "op_n",
    "push_count",
    "channel_funding_script",
    "channel_funding_unlock",
    "hop_script",
    "hop_claim_unlock",
    "hop_return_unlock",
    "p2pkh_script",
    "p2pkh_unlock",
    "bond_script",
    "bond_return_unlock",
    "bond_forfeit_unlock",
]
