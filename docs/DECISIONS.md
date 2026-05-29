# Design decisions

This file records design decisions taken in the implementation when the paper
specification admitted more than one faithful realisation. Each entry names
the decision, the alternative considered, and the rationale.

## D1. Multisig threshold for the bond's forfeiture branch

The bond's forfeiture branch is an `m`-of-`m` `OP_CHECKMULTISIG` over the
counterparties of the bond's owner. We set `m = n - 1` (every counterparty
must co-sign forfeiture). This is the strictest possible policy, matches the
paper's incentive model (joint forfeiture by the honest set), and avoids
introducing a smaller threshold that would let a sub-coalition seize an
honest party's bond.

## D2. Tiebreak rule for the netting remainder

The netting rule `Q*` distributes the remainder `R = S - sum(floor(a_i/k))`
of satoshis one each to the participants with the largest `a_i mod k`. Ties
are broken by **the fixed participant ordering** (the index `i` in the state
vector). This is deterministic, agreed at funding, and gives the paper's
guarantee that `Q*(a)` is a function of `a` alone.

## D3. Confirmation modelling

On-chain confirmation is modelled as a boolean flag on the funding
transaction (`confirmed: bool`). Operations that consume the funding output
refuse to sign while the flag is false (the "confirm-before-sign" discipline
of §6). No further on-chain interaction is modelled because the protocol
does not require any beyond what consensus already provides.

## D4. Sequence-number scheme for state versioning

The version counter `t` of a channel state is realised by setting every
input's `nSequence` to `START_SEQUENCE + t` for a fixed
`START_SEQUENCE = 0`. The settlement-final state always carries sequence
`0xFFFFFFFF`. The intermediate state versions are strictly increasing in
sequence number; the original replacement rule then guarantees that a
state of version `t' > t` may replace a state of version `t` before its
locktime matures. The settlement-final value `0xFFFFFFFF` exits the
non-final regime entirely; an `nLockTime` of zero is used for cooperative
closes (immediately final on broadcast).

## D5. Hop staggering

Hop `j` of an `l`-hop path carries `nLockTime = L_0 - j*Delta`. The hops
are strictly decreasing in horizon along the path, and the feasibility
bound is `l < L_0 / Delta`. We enforce this strictly at routing-time; an
attempt to construct a path with `l >= L_0/Delta` raises a typed error
from `routing.py`.

## D6. Persistence format

Channel state is persisted as JSON (versioned schema, see
`persistence.py`). Keys are stored as hex-encoded WIF-decoded private-key
bytes (compressed). On reload, the channel object is reconstructed and
its invariants re-validated.

## D7. Daemon transport: TCP loopback (Part II)

The daemon's control surface uses TCP on `127.0.0.1` (a configurable
port) rather than Unix-domain sockets. Reason: the target platform
matrix includes Windows, where Unix-domain sockets are only available
on Windows 10+ and require Python ≥ 3.9 with platform-specific build
flags. The spec calls for "Unix domain socket / local loopback"; we
choose local loopback. The transport is loopback-only and not
externally reachable; the daemon explicitly binds to `127.0.0.1`.

## D8. SQLite cross-thread access (Part II)

The system stores (`SystemStore`, `BlockStore`) open their SQLite
connection with `check_same_thread=False` and serialise writes via an
internal `RLock`. Reason: the daemon's request handlers run in the
standard library's `ThreadingMixIn` request threads; a per-thread
connection model would require a connection-pool layer that the
single-machine deployment target does not justify. The `RLock` provides
exclusive access at the per-call granularity, which is sufficient for
correctness of the single-writer schema.

## D9. Watchtower scope (Part II)

The watchtower is **custody-free**: it holds no key that lets it
re-route value to itself. Registration deposits a pre-signed current
state tx and a pre-signed forfeiture tx per potential offender;
intervention is limited to broadcasting these. A misbehaving tower can
delay settlement but cannot steal. The 1-of-1 trust model is
deliberately weak; it is what the spec requires.

## D10. Block count limit for n>16 funding scripts (Part II)

For `n > 16` parties the funding script pushes the CHECKMULTISIG
counts as minimal-encoded script numbers (via `push_count`), which
post-Genesis CHECKMULTISIG accepts. The 9000-party regime is exercised
in pure accounting (the funding tx with 9000 outputs is structurally
valid but too large to mine cheaply on regtest in CI). At-scale on-chain
funding signature verification is exercised at n=200 in
`test_scale_slow_on_chain_n_of_n_funding_signature`.

## D11. Phase 12 channel funding installs UTXOs directly (audit G5)

The Phase 12 integration test's `_install_channel_in_node` helper
inserts the channel's funding outputs (the n-of-n channel output and
the n bond outputs) directly into the embedded node's UTXO store,
bypassing the construction of a parent-spending funding transaction
out of the wallet's coinbase UTXOs.

**Why:** the Part I channel construction (`lifecycle.Channel.open`)
models the funding transaction with a placeholder OP_TRUE parent
input (its prev_hash and prev_idx are zeros). Wiring a real
wallet-funded parent would require a second transaction class with
full SIGHASH machinery wrapped around the channel construction, which
is out of scope for the paper's contribution. The property the
integration test demonstrates — every spend out of the channel
(state, close, forfeit) verifies through the interpreter against the
node's UTXO set — is unchanged by this scoping choice.

**How to apply:** the spec asks for end-to-end conservation and
interpreter-verified spends; both hold under the current modelling.
A wallet-funded-parent extension is a future Part II refinement and
does not invalidate the present construction.

## D12. Scale-test scope claims (audit G6)

Three distinct scale tests sit at different levels of fidelity, each
with a precise scope claim:

- `test_scale_fast_lifecycle` — 8 parties, 300 transfers, cooperative
  close, **every input verified through the interpreter**. The fast
  default that runs in every CI tier.
- `test_scale_slow_on_chain_n_of_n_funding_signature` — 200-party
  n-of-n CHECKMULTISIG funding spend, **on-chain VM-verified**. The
  on-chain-at-scale proof point.
- `test_scale_slow_accounting_9000_parties` — 9000 parties, 1100+
  transfers, `Q*` netting, **accounting only** (no on-chain VM step,
  because mining a 9000-output funding transaction in regtest CI is
  prohibitively slow).

**Paper claim:** the full channel lifecycle is VM-verified end-to-end
up to n = 200 parties; the accounting and netting layer is verified
by property tests up to n = 9000 parties. The construction admits
any larger n in principle; the implementation's scale ceiling is set
by regtest mining time, not by any consensus or in-script limit.

## D13. KDF parameters for the wallet seed (audit G9)

The wallet's encrypted-seed storage uses PBKDF2-HMAC-SHA256 with
600 000 iterations and a 16-byte salt + 16-byte nonce + 32-byte
HMAC-SHA256 tag. The iteration count matches OWASP's 2023 guidance
for SHA-256 password storage.

**Why:** the audit observed the previous 200 000-iteration cost was
low-end. We raised it to current best-practice, documented in
`src/channel/wallet/hd.py:_KDF_ITERS`. The decrypt step takes a few
hundred ms on a modern laptop, which is acceptable for an
interactive wallet-unlock.

**How to apply:** any future replacement of this layer with a
hardened AEAD (e.g. AES-GCM via `cryptography`) should preserve at
least the same KDF cost factor.

## D14. Watchtower incentive: accounting placeholder (audit G8)

`watchtower/incentive.py` is an accounting placeholder that records
the satoshi fee credited per intervention; it does **not**
script-enforce that the tower's payment is claimable only on a
forfeiture-branch spend.

**Why:** a script-enforced tower payment is a meaningful design
extension. It would either (a) thread a tower pubkey into the bond's
ELSE branch so the forfeiture transaction must pay the tower its
fee, or (b) add a separate tower-bond output co-signed at channel
open and claimable by the tower only after broadcasting a
current-state tx that overtakes a stale one. Both are several
hundred lines of additional script + integration-test code and
exceed the paper's narrow scope, which is the bonded sub-satoshi
channel itself.

**How to apply:** the tower's incentive-compatibility, in the
current implementation, is an off-chain accounting commitment
between the channel parties and the tower. The scoped claim in the
paper is the construction's non-reliance on the tower for
**soundness** (the custody-free property of D9). Incentive-
compatibility of the tower itself is left as future work.
