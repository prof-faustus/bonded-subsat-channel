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
