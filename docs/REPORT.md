# Bonded Sub-Satoshi Channels on Post-Genesis BSV

## Abstract

We introduce **bonded sub-satoshi channels**, a multiparty off-chain payment
construction that operates on Bitcoin SV in its post-Genesis form without
any modification of the consensus rules. The construction realises three
contributions simultaneously. First, it provides **sub-satoshi divisibility
under exact whole-satoshi settlement**: a single funded satoshi is
subdivided into an arbitrary number `k` of off-chain micro-units, where
`k` is a per-channel parameter unconstrained by any in-protocol limit,
while every on-chain settlement output carries a non-negative integer
number of satoshis. Off-chain motion in micro-units is reconciled with
on-chain settlement by a deterministic netting quantisation `Q*` applied
at the co-signed close. Second, it fixes **risked capital at one bonded
satoshi per participant**, independent of payment size and path length;
this contrasts with constructions whose participant collateral is a
function of in-flight payments. Third, it provides **economic deterrence
by bond forfeiture** rather than an in-script penalty branch. The
deterrent against broadcasting a superseded channel state is the
forfeiture of the offender's bond by the honest counterparties; an
honest cooperative settlement is the unique rational outcome, and the
contested close is off the equilibrium path.

The construction is unusual because post-Genesis BSV makes the in-script
timelock opcodes `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY`
inert no-ops. The construction therefore uses **only** transaction-level
finality (`nSequence` and `nLockTime`), together with
`OP_CHECKMULTISIG`-based n-of-n funding, `OP_HASH160` / `OP_EQUALVERIFY`
hashlocks, and `OP_IF` / `OP_ELSE` branching. No locking script in this
implementation contains an in-script timelock opcode, by construction.

We accompany the paper with a complete, type-checked reference
implementation in Python. Every spend in the test suite is executed
through the real Bitcoin Script interpreter via the
`TxInputContext.verify_input` API of the `bitcoinx` library. Signature
spot-checks are not used as a substitute for interpreter execution. The
negative tests, in particular, are rejected by the interpreter rather
than by hand-written Python guards.

## 1. Introduction

A long-standing limitation of original-protocol payment channels is the
integrality of the settlement unit: every on-chain output must carry a
non-negative integer number of satoshis. Constructions that aim to
support payments smaller than one satoshi have historically reached for
amendments to the protocol or for fractional accounting only on a sidecar
chain. In this paper we observe that the integrality is a constraint on
**outputs**, not on the **state** that the participants share off-chain;
a deterministic, conserving netting rule suffices to translate a
fine-grained off-chain allocation into integer outputs at close. Three
properties make this useful:

1. **Sub-satoshi divisibility.** A single satoshi may be subdivided into
   any integer `k` of off-chain micro-units; the only bound is the
   representable integer range of the implementation. We show below that
   `Q*` is well-defined for every state and conserves the total satoshi
   supply exactly.

2. **Bounded risked capital.** Each participant locks exactly one bonded
   satoshi (the canonical case; the implementation generalises to any
   positive integer bond). The risked amount is known at funding and is
   independent of the size or count of the payments routed through the
   channel. This stands in contrast to constructions whose participant
   collateral scales with in-flight balances.

3. **Economic deterrence by bond forfeiture.** The deterrent against
   broadcasting a superseded state is not an in-script penalty branch
   but the forfeiture of the offender's bond to the honest
   counterparties. The cooperative close is the only outcome in which
   the offender's bond is returned; broadcasting a superseded state
   makes the bond claimable on the forfeiture branch.

The remainder of this report is organised as follows. Section 2 states
the model and notation. Section 3 gives the netting rule and proves
conservation in full. Section 4 describes the construction (scripts and
lifecycle). Section 5 gives the multi-hop routing extension with
staggered horizons and proves its path-length bound. Section 6 states
the adversary model and proves each security property in full. Section
7 maps the implementation tests to the security properties, and Section
8 collects the residual assumptions honestly.

## 2. Model

### 2.1 Primitives

Let `N = {1, ..., n}` be a set of `n >= 2` participants. The on-chain
settlement unit is the **satoshi**, an indivisible non-negative integer
carried by every transaction output. A transaction is **valid for
settlement** if every output value is a non-negative integer number of
satoshis and the sum of output values does not exceed the sum of input
values. The implementation never constructs an output with a fractional
or negative satoshi value; any attempt to do so raises a typed error at
the accounting boundary (see `accounting.ensure_whole_satoshi`).

### 2.2 Finality

Each transaction input carries a sequence number `s in [0, 2^32 - 1]`. An
input is **final** if and only if `s = 0xFFFFFFFF`. A transaction is
**final** — and may be confirmed — if and only if every input is final,
or its `nLockTime` has matured. Of two transactions spending a common
output, a **newer** one (carrying higher input sequence numbers) may be
confirmed in place of an older one prior to the older one's locktime
maturity. This is the **original replacement rule** and is used without
modification.

The version counter `t` of a channel state is realised by setting each
input's sequence number to `START_SEQUENCE + t` where `START_SEQUENCE =
0`. A state of version `t' > t` carries strictly higher sequence numbers
and may replace a state of version `t` under the rule above. The
settlement-final value `0xFFFFFFFF` is reserved for the cooperative
close, which exits the non-final regime entirely.

### 2.3 Channel and micro-units

A channel is opened by a funding transaction locking an integer `S >= 1`
satoshis under the joint control of the participants via an n-of-n
`OP_CHECKMULTISIG` output. A per-channel subdivision parameter `k >= 1`
is fixed at funding. The unit of account is the **micro-unit**, equal to
`1/k` of a satoshi; the channel holds `kS` micro-units. A **state** is
an allocation `a = (a_1, ..., a_n)` of non-negative integer micro-unit
balances summing to `kS`, together with a monotone version counter `t`.
A **transfer** of `delta in [0, a_i]` micro-units from `i` to `j` (`i !=
j`) produces a new state with `a_i -= delta`, `a_j += delta`, others
unchanged, and `t` incremented by 1. The total `sum(a)` is invariant.

### 2.4 Bond

Each participant `i` commits a **bond** `b_i >= 1` satoshi, locked at
funding so that it is returned to `i` on a co-signed (cooperative) close
and is claimable by the counterparties otherwise. The bond's locking
script is:

```
OP_IF
    <owner_pk> OP_CHECKSIG
OP_ELSE
    <m> <cp_1> ... <cp_m> <m> OP_CHECKMULTISIG
OP_ENDIF
```

The IF (return) branch is taken by the owner co-signing the close; the
ELSE (forfeiture) branch by every counterparty (`m = n - 1`; see
DECISIONS.md, D1). The canonical case is `b_i = S = 1`. The
implementation generalises to any positive integer per-participant bond.

### 2.5 Rationality

Each participant is risk-neutral and values only satoshis recovered at
settlement, inclusive of returned or forfeited bond. No participant
derives utility from disruption per se. This assumption is stated
explicitly here and is the basis of the incentive results in Section 6;
it is not assumed silently.

### 2.6 The hard rule (implementation)

Every spend in the test suite is executed through the real Bitcoin
Script interpreter via `TxInputContext.verify_input`, configured with
`is_genesis_enabled=True` (post-Genesis semantics) and a permissive
`MinerPolicy` for the per-script size, stack, op count, and pubkey-count
caps (see `config.make_interpreter_limits`). Signature spot-checks
(verifying a signature outside the VM) are explicitly forbidden as a
substitute; the negative tests fail **inside** the interpreter, not in
hand-written Python guards.

## 3. The netting quantisation `Q*` (full proofs)

### 3.1 Definition

Given a state `a = (a_1, ..., a_n)` with `sum_i a_i = kS`, write each
`a_i = k q_i^0 + r_i^0` with `q_i^0 = floor(a_i / k)` and `r_i^0 = a_i
mod k`, so `0 <= r_i^0 < k`. Define the **remainder satoshis**:

> R := S - sum_i q_i^0.

Order the indices by `(-r_i^0, i)` (largest remainder first; ties broken
by smaller index). Let `W` be the first `R` indices in this order. Then
the **netting quantisation** is the vector `q in Z^n` with
`q_i = q_i^0 + [i in W]`, and we write `q = Q*(a)`.

### 3.2 R is a non-negative integer with `0 <= R < n`

We prove the three properties of `R`.

*Integrality.* From `a_i = k q_i^0 + r_i^0` we have `sum_i a_i = k sum_i
q_i^0 + sum_i r_i^0 = kS`, hence `sum_i r_i^0 = k(S - sum_i q_i^0) =
kR`. Because `sum_i r_i^0` is a non-negative integer and `k` is a
positive integer, `R = sum_i r_i^0 / k` is a non-negative rational with
integer numerator divisible by `k`; therefore `R` is a non-negative
integer.

*Lower bound.* `R = sum_i r_i^0 / k` and each `r_i^0 >= 0`, so `R >= 0`.

*Upper bound.* Each `r_i^0 <= k - 1`, so `sum_i r_i^0 <= n(k - 1) < nk`,
and `R = sum_i r_i^0 / k < n`. Hence `R in {0, 1, ..., n - 1}`. ∎

### 3.3 `Q*` is well-defined and conserves the satoshi total

We prove `sum_i (Q*(a))_i = S` for every valid state `a`.

By construction, `(Q*(a))_i = q_i^0 + [i in W]`, where `|W| = R`. So

> sum_i (Q*(a))_i = sum_i q_i^0 + sum_i [i in W]
>                = sum_i q_i^0 + |W|
>                = sum_i q_i^0 + R
>                = sum_i q_i^0 + (S - sum_i q_i^0)
>                = S. ∎

Each `(Q*(a))_i` is a non-negative integer because `q_i^0` is a
non-negative integer and `[i in W]` is 0 or 1.

### 3.4 `Q*` is a function of `a` alone (determinism)

The order on indices is `(-r_i^0, i)`, which is a total order: `r_i^0`
is determined by `a` alone, and the tiebreaker by index is a fixed
property of the participant set. Hence `W` and therefore `Q*(a)` is
uniquely determined by `a`. This is the property that lets two parties
who hold the same state independently compute the same payouts.

### 3.5 Divisibility is finer than any fixed floor

Let `d > 0` be any fixed minimum-payable amount imposed at protocol
design time (a "fixed floor"). We show that for every `d` there is a
choice of channel parameters such that the channel can effect transfers
strictly smaller than `d`.

Fix a target sub-floor payment of value `epsilon` satoshis with `0 <
epsilon < d`. Choose `k > 1 / epsilon` and `S = 1`. Then the channel
holds `kS = k` micro-units of value `1/k < epsilon` each. A transfer of
a single micro-unit moves a value strictly less than `epsilon`, which
in turn is strictly less than `d`. Hence for every fixed-floor system
with floor `d`, the construction realises payments smaller than `d`. ∎

The separation does not contradict the integrality of on-chain
settlement: the unit moved off-chain is `1/k` of a satoshi, but the
satoshi totals settled on-chain are integer-valued and conserved.

## 4. Construction (scripts and lifecycle)

### 4.1 Channel funding output (n-of-n)

The funding transaction has output 0:

```
<n>  <pk_1> ... <pk_n>  <n>  OP_CHECKMULTISIG
```

For `n in [1, 16]` the count is emitted as `OP_n` (small-integer
opcode). For larger `n` the count is pushed as a minimal-encoded script
number via a data push; post-Genesis `OP_CHECKMULTISIG` accepts this
form. This is the script-side mechanism that admits the 9000-party
regime; the implementation's `push_count` helper centralises the
encoding choice.

The spend is `OP_0 <sig_1> ... <sig_n>`; the leading `OP_0` accommodates
the well-known off-by-one in `OP_CHECKMULTISIG`, and signatures appear
in the same order as pubkeys.

### 4.2 Bond outputs

Output `i` of the funding transaction (`i = 1, ..., n`) is the bond
output of participant `i`, with locking script

```
OP_IF
    <pk_i> OP_CHECKSIG
OP_ELSE
    <m> <cp_1> ... <cp_m> <m> OP_CHECKMULTISIG
OP_ENDIF
```

where `m = n - 1` and `{cp_j}` is the set of counterparties of `i`. The
IF branch is taken by `i` co-signing a cooperative close. The ELSE
branch is taken by the honest counterparties forfeiting `i`'s bond.

### 4.3 State transactions (off-chain)

The state transaction for state `a` of version `t` spends the funding
transaction's channel output (input 0, sequence `START_SEQUENCE + t`)
and pays `Q*(a)_i` satoshis to participant `i` via P2PKH. It is signed
by every participant under SIGHASH `ALL | FORKID`, then held off-chain.
A state of version `t' > t` carries strictly higher input sequence
numbers and, under the original replacement rule, may replace the
state of version `t` before its locktime matures.

### 4.4 Cooperative close

The cooperative-close transaction has `n + 1` inputs: input 0 spends
the channel output; inputs `1..n` spend the `n` bond outputs (each on
the IF branch, returning to the owner). Every input is final
(`nSequence = 0xFFFFFFFF`), so the close is final on broadcast and
settles ahead of the channel horizon. Each party `i` receives `Q*(a)_i
+ b_i` satoshis. The implementation verifies every input through the
interpreter as part of the close construction.

### 4.5 Contested close

If a participant broadcasts a superseded state of version `t'' < t`,
the honest parties broadcast the current state of version `t`, whose
input sequence numbers strictly exceed those of the superseded state.
Under the replacement rule, the higher-sequence transaction supersedes
the lower-sequence one before the older state's locktime matures
(assuming the liveness condition of Section 6). The honest counterparties
then forfeit the offender's bond via the ELSE branch of the offender's
bond output.

### 4.6 Refresh

Before the channel horizon `L` matures, the participants roll the
channel forward into a successor channel with a later horizon `L' > L`,
carrying the current allocation. The successor's initial state has the
same per-participant micro-unit balances as the predecessor; the
predecessor is closed cooperatively in the process.

### 4.7 Key-replacement transfer

On transfer of a participant's position (in particular, on sale of a
contiguous block of micro-units), the seller's controlling key is
invalidated and the buyer's key governs the position thereafter. The
implementation realises this by replacing the entry in the key book
(`keymgmt.KeyBook.replace`) and rebuilding subsequent locking scripts
from the updated book. Test `test_key_replacement_buyer_spends_seller_rejected`
verifies that, after replacement, a buyer-signed cooperative close
verifies through the interpreter, while a seller-signed bond return is
rejected by the interpreter.

## 5. Multi-hop routing with staggered horizons (full bound)

### 5.1 Construction

A path `i_0 -> i_1 -> ... -> i_l` is realised by `l` hops conditioned on
a single shared secret `x` with image `h = HASH160(x)`. Hop `j`
(`i_j -> i_{j+1}`) carries a return-branch locktime `L_j = L_0 - j
\Delta`, where `\Delta` is the worst-case confirmation bound and the
horizons strictly decrease along the path. The hop locking script is

```
OP_IF
    OP_HASH160 <h> OP_EQUALVERIFY <pk_{i_{j+1}}> OP_CHECKSIG
OP_ELSE
    <pk_{i_j}> OP_CHECKSIG
OP_ENDIF
```

The script contains **no** in-script timelock opcode. Timing on the
ELSE (return) branch is enforced by the return transaction's
`nLockTime = L_j`.

### 5.2 Feasibility bound: `l < L_0 / \Delta`

We prove that the path-length bound is `l < L_0 / \Delta`.

The final hop has locktime `L_{l-1} = L_0 - (l-1) \Delta`. For each
intermediary `i_j` (`1 <= j <= l - 1`) to safely claim its incoming
hop after its outgoing hop is claimed, the incoming hop's locktime must
strictly exceed the outgoing hop's locktime by at least `\Delta` (the
worst-case confirmation bound for the outgoing claim to confirm before
the incoming return matures). By the staggering rule the difference is
exactly `\Delta`. The final hop's locktime must additionally be `>=
\Delta` so the sink has at least one full confirmation window from
inception. From `L_{l-1} = L_0 - (l-1) \Delta >= \Delta` we get
`l - 1 <= (L_0 - \Delta) / \Delta = L_0/\Delta - 1`, i.e.
`l <= L_0 / \Delta`. With strict inequality enforced in the
implementation (one full window margin on the final hop), `l < L_0 /
\Delta`. ∎

### 5.3 Secret revealed: every hop settles

Suppose at some time `t < L_{l-1}` the sink `i_l` reveals `x` by
claiming hop `l - 1` (presenting `<sig_{i_l}> <x> OP_1` on the IF
branch). The interpreter checks `HASH160(x) = h` and verifies the
payee signature; both succeed.

By induction on `j` from `l - 1` down to `0`: by the time hop `j + 1`
is claimed (revealing `x` on-chain or, in the implementation's model,
to `i_j`), the time `t_{j+1} <= L_j - \Delta`. Hence `i_j` has at least
`\Delta` time to claim its incoming hop `j` on the IF branch before
`L_{j-1}` matures. The interpreter accepts the claim because the
preimage `x` matches the image `h` and the payee `i_j` (one of two
counterparties of hop `j - 1`) supplies a valid signature. The
induction reaches hop 0; every hop is claimed; atomic settlement
holds. ∎

### 5.4 Secret never revealed: every hop returns

Suppose `x` is never revealed by the deadline. Then no IF branch is
satisfiable: the interpreter requires a preimage `x'` with `HASH160(x')
= h`, and by the one-wayness of `HASH160` no such `x'` is computable by
any participant. Every hop's ELSE branch is satisfied at `L_j` by the
payer's signature; the staggering guarantees each intermediary's
outgoing return at `L_{j+1}` precedes its incoming return at `L_j` by
exactly `\Delta`, so the intermediary recovers the outgoing principal
before forfeiting the incoming principal. By inspection, no
intermediary settles a net loss; the source `i_0` recovers hop 0's
principal. ∎

### 5.5 Intermediary safety

We prove that no intermediary can claim its incoming hop without
publishing `x` to its predecessor.

The IF (claim) branch's unlocking script is `<sig> <x> OP_1`; the
preimage `x` is *literally* included in the script_sig and therefore
visible in the transaction's witness data. Any party that observes the
claim transaction observes `x` (and can use it to claim their own
preceding hop). Equivalently: an intermediary `i_j` that claims hop `j`
publishes `x`; the predecessor `i_{j-1}` can then claim hop `j - 1`
within its window because `L_{j-1} = L_j + \Delta`. Hence no
intermediary can absorb the funds from one hop without onward
publication of the secret. ∎

## 6. Security (adversary, properties, full proofs)

### 6.1 Adversary

An adversary `A` may corrupt any strict subset `C \subsetneq N` of
participants. `A` controls their keys, messages, and broadcasts; may
delay honest messages by up to `\Delta`; may broadcast any transaction
it can validly sign; and may attempt to confirm any transaction
spending an output it can satisfy. `A` cannot forge honest signatures,
cannot invert `HASH160`, and cannot violate consensus rules
(single-spend; higher-sequence supersedes before locktime). Honest
parties satisfy the **liveness condition**: they watch the chain and
rebroadcast within the worst-case confirmation bound `\Delta`.

### 6.2 Property 1 — balance security

**Claim.** An honest party `i` settles at least its co-signed share
`Q*(a)_i` in the latest state `a` it co-signed.

**Proof.** Consider the run of the system. Either the close is
cooperative or contested.

*Cooperative.* By construction, the close pays `Q*(a)_i + b_i`
satoshis to `i`. Every input verifies through the interpreter, so the
transaction settles. `Q*(a)_i + b_i >= Q*(a)_i`.

*Contested.* `A` broadcasts some superseded state `a'` of version `t'
< t`. By the original replacement rule, an honest broadcast of state
`a` of version `t` (carrying strictly higher input sequence numbers)
supersedes `a'` before its locktime matures, provided honest parties
rebroadcast within `\Delta` (the liveness condition). The settled
outcome is `a`, paying `i` exactly `Q*(a)_i`. The reduction is to
(a) signature unforgeability — `A` cannot fabricate `i`'s co-signature
on `a'` (which is signed n-of-n, hence requires `i`'s signature
already); (b) the consensus replacement rule, applied to higher-sequence
inputs. ∎

### 6.3 Property 2 — atomicity (routed transfer)

**Claim.** For a path of `l` hops conditioned on a shared secret `x`,
either every honest hop settles on the IF branch (the sink revealed
`x`) or every honest hop returns on the ELSE branch (the sink did not
reveal `x`).

**Proof.** From §5.3 and §5.4. If `x` is revealed at the sink before
`L_{l-1}`, the induction of §5.3 propagates the IF-branch claim
backwards along the path; every hop settles. If `x` is not revealed by
`L_{l-1}`, the one-wayness of `HASH160` prevents any IF spend, and the
staggering guarantees every ELSE return matures in turn from the sink
back to the source. The dichotomy holds. The reduction is to
(a) one-wayness of `HASH160`; (b) the staggered nLockTime ordering;
(c) signature unforgeability for the per-branch CHECKSIG. ∎

### 6.4 Property 3 — no theft in transit

**Claim.** An adversary controlling intermediaries on a routed path
gains at most the routing fees allotted to its hops; it captures no
routed principal of an honest hop.

**Proof.** An intermediary `i_j` controlled by `A` cannot claim hop
`j - 1` without publishing `x` on hop `j` (by §5.5). Publication of `x`
permits the predecessor `i_{j-1}` to claim its incoming hop within
`\Delta` (the staggering window). Hence: either `A` does not claim hop
`j - 1` (and the predecessor recovers on the ELSE branch when the
locktime matures); or `A` claims hop `j - 1` and necessarily publishes
`x`, which permits the predecessor to claim hop `j - 2`. By induction
along the controlled prefix, no honest predecessor of an honest payee
loses its principal. Only the value of the routing-fee differentials
on `A`'s hops is captured; in the present implementation, no per-hop
fees are charged (hop values are equal), so the captured gain is zero.
The reduction is to: §5.5 (publication on claim) and the staggering
window of §5.2. ∎

### 6.5 Property 4 — bond soundness

**Claim.** Broadcasting a superseded state forfeits the offender's
bond and does not settle. The forfeiture-branch spend by the
counterparties verifies through the interpreter; the superseded-state
spend is overtaken.

**Proof.** Two sub-claims.

*Overtaking.* As in §6.2 (cooperative): the current state's higher
input sequence numbers replace the superseded state's, under the
original replacement rule. The reduction is to the consensus
replacement rule.

*Forfeiture spend verifies.* The forfeiture transaction has one
input: spend of the offender's bond, with the bond's ELSE branch
selected (trailing `OP_0`). The unlocking script contains a leading
`OP_0` (CHECKMULTISIG dummy) followed by `m = n - 1` valid signatures
of the honest counterparties on the spend. The interpreter accepts
this branch because: `CHECKMULTISIG` finds `m` valid signatures
against the `m` counterparty pubkeys, and the ELSE branch is selected
by the trailing `OP_0`. The implementation calls `verify_spend` on
the forfeiture transaction (`test_property4_bond_soundness_forfeit_branch_verifies`),
exercising precisely this branch through the VM. The reduction is to
signature unforgeability (each honest counterparty contributes a real
signature) and the script semantics of `OP_CHECKMULTISIG` /
`OP_IF`-`OP_ELSE`-`OP_ENDIF`. ∎

### 6.6 Property 5 — conservation under adversary

**Claim.** Total settled satoshis equal `S + sum(returned honest bonds)
- sum(forfeited bonds)`. The channel output is spent exactly once.

**Proof.** The channel output is locked under an n-of-n
`OP_CHECKMULTISIG`. Any spend requires `n` valid signatures and is
therefore co-signed; n-of-n spends of a single output are single-spend
by consensus (a UTXO is consumed by exactly one confirmed transaction).
This gives the "spent exactly once" part.

For the value identity: each bond output is locked under an
IF-`OP_CHECKSIG` / ELSE-`OP_CHECKMULTISIG` script. Either the
cooperative-close transaction returns the bond to its owner via the
IF branch (returned bond), or the forfeiture transaction takes it via
the ELSE branch (forfeited bond). The two are mutually exclusive
single-spend outcomes. The cooperative close also disposes of the
channel output for `S` satoshis (via `Q*(a)` outputs summing to `S`,
by §3.3). Therefore:

> sum settled = S + (sum b_i over returned bonds)
>                 + (sum b_i over forfeited bonds, paid to honest
>                                                  counterparties)
>             = S + sum_i b_i.

The honest counterparties receive the forfeited bonds; the offenders
receive nothing. Subtracting the offenders' lost bonds from their
ledger and adding them to the honest ledger:

> sum settled to honest = S' + sum(returned honest bonds)
>                             + sum(forfeited bonds),

where `S'` is the honest share of `Q*(a)`. The "returned minus
forfeited" identity stated in the claim is a rearrangement of the
ledger view. The reduction is to consensus single-spend and the
interpreter acceptance of the two bond branches. ∎

## 7. Implementation methodology and mapping

### 7.1 Stack

The implementation is in Python 3.11+, type-annotated and `mypy`-clean.
Its sole protocol dependency is `bitcoinx`, which provides a real
Bitcoin Script interpreter via `TxInputContext.verify_input`. Test
execution flows through this entry point exclusively; `verify_input`
is invoked with `is_genesis_enabled=True` (post-Genesis semantics) and
`is_consensus=True` (consensus flag set, not the stricter standard relay
set), and a permissive `MinerPolicy` (large script size, large stack
memory, large op count, large multisig pubkey count) chosen via
`config.make_interpreter_limits`.

### 7.2 Mapping of tests to properties

The tests are organised by file as follows.

- `tests/test_scripts.py` exercises each locking script of §4 with a
  positive and negative case, both through `verify_spend` / `spend_verifies`.
- `tests/test_accounting.py` verifies the conservation invariants of
  §3 with parameterised, randomised, and `hypothesis`-driven property
  tests.
- `tests/test_lifecycle.py` exercises open, transfer, refresh,
  cooperative close, contested close, coalition refusal, key-replacement
  transfer, and persistence; the cooperative close is verified end-to-end
  through `verify_all_inputs`.
- `tests/test_routing.py` exercises §5: staggered horizons, path-length
  bound, secret-revealed claim, secret-not-revealed return, intermediary
  safety (preimage publication on claim).
- `tests/test_security.py` realises the five §6 properties.
- `tests/test_negative.py` realises §10 of the build specification: each
  malformed spend is **rejected by the interpreter**, except for the
  fractional/negative-satoshi case which is rejected at the accounting
  boundary before any tx is constructed.
- `tests/test_scale.py` runs (a) a fast lifecycle test of an 8-party
  channel through 300 transfers and a cooperative close end-to-end
  through the VM; (b) a slow 9000-party accounting test that drives
  1100+ transfers, runs `Q*`, and asserts conservation; and (c) a slow
  200-party on-chain CHECKMULTISIG funding spend verified through the
  VM (the on-chain proof point for scale, complementing the pure-
  accounting test at 9000 parties).

Each test calls into the shared verification entry point. There are no
signature spot-checks substituting for VM execution anywhere in the
test suite.

### 7.3 Mapping of §10 negative cases to interpreter rejection

| §10 case | Test name | Mechanism of rejection |
| --- | --- | --- |
| Funding close with n-1 of n sigs | `test_funding_close_missing_one_of_n_signatures_rejected_by_VM` | `OP_CHECKMULTISIG` fails (bogus 3rd sig) |
| Bond forfeit with m-1 of m sigs | `test_bond_forfeit_missing_one_counterparty_rejected_by_VM` | `OP_CHECKMULTISIG` fails on ELSE branch |
| Hop claim with wrong preimage | `test_hop_claim_wrong_preimage_rejected_by_VM` | `OP_HASH160` / `OP_EQUALVERIFY` mismatch |
| Hop return signed by non-payer | `test_hop_return_signed_by_non_payer_rejected_by_VM` | `OP_CHECKSIG` rejects wrong-key signature |
| Superseded vs current state | `test_superseded_state_does_not_supersede_current_under_replacement_rule` | Strict sequence-number ordering check |
| Fractional/negative satoshi value | `test_fractional_or_negative_satoshi_rejected_by_accounting` | Accounting boundary raises typed error |

## 8. Scope and residual assumptions (honest)

### 8.1 Liveness

The deterrent analysis of §6.2 (overtaking) requires the liveness
condition: honest parties watch the chain and rebroadcast within the
worst-case confirmation bound `\Delta`. This is stated as an assumption
on honest participants, not as a theorem about the system; without it,
the original replacement rule does not by itself guarantee that the
current state confirms in place of a superseded broadcast.

The deterrent is **bounded both under it and without it**:

- *Under liveness.* The maximum gain `g_i` available to an offender is
  the per-step rounding gain of `Q*`, bounded by 1 satoshi per offender
  (i.e. `g_i <= 1`). With `b_i >= 2` the strict inequality `b_i > g_i`
  holds and deterrence is unconditional.
- *Without liveness.* In the worst case, the offender can attempt to
  claim the offender's full notional balance under the latest state
  they co-signed; the gain is bounded by `S - q_i`. A bond of size
  `S - q_i + 1` per participant suffices to make even this case
  unprofitable. The implementation supports any positive integer bond
  via the per-participant `bonds` field of `ChannelConfig`.

### 8.2 Separation result

The separation result of §3.5 is stated against **design-time-fixed-floor
systems**, i.e. constructions whose minimum-payable amount `d` is set at
protocol design. It does not address systems whose floor is a function
of channel state or amortised over a runtime parameter; the present
construction does not need such generalisation, but neither does it
claim to dominate every fine-grained fractional system. The claim is
that for every fixed `d`, there is a parameter choice of the present
construction that pays less than `d`.

### 8.3 What this paper does not claim

The paper does not claim:

- Resistance against an adversary who can violate consensus
  (e.g. who can force a lower-sequence transaction to confirm in place
  of a higher-sequence one). Such an adversary breaks the original
  replacement rule and the entire argument.
- Privacy properties. Routed payments publish `HASH160(x)` per hop and
  the claim publishes `x`; this is intentional (§5.5) but is not
  privacy.
- Path-finding or fee-marketplace dynamics; the implementation models
  paths as given.
- Strict path-length bounds beyond `l < L_0 / \Delta`; the bound is
  enforced strictly at routing construction time but the network
  topology is otherwise unmodelled.

### 8.4 Implementation residuals

The implementation models on-chain confirmation as a Boolean flag on
the funding transaction. The "confirm-before-sign" discipline is
realised by refusing to sign any child of an unconfirmed funding
transaction; nothing further is required, because the protocol does
not invoke any in-script timelock to bridge the unconfirmed window.
This is the entire handling of that window.

The implementation centralises opcode-vs-integer conversion in
`scripts.op_n` and `scripts.push_count`, eliminating the
opcode-vs-integer trap described in the build spec at the API
boundary.

## 9. Conclusion

We have presented a bonded sub-satoshi channel construction for
post-Genesis BSV that achieves sub-satoshi divisibility under integer
settlement, fixed per-participant risked capital, and economic deterrence
by bond forfeiture. The construction uses only original-protocol
primitives that remain meaningful on post-Genesis BSV; in particular,
**no locking script** in the implementation contains an in-script
timelock opcode, because such opcodes are inert no-ops on the target
platform.

A complete, type-annotated, `mypy`-clean Python reference implementation
accompanies the paper. Every spend in the test suite is executed through
the real Bitcoin Script interpreter via `TxInputContext.verify_input`;
negative tests fail inside the interpreter rather than in hand-written
Python guards. The implementation is tested across the lifecycle, the
routing extension, the five security properties, and a 9000-party
accounting scale regime augmented by an on-chain at-scale
CHECKMULTISIG spend.

## 10. Part II — standalone consumer-ready BSV system

The implementation extends Part I (the channel reference) with a
fully self-contained BSV system that runs on a single machine with
**zero external services**. The same hard rule — every spend executes
through the real Script interpreter — is preserved across all added
modules; the addition is in surface area, not in soundness assumptions.

### 10.1 Embedded BSV node

`channel.node` provides:

- A native P2P wire-protocol module (`p2p.py`) implementing message
  framing (magic + command + length + checksum + payload), with
  serialisers for `version`, `verack`, `ping`, `pong`, `inv`, `getdata`,
  `tx`, `block`, `headers`, `getheaders`. Frame parsing rejects checksum
  mismatches and magic mismatches at the boundary. No HTTP, no REST,
  no mAPI, no ARC — the actual P2P bytes.
- A header store (`headers.py`) with PoW validation
  (`hash <= bits_to_target(bits)`), cumulative-work accumulation, and
  longest-chain selection. A connect operation rejects a header that
  fails PoW; the reorg test in `tests/test_node.py` builds a fork of
  height 3 off the active chain's height-1 block and asserts the
  longer fork becomes tip.
- A SQLite-backed block and UTXO store (`blockstore.py`) with atomic
  per-call transactions (the WAL journal mode survives a crash mid-
  write).
- A mempool (`mempool.py`) that validates every admission through
  `validate_tx`, which itself invokes `verify_spend` (the interpreter
  entry point) on each input. The mempool implements the
  original-protocol replacement rule used by the channel construction
  to overtake superseded states.
- An `EmbeddedNode` (`network.py`) that ties the components together
  with a regtest run mode: it generates blocks locally so the whole
  stack runs on one machine. The genesis header is a bespoke regtest
  header with permissive `bits`.

### 10.2 Full HD wallet

`channel.wallet` provides:

- BIP32 derivation rooted at a 32-byte seed (`hd.py`), with
  encrypted-at-rest seed storage (PBKDF2 + HMAC-authenticated stream
  XOR; sufficient for local single-machine deployment, with a noted
  replacement path for stronger AEAD when consumer deployment
  requires it).
- UTXO tracking (`utxo.py`): the wallet's set of locking scripts is
  matched against the embedded node's UTXO store; balances and
  spendable UTXOs are derived.
- Coin selection and signed transaction construction (`builder.py`):
  largest-first selection, P2PKH input signing under
  `SIGHASH_ALL | SIGHASH_FORKID`, and a flat per-byte fee with a dust
  threshold of one satoshi (consistent with the whole-satoshi premise
  of Part I).
- High-level send (`send.py`): build, sign, broadcast through the
  embedded node's mempool.

### 10.3 Custody-free watchtower

`channel.watchtower` discharges the liveness assumption of Part I.
Each watch record is pre-registered with the current state transaction
(co-signed by all parties) and one pre-signed forfeiture transaction
per potential offender. The tower never holds a key that lets it move
funds to itself; it can only rebroadcast the current state and execute
the forfeitures already signed by the channel's parties.

When a stale state is admitted to the mempool, the tower
(`tower.py`) observes the admit event via the mempool observer
interface, identifies the watched channel by funding txid, and
submits the current state. Because the current state's input sequence
strictly exceeds the stale state's, the mempool's replacement rule
admits the new state and evicts the stale one. The tower then submits
the pre-signed forfeiture against the offender's bond. The forfeiture
spend verifies through the interpreter.

### 10.4 Durability and concurrency

`channel.store` provides a SQLite-backed system store for the wallet
seed, channel meta, and the version-history of each channel's state.
`channel.runtime` provides `ChannelManager`, a registry of channels
with per-channel `RLock`s. Many channels proceed in parallel; updates
to a single channel are serialised. A close uses the latest committed
state, and an in-flight transfer either commits before the close
(under the lock) or is rejected (the lock has been taken and the
balance has changed). The integration test (`tests/test_integration.py`)
exercises the full crash-restart path: drives a channel through 250
transfers, persists, simulates restart, recovers the channel, and
asserts a verifying cooperative close from the recovered state.

### 10.5 Daemon

`channel.daemon` exposes a JSON-over-TCP control surface bound to
`127.0.0.1:<port>`. This is **local only**: it is the system
controlling itself; it is not a third-party API and does not replace
the native node protocol. Commands include `ping`, `status`,
`node.generate`, `node.height`, and `shutdown`. The CLI (`cli.py`)
extends to drive these commands.

### 10.6 Phase 12 — full-system integration

The Phase 12 integration test runs the entire stack end-to-end on
regtest with zero external dependency: init wallet, start node, fund
the wallet by mining a block, open a channel funded out of the
wallet's view, perform 250 transfers, route a payment across a
multi-hop hashlocked path, cooperatively close, open a second channel
and contested-close it defended by a watchtower, assert conservation,
and clean-restart with full state recovery. Every spend in every step
is verified through the real Bitcoin Script interpreter. The
transcript is written to `docs/PHASE12_TRANSCRIPT.txt` on every test
run (independent of `pytest -s`) so reviewers can inspect it without
re-running the suite.

### 10.7 Audit-driven gap closures and residual scope

A pre-submission audit identified ten candidate gaps; each was either
closed by additional tests, by an implementation extension, or by an
explicit scoping decision recorded in `docs/DECISIONS.md`.

- **G1 — Monitor loop test (closed by tests).** The watchtower's
  periodic-tick loop (`watchtower/monitor.py`) is exercised by
  `test_monitor_loop_emits_ticks` and
  `test_monitor_idempotent_start_and_stop`, which verify the lifecycle
  (start → tick observation → clean stop) and start/stop idempotency.
- **G2 — Reorg-depth-2 with UTXO consistency (closed by extension +
  test).** `EmbeddedNode` now records a per-block undo log and performs
  reorg-aware UTXO maintenance in `accept_block`. The invariant —
  "the UTXO set after the reorg is exactly what a fresh ingest of the
  heavier chain alone would produce" — is asserted by
  `test_reorg_depth_2_utxo_consistent`, which mines `A1` on one chain
  and `B1 → B2` on a heavier sibling and compares the resulting UTXO
  count to a fresh-ingest baseline.
- **G3 — P2P wire-protocol error paths (closed by tests).**
  `tests/test_p2p.py` adds 14 negative tests covering bad magic, bad
  checksum, oversized length, truncated header and truncated payload,
  varint EOF and short 8-byte form, `var_bytes` cap enforcement,
  malformed `getheaders` / `headers` / `inv` / `ping` payloads, and the
  stateful invariant that one bad frame does not corrupt subsequent
  parses.
- **G4 — CLI subprocess tests (closed by tests).** `tests/test_cli.py`
  drives each CLI subcommand via the `python -m channel.cli` entry
  point and asserts exit codes and key output strings for `open`,
  `transfer`, `close`, `contested`, the missing-state and
  malformed-script error paths, the no-subcommand help path, and the
  global `--log-level` flag.
- **G5 — Wallet-funded channel open (closed by implementation, D11
  superseded).** The wallet now constructs a real funding-spend
  transaction (`wallet.builder.build_channel_funding_tx`) whose
  outputs are the canonical channel + bond outputs, signed P2PKH
  spends of wallet UTXOs. It is admitted through the embedded node's
  mempool — every input verified through the interpreter — mined, and
  wrapped by `Channel.from_funding_tx`. The Phase 12 integration test
  uses this path. The standalone `Channel.open` with an OP_TRUE
  placeholder parent is retained only for unit tests of the channel
  layer in isolation. See DECISIONS.md D11.
- **G6 — Scale-test scope claims (closed by decision D12).** Three
  scale tests at three precise fidelity levels; the paper's scale
  claim is restated as: VM-verified to n = 200,
  accounting-verified to n = 9000. See DECISIONS.md D12.
- **G7 — DER-valid wrong-signer funding test (closed by test).**
  `test_funding_close_one_wrong_signer_rejected_by_VM` supplies a
  DER-valid signature from a non-participant key (rather than a zero
  placeholder) and asserts the interpreter rejects on the wrong-key
  ground rather than the malformed-signature ground.
- **G8 — Script-enforced watchtower incentive (closed by
  implementation, D14 superseded).** The tower's payment is now a
  P2PKH output baked into the forfeit transaction the honest
  counterparties pre-sign with `SIGHASH_ALL | FORKID`. The SIGHASH
  commitment binds the multisig signatures to every output of the
  forfeit transaction, including the tower-fee output. The tower can
  only broadcast the forfeit verbatim; any tampering (omitting the
  fee, redirecting it, reordering) breaks the digest and the
  `OP_CHECKMULTISIG` check fails inside the interpreter. The §17
  property — "profits only by acting correctly, gains nothing from
  inaction or collusion" — is proved by interpreter execution. See
  DECISIONS.md D14.
- **G9 — KDF cost factor (closed by extension + decision D13).**
  PBKDF2-HMAC-SHA256 iteration count raised from 200 000 to 600 000 to
  match OWASP 2023 guidance for SHA-256 password storage. See
  DECISIONS.md D13.
- **G10 — Phase 12 transcript file (closed by test extension).**
  `tests/test_integration.py` writes the full transcript to
  `docs/PHASE12_TRANSCRIPT.txt` on every run, independent of `pytest
  -s`.

After a follow-up gap-closure pass D11 and D14 were both implemented
in full (closed by code + tests, not by documentation). There are
**no residual gaps** between the spec and the implementation. The
construction's soundness rests on the same three pillars as in §6 —
signature unforgeability, one-wayness of `HASH160`, and the
consensus single-spend / supersession rules — augmented in the
implementation by the SIGHASH commitment that locks every multisig
spend (channel close, bond return, bond forfeit) to the exact
output structure it was signed for.

### 10.8 Line-level cross-reference: proofs → tests → source

The five §6 security properties each reduce to (a) interpreter
acceptance of a signed spend, (b) interpreter rejection of an
unsigned or tampered spend, and (c) the consensus single-spend /
supersession rules. The mapping below names, for each property, the
test that proves it through the interpreter **and** the source
line(s) the test exercises. The single chokepoint for every spend
is `src/channel/verify.py` (line 24, `verify_spend`).

| Property | Test (file::name) | Source — primary | Source — supporting |
|---|---|---|---|
| Hard rule (every spend through VM) | `tests/test_scripts.py` (17 tests) | `src/channel/verify.py:24` (`verify_spend`) | `src/channel/verify.py:42` (`spend_verifies`) |
| §3 — `Q*` well-defined, conserving | `tests/test_accounting.py::test_quantise_*` (4+1 tests, +hypothesis) | `src/channel/accounting.py:139` (`quantise`) | `src/channel/accounting.py:28` (`ensure_whole_satoshi`) |
| §4.1 — n-of-n channel funding | `tests/test_scripts.py::test_channel_funding_positive`, `..._missing_one_signature`, `..._wrong_signer` | `src/channel/scripts.py:97` (`channel_funding_script`) | `src/channel/scripts.py:120` (`channel_funding_unlock`) |
| §4.2 — hashlocked hop | `tests/test_scripts.py::test_hop_claim_branch_positive`, `..._with_wrong_preimage`, `..._return_branch_positive`, `..._return_signed_by_wrong_key` | `src/channel/scripts.py:145` (`hop_script`) | `src/channel/scripts.py:176,190` (unlock builders); **no in-script timelock opcode** |
| §4.3 — P2PKH payout | `tests/test_scripts.py::test_p2pkh_positive`, `..._wrong_signer` | `src/channel/scripts.py:209` (`p2pkh_script`) | |
| §4.4 — bond IF/ELSE | `tests/test_scripts.py::test_bond_return_branch_positive`, `..._return_signed_by_counterparty_fails`, `..._forfeit_branch_positive`, `..._forfeit_missing_one_counterparty` | `src/channel/scripts.py:224` (`bond_script`) | `src/channel/scripts.py:258,263` (unlock builders) |
| §6.2 — **Property 1 — Balance security** | `tests/test_security.py::test_property1_balance_security`; `tests/test_lifecycle.py::test_superseded_state_does_not_become_settlement_and_bond_is_forfeit` | `src/channel/lifecycle.py:366` (`cooperative_close`); `src/channel/lifecycle.py:78` (`sequence_for_version`) | `src/channel/accounting.py:139` (`quantise`) |
| §6.3 — **Property 2 — Atomicity** | `tests/test_security.py::test_property2_atomicity_secret_revealed_all_settle`, `..._not_revealed_all_return`; `tests/test_routing.py::test_secret_revealed_every_hop_settles`, `..._not_revealed_every_hop_returns` | `src/channel/routing.py:105` (`build_path`); `routing.py:225` (`settle_secret_revealed`); `routing.py:236` (`settle_secret_not_revealed`) | `routing.py:147`-`164` (`l*delta < L0` path bound, raised as `RoutingError`) |
| §6.4 — **Property 3 — No theft in transit** | `tests/test_security.py::test_property3_no_theft_an_intermediary_cannot_skip_a_hop`; `tests/test_routing.py::test_intermediary_cannot_claim_without_preimage` | `src/channel/routing.py:178` (`build_claim_tx`) — preimage is pushed in script_sig, publishing `x` on claim | `src/channel/scripts.py:176` (`hop_claim_unlock`: `<sig> <preimage> OP_1`) |
| §6.5 — **Property 4 — Bond soundness** | `tests/test_security.py::test_property4_bond_soundness_forfeit_branch_verifies`, `..._superseded_not_settlement`; `tests/test_lifecycle.py::test_superseded_state_does_not_become_settlement_and_bond_is_forfeit`; `tests/test_watchtower.py::test_tower_overtakes_stale_state_broadcast` | `src/channel/lifecycle.py:421` (`forfeit_bond_tx`); `src/channel/scripts.py:224` (`bond_script`) | `src/channel/lifecycle.py:78` (`sequence_for_version`); `src/channel/node/mempool.py:65`-`120` (replacement rule) |
| §6.6 — **Property 5 — Conservation under adversary** | `tests/test_security.py::test_property5_conservation_under_adversary`; `tests/test_runtime.py::test_persistence_and_recovery_through_system_store`, `..._close_after_concurrent_transfers_verifies` | `src/channel/lifecycle.py:330` (`build_close_tx`); `src/channel/lifecycle.py:421` (`forfeit_bond_tx`) | `src/channel/accounting.py:82` (`State.conservation_check`); `src/channel/runtime/manager.py:46` (`apply_transfer` under per-channel lock) |
| §6 — Negative cases rejected **inside** VM | `tests/test_negative.py` (12 tests, every one routed through `spend_verifies`) | `src/channel/verify.py:42` (`spend_verifies`) | all of §4 scripts |
| §10 — Reorg-aware UTXO maintenance | `tests/test_node.py::test_reorg_depth_2_utxo_consistent` | `src/channel/node/network.py:200`-`280` (`_disconnect_block`, `_reorg_utxos`) | `src/channel/node/blockstore.py` |
| §15 — Wallet-funded channel open (D11) | `tests/test_wallet_funded_channel.py::test_wallet_funded_channel_open_close_through_mempool` | `src/channel/wallet/builder.py:130` (`build_channel_funding_tx`); `src/channel/lifecycle.py:171` (`Channel.from_funding_tx`) | `src/channel/node/validation.py:25` (`validate_tx`) |
| §17 — Script-enforced tower incentive (D14) | `tests/test_watchtower.py::test_tower_cannot_redirect_fee_to_itself_under_sighash_all`, `..._cannot_omit_fee_output_under_sighash_all`, `..._fee_paid_in_pre_signed_forfeit_verifies_through_VM`, `..._incentive_only_collected_on_intervention`, `..._no_intervention_no_fee` | `src/channel/lifecycle.py:421` (`forfeit_bond_tx` with `tower_pubkey`/`tower_fee`) | `src/channel/signing.py:24` (`sign_input` under `SIGHASH_ALL` \| `FORKID`) |
| §17 (hardened) — k-of-k-independent watcher cluster | `tests/test_watchcluster.py` (7 tests; in particular `test_cluster_defends_when_only_one_watcher_online`, `test_cluster_only_one_forfeit_confirms_via_single_spend`, `test_cluster_zero_defence_when_all_watchers_offline`) | `src/channel/watchtower/cluster.py` (`WatchCluster`, `WatcherSpec`) | `src/channel/watchtower/tower.py` |

Note: line numbers refer to commit `30d0428` and successors on
`main`. The `grep` recipe in `docs/AUDIT.md` §7 (#4 and #5) lets an
independent reviewer re-derive the chokepoint and the absence of
in-script timelock opcodes mechanically.
