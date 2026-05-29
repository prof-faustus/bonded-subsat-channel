# Privacy properties and future-work roadmap

This document states explicitly what the construction does and does not
hide from on-chain observers, and lists the roadmap items required to
extend the construction toward stronger privacy. Honest scoping is
the rule: every weakness named below is one a referee would otherwise
discover independently, and the appropriate response is to surface it
in the paper rather than minimise it.

## 1. What is visible on-chain at present

### 1.1 Funding transaction

The funding transaction is a single on-chain object whose outputs are
the n-of-n channel CMS output and the n bond outputs (one IF/ELSE per
party). An observer of the chain therefore learns:

- the **participant count** `n` (from the CMS count and the bond
  outputs);
- the **set of participant public keys** (encoded in the CMS and the
  bond IF branches);
- the **funded amount** `S` (the value of output 0) and the **per-party
  bond** `b_i` (the values of outputs 1..n).

The **subdivision parameter** `k` is **not** visible on-chain; it is a
per-channel off-chain agreement. The chain sees only whole-satoshi
amounts, by construction.

### 1.2 Channel state transactions (off-chain by design)

State transactions are held off-chain. They are never broadcast unless
the channel closes contestedly. The chain therefore never sees the
sequence of micro-unit transfers in normal operation.

### 1.3 Cooperative close

The cooperative close transaction reveals:

- the **final allocation** `Q*(a)` of whole satoshis to each
  participant (the per-party P2PKH outputs);
- the **return** of every bond to its owner (as the per-party output
  values exceeding `Q*(a)_i` by the bond amount).

It does **not** reveal:

- intermediate states or transfers;
- the subdivision parameter `k`;
- which transfers contributed to the final allocation.

### 1.4 Contested close

If a contested close occurs, the chain sees:

- one or more **state transactions** (the offender's stale broadcast,
  the honest current-state broadcast that overtakes it). Each carries
  the input sequence number that encodes its version `t`, so an
  observer learns the **number of intermediate states** at the moment
  of contest.
- the **bond-forfeiture transaction**. If a watchtower mediated, the
  forfeit's first output is a P2PKH to the watchtower's pubkey for the
  agreed fee; the remaining outputs are P2PKHs to the honest
  counterparties.

### 1.5 Multi-hop routing — preimage leak (acknowledged)

This is the construction's principal privacy weakness, inherited from
every hashlock-based routing scheme on Bitcoin-family ledgers.

When a hop's IF branch is satisfied (claim), the **preimage** `x` is
present **as a push** in the spending transaction's `script_sig`:

```
<payee_sig> <x> OP_1
```

Anyone observing the chain therefore learns `x`. Because the same `x`
is the secret for every hop along the path conditioned on the same
image `h = HASH160(x)`, an observer who can correlate the claim
transactions of different hops can link them as belonging to the same
multi-hop payment. This is the standard "PTLC-vs-HTLC" tradeoff: PTLCs
(point time-locked contracts) use Schnorr signature adaptors instead
of hashlocks and do not leak the secret on-chain; the present
construction does not use them.

What an observer **can** infer from a routed payment that completes:

- a path of hops that all share the same image `h`;
- a chain of claim transactions that all reveal the same preimage `x`,
  permitting linkage of the hops to one logical payment.

What an observer **cannot** infer:

- the source (`i_0`) or sink (`i_l`) of the path: each hop's payer and
  payee are local to that hop; there is no on-chain "from" or "to";
- the path length `ℓ` (unless the observer sees every hop's claim);
- the original amount conditioned on the preimage (each hop's value is
  local; intermediaries may charge fees, hiding the relationship).

The return-branch case is symmetric: returns are P2PKH spends with the
payer's signature; the preimage is **not** revealed when a hop returns.

## 2. Version-counter visibility

The protocol encodes the state version `t` in the input sequence
number of state transactions (see DECISIONS.md D4). A contested close
therefore reveals the **integer version of the state being broadcast**.
An observer who sees a contested close learns the maximum off-chain
version reached at the time of contest. This is benign in normal use
but is information leak in the contested path.

## 3. Watchtower information

A watchtower in this construction holds:

- the channel's **current co-signed state transaction**;
- one **pre-signed forfeiture transaction per potential offender**.

From these the tower learns:

- the **set of participants** (their pubkeys, via the channel and bond
  scripts);
- the **current `Q*(a)` outputs** (the per-party payouts in the
  current state — i.e. the latest co-signed allocation);
- the **bond values**.

The tower does **not** learn:

- the **per-state transfer history** (only the latest co-signed
  state);
- the **off-chain micro-unit allocations** between updates;
- the **subdivision parameter** `k` (unless the parties tell it);
- any **key material** that would let it move funds (custody-freedom).

When a cluster (§17 hardening) is used, each watcher independently has
the same view; cluster members cannot collude to gain custody.

## 4. Roadmap — privacy extensions

The following are scoped extensions that would improve privacy without
disturbing the soundness argument of the paper. They are listed in
order of approximate implementation cost.

### 4.1 PTLC routing (medium)

Replace the hashlock-based hop script with a point time-locked
construction using a Schnorr signature adaptor. The hop's claim then
reveals the discrete-log point (not a hash preimage), and a properly
constructed scheme prevents on-chain linkage of hops belonging to the
same multi-hop payment.

Effort: moderate. Requires a Schnorr-style signing primitive bound to
the BSV interpreter's actual capabilities. The post-Genesis opcode set
admits the necessary primitives (`OP_CHECKSIG` with arbitrary public
keys, `OP_CAT`/`OP_SPLIT` for the witness construction).

### 4.2 Stealth-address payouts (low)

Replace the per-party fixed P2PKH at close with one-time addresses
derived per close. Each party uses an ECDH-style derivation from a
shared secret to compute a one-time output script; this prevents
chain-walkers from linking a party's identity across closes.

Effort: small wallet-side change. The channel-layer scripts are
unchanged.

### 4.3 CoinSwap-style funding (medium-high)

Bury the funding transaction's participant set inside a chain of
indistinguishable swaps so the on-chain structure no longer reveals
`n`, the per-party bond values, or the participant pubkeys. This is a
substantial protocol extension and is orthogonal to the channel
construction.

### 4.4 Aggregate signatures on the n-of-n channel output (medium)

Replace the `OP_CHECKMULTISIG` with a single aggregated Schnorr
signature (e.g. MuSig2-style). The funding output then looks like a
plain P2PK on-chain and reveals neither the participant count nor the
individual pubkeys. This is the simplest privacy win and the most
visually impactful from a chain-analysis perspective.

Effort: depends on the availability of an aggregate-signature
primitive that the interpreter accepts under standardness rules.

### 4.5 Confidential transactions / amounts (high)

A full confidential-amounts overlay would hide the `S` and `b_i`
values on-chain. This is a substantial cryptographic and consensus
work item, far outside the scope of this paper.

### 4.6 Sealed-bid contested closes (low, immediate)

A small refinement to the contested-close path: instead of carrying
the version `t` directly in the input sequence number, carry a hashed
commitment to `t` and reveal the value only on settlement. This costs
one additional round of interaction per state but reduces the
information leak of a contested close.

## 5. Statement for the paper

The paper should state, in §8 ("Scope and residual assumptions"):

> "The construction reveals the participant set, the funded amount,
> and the per-party bond amounts in the funding transaction;
> cooperative closes additionally reveal the final allocation. The
> subdivision parameter `k` and the intermediate states are not
> revealed in normal operation. Multi-hop routed payments leak the
> shared preimage on every hop's claim, permitting on-chain linkage
> of the hops belonging to one logical payment; this is the standard
> HTLC limitation, addressable by a PTLC-routing extension (roadmap
> §4.1). The construction does not claim privacy from a chain-walking
> observer."

The roadmap items are not promises; they are bounds on what the
construction could become under additional engineering effort.

## 6. References

- The implementation's per-module comments call out preimage leakage
  at the IF (claim) branch in `src/channel/scripts.py:hop_script`.
- The accompanying paper's §8.3 reproduces the privacy disclaimer
  verbatim.
- DECISIONS.md D9 records the tower's custody-free property and its
  bounded view of channel state.
