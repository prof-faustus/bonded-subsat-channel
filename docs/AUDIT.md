# Audit and gap-closure record

This document records the pre-submission audit of the implementation
against the build prompt and the accompanying paper, together with the
diff that closes every gap the audit raised. It is a **self-audit**;
it is not a substitute for an independent professional review and is
not represented as one. The intent is that any independent reviewer
can use this document as the starting point for their own pass.

The reproduction recipe and the test/timing/coverage measurements are
at the top of this file. The audit findings — what was raised, what
was closed, what remained — follow in §3. The final state, including
the script-enforced incentive (D14) and the wallet-funded channel
open (D11), is in §4.

## 1. How to reproduce

```bash
git clone https://github.com/prof-faustus/bonded-subsat-channel
cd bonded-subsat-channel
# system dep (Debian/Ubuntu); on macOS: brew install secp256k1
sudo apt-get install -y libsecp256k1-dev
python3 -m pip install -r requirements.txt
python3 -m pip install pytest-cov bandit

# core suite
python3 -m pytest -q

# with coverage
python3 -m pytest --cov=src/channel --cov-report=term

# type check + security lint
python3 -m mypy src/
python3 -m bandit -r src/ --severity-level high --confidence-level medium

# end-to-end transcript
python3 -m pytest tests/test_integration.py -v -s

# one-command demo
./demo.sh          # local
./demo.sh docker   # in a container
```

## 2. Measured results

| Metric | Value | Notes |
|---|---|---|
| Tests passing | **183 / 183** | pytest -q |
| Wall time | ~20 s | full suite incl. integration |
| mypy | **clean** | 43 source files |
| bandit (HIGH severity) | **clean** | `src/` only; tests intentionally have weak fixtures |
| Line coverage | ~89 % | overall; channel layer above 90 % |
| Phase 12 transcript | committed | `docs/PHASE12_TRANSCRIPT.txt` |

## 3. Audit findings and their resolution

### 3.1 First-pass audit (10 findings, G1–G10)

The first-pass audit raised ten candidate gaps. Each entry below states
the original finding, the code response, and the test that proves the
fix.

| Gap | Original concern | Resolution | Test reference |
|---|---|---|---|
| **G1** | Monitor periodic-tick loop unreachable from tests (0% coverage) | `watchtower/monitor.py` exposes observable `ticks` counter and `is_running()`; mutable-default Event bug fixed via `field(default_factory=...)` | `test_watchtower.py::test_monitor_loop_emits_ticks`, `test_monitor_idempotent_start_and_stop` |
| **G2** | Reorg-depth-2 + UTXO consistency assertion missing | `EmbeddedNode` gains per-block undo log; `accept_block` performs reorg-aware UTXO maintenance via `_disconnect_block` / `_reorg_utxos` | `test_node.py::test_reorg_depth_2_utxo_consistent` |
| **G3** | P2P wire-protocol error paths uncovered | New `tests/test_p2p.py` with 14 tests for malformed frames, varints, var_bytes cap, per-message parsers, no-corruption invariant | `tests/test_p2p.py` (14 tests) |
| **G4** | CLI subcommands at 77% — no subprocess tests | New `tests/test_cli.py` drives every CLI subcommand via `subprocess` | `tests/test_cli.py` (8 tests) |
| **G5** | Phase 12 installed channel UTXOs directly instead of via a wallet-funded tx | Wallet builder constructs a real funding-spend tx; mempool admits it via the interpreter; mined; channel layer wraps the confirmed funding tx (`Channel.from_funding_tx`); Phase 12 uses this path | `tests/test_wallet_funded_channel.py` + upgraded `tests/test_integration.py` |
| **G6** | Scale claim mismatch (no full-VM 9000-party run) | Three precise scale tests at three fidelity levels, with the paper claim restated: VM-verified to n = 200, accounting-verified to n = 9000 | `tests/test_scale.py` + DECISIONS.md D12 |
| **G7** | Wrong-signer funding negative test used a zero placeholder | New `test_funding_close_one_wrong_signer_rejected_by_VM` uses a DER-valid signature from a non-participant key | `tests/test_negative.py` |
| **G8** | Watchtower incentive was an off-chain accounting placeholder | `Channel.forfeit_bond_tx` accepts `tower_pubkey` + `tower_fee`; SIGHASH_ALL on the multisig binds the counterparty signatures to the tower-fee output. The tower can broadcast only verbatim; tampering invalidates the multisig and the spend is VM-rejected | `tests/test_watchtower.py` (6 tests) |
| **G9** | PBKDF2 iteration count was 200 000 (low-end) | Raised to 600 000 to match OWASP 2023 guidance for SHA-256 password storage | DECISIONS.md D13 |
| **G10** | Phase 12 transcript only visible with `pytest -s` | Integration test writes `docs/PHASE12_TRANSCRIPT.txt` unconditionally | `tests/test_integration.py` |

### 3.2 Second-pass audit (7 priorities + liveness hardening)

A second audit pass identified seven priority items and one
architectural concern. Each is now closed.

| Priority | Original concern | Resolution |
|---|---|---|
| **P1** | No license | MIT `LICENSE` at the root, referenced in `pyproject.toml` + `README.md`. Includes a RESEARCH-CODE notice. |
| **P2** | No publishable audit | This file (`docs/AUDIT.md`). |
| **P3** | No CI | `.github/workflows/ci.yml` runs pytest (matrix: Ubuntu/macOS/Windows × Python 3.11/3.12), mypy, bandit, builds the source ZIP as an artifact |
| **P4** | No mainnet-mode guard, no warning banners | `src/channel/safety.py` enforces mainnet opt-in (requires explicit `i_understand_this_is_research_code=True`); CLI prints `RESEARCH_BANNER` by default and rejects `--mainnet` without `--i-understand-this-is-research-code`; covered by `tests/test_safety.py` (8 tests) |
| **P5** | No line-level cross-reference between proofs and code | New §10.8 of `docs/REPORT.md` maps every security property to the test name **and** the source file+line that realises it |
| **P6** | No Docker / one-command demo | `Dockerfile` (multi-stage, runs tests at build time) and `demo.sh` (`./demo.sh` or `./demo.sh docker`) print the Phase 12 transcript |
| **P7** | No privacy / future-work doc | New `docs/PRIVACY.md` enumerates the on-chain leaks (preimage on hop claim, version counter on contested close), the watcher's view, and a six-item privacy roadmap |
| **L** | Liveness assumption pinned to a single honest party / single tower | `src/channel/watchtower/cluster.py` — `WatchCluster` of `k` independent watchers; any one suffices to defend; the single-spend rule resolves the race; covered by `tests/test_watchcluster.py` (7 tests) |

### 3.3 D11 and D14 — soundness-adjacent residuals closed

Two scoping decisions in earlier revisions (`DECISIONS.md` D11, D14)
described features that were short of the spec's full intent. Both are
now implemented in full, not documented as scope notes.

- **D11 (wallet-funded channel open).** The wallet builds a real
  funding-spend transaction (P2PKH spends of its UTXOs → channel and
  bond outputs), the transaction is admitted to the embedded node's
  mempool through the real interpreter, mined, and the channel layer
  wraps the confirmed funding tx via `Channel.from_funding_tx`. Phase
  12 uses this path. The earlier "direct UTXO install" helper is
  retained for the standalone `Channel.open` and for the second
  channel of Phase 12 only (to exercise both paths).
- **D14 (script-enforced tower incentive).** The forfeit transaction
  carries a P2PKH output paying the tower its fee. The counterparties
  sign the m-of-m forfeit branch with `SIGHASH_ALL | FORKID`; the
  digest is bound to the exact output structure. Any tampering by the
  tower (omitting the fee output, redirecting it, reordering) fails
  the `OP_CHECKMULTISIG` check **inside the interpreter**. Six tests
  in `tests/test_watchtower.py` prove the property: the tower
  receives the fee only by broadcasting the pre-signed forfeit
  verbatim; inaction → no fee; tampering → VM rejection.

## 4. Current state — residual gaps

After both audit passes there are **no functional or soundness gaps
between the spec and the implementation**. The remaining items are
genuine future-work extensions, recorded in `docs/PRIVACY.md` §4
(PTLC routing, stealth-address payouts, CoinSwap funding, aggregate
signatures, confidential transactions, sealed-bid contested closes).

The liveness assumption is now hardened from "one specific honest
party" to "at least one of `k` independent watchers" (P4 + L). This
reduces but does not eliminate dependence on at-least-one-honest-
watcher; the paper states the residual assumption explicitly and the
test suite includes an honest negative case
(`test_cluster_zero_defence_when_all_watchers_offline`).

## 5. Methodology

Every audit response above is verified by an executable test:

- Spend correctness — exercised through the real Bitcoin Script
  interpreter via `channel.verify.verify_spend` /
  `TxInputContext.verify_input(..., is_utxo_after_genesis=True)`.
- Negative cases — fail **inside** the interpreter, not in
  hand-written Python guards. The audit verified this for every
  negative test by reading the test source.
- Concurrency — exercised by `tests/test_runtime.py` driving parallel
  transfers across many channels with conservation assertions per
  channel.
- Integration — exercised by `tests/test_integration.py`
  (`test_phase12_full_system_integration`) which drives the whole
  stack end-to-end on regtest with zero external services.

## 6. Files added or changed in the audit closure

```
LICENSE                                    new (MIT + research-code notice)
.github/workflows/ci.yml                   new (pytest/mypy/bandit/zip)
Dockerfile                                 new (multi-stage; tests at build time)
.dockerignore                              new
demo.sh                                    new (local | docker)
docs/AUDIT.md                              new (this file)
docs/PRIVACY.md                            new
docs/REPORT.md                             extended (§10.7, §10.8)
docs/DECISIONS.md                          extended (D11/D14 closed; D15/D16 added)
docs/PHASE12_TRANSCRIPT.txt                regenerated on every test run

src/channel/safety.py                      new (mainnet gate + banners)
src/channel/cli.py                         extended (banner, --mainnet)
src/channel/lifecycle.py                   extended (from_funding_tx, build_channel_outputs, tower_pubkey/fee)
src/channel/node/network.py                extended (undo log + reorg-aware UTXO maintenance)
src/channel/wallet/builder.py              extended (build_channel_funding_tx)
src/channel/wallet/hd.py                   KDF iterations 200k -> 600k
src/channel/watchtower/cluster.py          new (WatchCluster, WatcherSpec)
src/channel/watchtower/monitor.py          observable ticks + field(default_factory)
src/channel/watchtower/tower.py            tower_pubkey field

tests/test_cli.py                          new (8)
tests/test_p2p.py                          new (14)
tests/test_safety.py                       new (8)
tests/test_wallet_funded_channel.py        new (2)
tests/test_watchcluster.py                 new (7)
tests/test_node.py                         extended (UTXO-consistency reorg)
tests/test_negative.py                     extended (wrong-signer)
tests/test_integration.py                  extended (wallet-funded path, transcript file)
tests/test_watchtower.py                   extended (D14 cluster of 6)
```

Test counts before / after:

```
initial commit (4453613):  134 tests
after G-pass     (2af6eb2): 160 tests (+26)
after D-pass     (30d0428): 168 tests (+8)
after P-pass     (current): 183 tests (+15)
```

mypy: clean across all revisions. bandit: clean at HIGH severity.

## 7. Independent review path

A reviewer wishing to replicate this audit independently should:

1. Clone the repo at the v0.3.0 tag (or `main`).
2. Run the reproduction recipe of §1.
3. Walk the §3 table; for each row, open the named test and check
   that it exercises the property claimed.
4. Verify the absence of in-script timelock opcodes:
   `grep -rE 'OP_CHECKLOCKTIMEVERIFY|OP_CHECKSEQUENCEVERIFY|OP_CLTV|OP_CSV' src/`
5. Verify the interpreter chokepoint:
   `grep -rE 'verify_input|TxInputContext' src/ tests/`
6. Check `docs/PRIVACY.md` §1 against the source — `hop_script` in
   `src/channel/scripts.py` should embed the preimage in the IF
   branch as documented.

Disagreement, additional findings, or unclear claims are welcomed
through GitHub issues at
https://github.com/prof-faustus/bonded-subsat-channel/issues.
