# Quickstart walkthrough

> **⚠ RESEARCH CODE — regtest only.** This is the reference implementation
> accompanying an academic paper. Do not connect it to mainnet. See
> [LICENSE](../LICENSE) and [PRIVACY.md](PRIVACY.md).

This is the fastest path from a fresh clone to a green test run, a working
sub-satoshi transfer demo, and (optionally) a containerised one-command
demo. The whole flow is in two scripts; this document is the
human-readable walkthrough that explains what they do and why.

- **bash:** [`scripts/quickstart.sh`](../scripts/quickstart.sh)
- **PowerShell:** [`scripts/quickstart.ps1`](../scripts/quickstart.ps1)
- **demo only:** [`scripts/tiny_transfers_demo.py`](../scripts/tiny_transfers_demo.py)

Both quickstart scripts do exactly the same work and accept the same
flags; pick the one for your shell.

---

## 1. The one-line version

If you already have Python 3.11+ and `libsecp256k1` on a Debian/Ubuntu/macOS
machine:

```bash
git clone https://github.com/prof-faustus/bonded-subsat-channel
cd bonded-subsat-channel
./scripts/quickstart.sh
```

On Windows / PowerShell:

```powershell
git clone https://github.com/prof-faustus/bonded-subsat-channel
cd bonded-subsat-channel
.\scripts\quickstart.ps1
```

Expected output ends with:

```
========================================================================
  Done
========================================================================
Everything green.
```

Total wall time on a modern host: **≈ 30 seconds** (without Docker).

---

## 2. What the script does, step by step

The script prints a header before each step so you can follow along. Here
is every step and why it is there.

### Step 1 — prerequisites

Checks for `python3` on `PATH` and prints the version. Warns if the
detected version is outside the tested matrix (3.11 / 3.12). On Linux it
hints at `libsecp256k1-dev`; on macOS it hints at `brew install secp256k1
autoconf automake libtool` (autotools are required when the platform has
no pre-built wheel for your Python version and pip has to build from
source).

No state is changed in this step.

### Step 2 — venv + dependencies

Creates an isolated virtual environment at `.venv-quickstart/` inside the
repo (deliberately not `.venv/`, so it does not collide with whatever
you might already use for development), activates it, and installs:

- `requirements.txt` — `bitcoinX`, `pytest`, `hypothesis`, `mypy`
- `pytest-cov` — coverage measurement
- `bandit` — security lint

The venv is reusable: a second run reuses the existing venv and `pip
install` is a no-op.

### Step 3 — tests + mypy + bandit

Runs the three quality gates the project commits to:

1. **`pytest -q`** — full test suite (183 tests including 6 platform
   matrices in CI but a single platform here). Every spend in every test
   is executed through the real Bitcoin Script interpreter via
   [`channel.verify.verify_spend`](../src/channel/verify.py). No
   signature spot-check is used as a substitute.
2. **`mypy src/`** — type-checks the source tree (44 files, clean).
3. **`bandit -r src/ --severity-level high --confidence-level medium`** —
   static security scan; expected to be clean. If a high-severity
   finding lands, the script halts (`exit 1`) and asks you to review
   before continuing.

If any of these fail, fix the underlying issue before doing anything
else. The remaining steps assume green.

### Step 4 — tiny-transfers demo

Runs [`scripts/tiny_transfers_demo.py`](../scripts/tiny_transfers_demo.py).
This is the **central paper claim made visible in 50 lines of output**.

The demo opens a channel funded with **a single satoshi** subdivided into
`k = 1000` micro-units (one micro-unit = one milli-satoshi), then makes
200 transfers of one micro-unit each between random parties. Each transfer
moves `1/1000` of a satoshi off-chain — strictly sub-satoshi, impossible
on a plain Bitcoin output.

At the close, the demo prints:

- the **off-chain micro-unit balances** (each strictly sub-satoshi);
- the **`Q*(state)` netting** — the integer-satoshi payouts that will
  actually settle;
- the **cooperative-close transaction** — every input verified through
  the real interpreter — with per-party `q_i + bond_i` outputs summing
  exactly to `S + sum(bonds)`.

The assertions in the demo are real: a conservation violation would
exit non-zero.

Customise the run via flags:

```bash
python scripts/tiny_transfers_demo.py \
    --parties 5 --k 1000 --funded 1 --bond 1 \
    --transfers 1000 --seed 42
```

### Step 5 — Phase 12 transcript

Runs the full-system integration test. This is the largest single test
in the suite: it stands up the embedded BSV regtest node, funds the
wallet, opens a real wallet-funded channel through the mempool,
performs 250 transfers, routes a payment over a multi-hop hashlocked
path, cooperatively closes, opens a second channel and contested-closes
it defended by a watchtower, then simulates a restart and asserts full
state recovery.

The transcript is also written to
[`docs/PHASE12_TRANSCRIPT.txt`](PHASE12_TRANSCRIPT.txt) on every run,
so you can read the most recent successful run without re-running.

### Step 6 (optional) — Docker

With `--with-docker` (bash) / `-WithDocker` (PowerShell), the script:

1. Builds the [`Dockerfile`](../Dockerfile) image. The Dockerfile is
   multi-stage and **runs `pytest` and `mypy` at build time**, so a
   broken image cannot ship.
2. Runs the image, which prints the Phase 12 transcript on stdout.

First build is ~3 minutes (downloading the base image and building
secp256k1). Subsequent runs are ~30 seconds.

The image is tagged `bonded-subsat-channel:quickstart` locally; the
`--cleanup` flag removes it.

### Cleanup

```bash
./scripts/quickstart.sh --cleanup
```

```powershell
.\scripts\quickstart.ps1 -Cleanup
```

Removes:

- the `.venv-quickstart/` virtualenv;
- the `bonded-subsat-channel:quickstart` Docker image (if Docker is
  installed and the image exists).

Nothing else is touched. The repo, your git working tree, and the
project's tracked files are unchanged.

---

## 3. Reading the tiny-transfers demo output

A representative run with the default flags (4 parties, k=1000, S=1,
bond=1, 200 transfers, seed=42):

```
========================================================================
Tiny-transfers demo
========================================================================
  parties (n)                    : 4
  subdivision (k, micro-units/sat): 1000
  funded satoshis (S)            : 1
  per-party bond                 : 1 satoshi
  total micro-units in channel   : 1000
  one micro-unit                 : 1/1000 satoshi  (0.001000 sat)

Performing 200 transfers of 1 micro-unit each, random sender/recipient.

  applied 200 sub-satoshi transfers  (state version = 200)

Off-chain micro-unit balances (each strictly sub-satoshi):
  party 0:    988 micro-units  = 0.988000 satoshi
  party 1:      4 micro-units  = 0.004000 satoshi
  party 2:      2 micro-units  = 0.002000 satoshi
  party 3:      6 micro-units  = 0.006000 satoshi
  total      : 1000 micro-units  (== k*S = 1000) [OK]

On-chain settlement via Q* (whole satoshis only):
  party 0: q_i = 1 satoshi  (from 988 micro-units)
  party 1: q_i = 0 satoshi  (from 4 micro-units)
  party 2: q_i = 0 satoshi  (from 2 micro-units)
  party 3: q_i = 0 satoshi  (from 6 micro-units)
  sum        : 1 satoshi  (== S = 1) [OK]

Cooperative close (every input verified through the Script interpreter):
  tx size                : 940 bytes
  outputs (party payouts): 4
    party 0: 2 satoshi  (= Q*_i + bond_i = 1 + 1)
    party 1: 1 satoshi  (= Q*_i + bond_i = 0 + 1)
    party 2: 1 satoshi  (= Q*_i + bond_i = 0 + 1)
    party 3: 1 satoshi  (= Q*_i + bond_i = 0 + 1)
  total settled          : 5 satoshi
  expected (S + sum(bonds)): 5 satoshi
  conservation           : OK [OK]
```

What to notice:

- **Off-chain balances are sub-satoshi.** Party 1's holdings of 4
  micro-units = 0.004 satoshi is an amount you cannot represent in a
  plain Bitcoin output. The channel construction holds and transfers it
  off-chain at integer precision.

- **`Q*` is the netting rule.** Party 0 has 988 micro-units (close to
  one satoshi) and receives 1 satoshi at close; parties 1–3 each have
  small fractions and receive 0 satoshis from `Q*`. The remainder `R =
  S - sum(floor(a_i/k)) = 1 - 0 = 1` is awarded to the largest-fractional
  party (party 0), deterministically, with ties broken by index. See
  the proof in [REPORT.md §3](REPORT.md).

- **Conservation is exact.** `sum(Q*(a)) == S` always; the close pays
  exactly `S + sum(bonds)` satoshis. Both are asserted by the demo.

- **Every input went through the VM.** The cooperative-close transaction
  has `n+1` inputs (one channel-output spend, n bond returns). Each one
  was executed through `TxInputContext.verify_input(...,
  is_utxo_after_genesis=True)`. There is no signature spot-check
  substituting for VM execution anywhere.

If you increase `--k` and `--transfers`, you can move arbitrarily small
amounts. `k = 1_000_000_000` makes one micro-unit = one nanosatoshi.
There is no consensus limit on `k`; the only bound is the implementation's
integer representation (Python `int`, i.e. arbitrary precision).

---

## 4. Troubleshooting

### "libsecp256k1 not found" / wheel build failure

The `bitcoinx` dependency needs `libsecp256k1`. On a fresh system:

- **Debian/Ubuntu:** `sudo apt-get install -y libsecp256k1-dev`
- **macOS (Homebrew):** `brew install secp256k1 autoconf automake libtool`
  (the autotools are required when pip has to build the
  `electrumsv-secp256k1` package from source, which happens whenever no
  matching binary wheel exists for your Python version)
- **Windows:** the wheel is shipped pre-built; no extra packages needed.

If the wheel still fails to build, fall back to conda:

```bash
conda create -n bsc python=3.11
conda activate bsc
conda install -c conda-forge secp256k1
pip install -r requirements.txt
```

### "bandit found a high-severity finding"

The repo is committed to a clean bandit run at HIGH severity / MEDIUM
confidence. If a fresh finding appears it is either a regression (treat
as such) or a false positive (suppress it with a `# nosec Bxxx` comment
*plus* a one-line justification, never silently).

### Tests pass locally but fail in Docker

The Docker image rebuilds from a clean source copy and runs every test
at build time. If tests pass on the host but fail in Docker the most
common cause is an untracked file the host depends on (e.g. a stale
`.venv-quickstart` Python that pip imports from). The `.dockerignore`
file excludes the usual suspects; if the failure is unrelated to that,
open an issue.

### CI is green but the local run fails

CI uses Ubuntu/macOS/Windows × Python 3.11/3.12. If a local Python 3.13
or 3.10 fails where 3.11/3.12 pass, the project's tested range simply
does not include your Python version. Use `pyenv` or `conda` to get
3.11 or 3.12 alongside your system Python.

---

## 5. Next steps

- **For the science:** read [`docs/REPORT.md`](REPORT.md) — the full
  technical report with proofs and the line-level proof → test → source
  cross-reference in §10.8.
- **For the audit:** read [`docs/AUDIT.md`](AUDIT.md) — the full G1–G10
  / P1–P7 / L closure record with reviewer recipe.
- **For privacy implications:** read [`docs/PRIVACY.md`](PRIVACY.md) —
  what is on-chain visible and a six-item privacy roadmap.
- **For the design decisions:** read [`docs/DECISIONS.md`](DECISIONS.md)
  — D1 through D14, every choice made under ambiguity with reasoning.
- **To contribute:** see the PR template description in the repo root
  README and the contribution checklist there.
