#!/usr/bin/env bash
#
# One-command quickstart for bonded-subsat-channel.
#
#   ./scripts/quickstart.sh                # full flow: venv + tests + demo
#   ./scripts/quickstart.sh --with-docker  # also build + run the docker image
#   ./scripts/quickstart.sh --cleanup      # remove venv + docker image
#
# Total wall time (no docker): ~30 s on a modern host.
# Total wall time (with docker): ~3-5 min on first build, then ~30 s.
#
# The script does only reversible work and prints what it is doing at each
# step. Nothing is force-deleted without an explicit --cleanup. Read it
# before running it; this is research code, not a black box.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv-quickstart"
DOCKER_IMAGE="bonded-subsat-channel:quickstart"

WITH_DOCKER=0
CLEANUP=0
PYTHON_BIN="${PYTHON_BIN:-python3}"

for arg in "$@"; do
  case "$arg" in
    --with-docker)  WITH_DOCKER=1 ;;
    --cleanup)      CLEANUP=1 ;;
    -h|--help)
        sed -n '1,15p' "$0"; exit 0 ;;
    *)  echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

section() {
  printf '\n========================================================================\n'
  printf '  %s\n' "$*"
  printf '========================================================================\n'
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
if [[ "$CLEANUP" -eq 1 ]]; then
  section "Cleanup"
  if [[ -d "$VENV_DIR" ]]; then
    echo "removing ${VENV_DIR}"
    rm -rf "$VENV_DIR"
  fi
  if command -v docker >/dev/null 2>&1; then
    if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
      echo "removing docker image ${DOCKER_IMAGE}"
      docker image rm "$DOCKER_IMAGE" >/dev/null || true
    fi
  fi
  echo "Cleanup done."
  exit 0
fi

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 1 — system prerequisites
# ---------------------------------------------------------------------------
section "Step 1 — checking prerequisites"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: python3 not found on PATH; install Python 3.11+ first" >&2
  exit 1
fi
PY_VER=$("$PYTHON_BIN" -c 'import sys;print("{}.{}".format(*sys.version_info[:2]))')
echo "python: $("$PYTHON_BIN" -V)  ($PY_VER)"
case "$PY_VER" in
  3.11|3.12|3.13) ;;
  *) echo "warning: tested on Python 3.11/3.12; you have $PY_VER" >&2 ;;
esac

# Native libsecp256k1 is needed by the bitcoinx wheel. Try to detect.
if [[ "$(uname -s)" == "Linux" ]]; then
  if ! ldconfig -p 2>/dev/null | grep -q libsecp256k1; then
    echo "hint: install libsecp256k1-dev (e.g. sudo apt-get install -y libsecp256k1-dev)"
  fi
elif [[ "$(uname -s)" == "Darwin" ]]; then
  if ! command -v brew >/dev/null 2>&1 || ! brew list secp256k1 >/dev/null 2>&1; then
    echo "hint: brew install secp256k1 autoconf automake libtool"
  fi
fi

# ---------------------------------------------------------------------------
# Step 2 — venv + dependencies
# ---------------------------------------------------------------------------
section "Step 2 — creating venv and installing dependencies"
if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt
python -m pip install pytest-cov bandit
python -V
python -c "import bitcoinx; print('bitcoinx:', getattr(bitcoinx, '__version__', 'ok'))"

# ---------------------------------------------------------------------------
# Step 3 — full test suite + mypy + bandit
# ---------------------------------------------------------------------------
section "Step 3 — running tests, mypy, bandit"
python -m pytest -q
python -m mypy src/
python -m bandit -r src/ --severity-level high --confidence-level medium -q || {
  echo "bandit found a high-severity finding; review before continuing" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Step 4 — tiny-transfers demo
# ---------------------------------------------------------------------------
section "Step 4 — tiny-transfers demo (sub-satoshi off-chain, integer on-chain)"
python scripts/tiny_transfers_demo.py

# ---------------------------------------------------------------------------
# Step 5 — full Phase 12 end-to-end transcript
# ---------------------------------------------------------------------------
section "Step 5 — Phase 12 full-system integration transcript"
python -m pytest tests/test_integration.py -v -s 2>&1 | sed -n '/Phase 12/,/Phase 12 . PASSED/p' || true

# ---------------------------------------------------------------------------
# Step 6 (optional) — Docker
# ---------------------------------------------------------------------------
if [[ "$WITH_DOCKER" -eq 1 ]]; then
  section "Step 6 — building and running the docker image"
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not on PATH; skipping" >&2
  else
    docker build -t "$DOCKER_IMAGE" .
    echo
    echo "Running container (Phase 12 transcript):"
    docker run --rm "$DOCKER_IMAGE"
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
section "Done"
echo "Everything green."
echo
echo "Next steps:"
echo "  - read docs/QUICKSTART.md for the walkthrough"
echo "  - read docs/REPORT.md for the technical report"
echo "  - read docs/AUDIT.md for the audit and gap-closure record"
echo "  - read docs/PRIVACY.md for what is on-chain visible"
echo
echo "To clean up:"
echo "  ./scripts/quickstart.sh --cleanup"
