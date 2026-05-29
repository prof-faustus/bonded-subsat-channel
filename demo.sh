#!/usr/bin/env bash
# One-command demo for bonded-subsat-channel.
#
# Usage:
#     ./demo.sh           # local (uses host Python)
#     ./demo.sh docker    # build and run the Docker image
#
# Both paths print the Phase 12 end-to-end transcript on stdout.
# Target: total wall time under 60 s on a modern host.

set -euo pipefail

MODE="${1:-local}"

case "$MODE" in
  local)
    echo ">>> running tests locally"
    python -m pip install -q -r requirements.txt
    python -m pytest -q
    echo
    echo ">>> Phase 12 end-to-end transcript"
    echo
    python -m pytest tests/test_integration.py -v -s
    ;;
  docker)
    echo ">>> building image"
    docker build -t bonded-subsat-channel:demo .
    echo
    echo ">>> running Phase 12 transcript in container"
    docker run --rm bonded-subsat-channel:demo
    ;;
  *)
    echo "usage: $0 [local|docker]" >&2
    exit 2
    ;;
esac
