# Bonded Sub-Satoshi Channels — research-code container.
#
# Builds a small image that contains the source, runs the test suite,
# and (when invoked with the demo entrypoint) prints the Phase 12
# end-to-end transcript on stdout in under 60 seconds on a modern host.
#
# THIS IS RESEARCH CODE. The container has no network mode that would
# connect to mainnet. The embedded BSV node runs in regtest only.

FROM python:3.12-slim AS build

LABEL org.opencontainers.image.title="bonded-subsat-channel"
LABEL org.opencontainers.image.description="Research reference implementation — regtest only."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/prof-faustus/bonded-subsat-channel"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libsecp256k1-dev \
        build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the manifest first so dependency layers cache between builds.
COPY requirements.txt pyproject.toml ./
RUN python -m pip install --upgrade pip \
 && python -m pip install -r requirements.txt \
 && python -m pip install pytest-cov

# Now the source.
COPY . .

# Run the suite at build time so a broken image never ships.
RUN python -m pytest -q \
 && python -m mypy src/

# ---------------------------------------------------------------------------
# Runtime entry — print Phase 12 transcript by default.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends libsecp256k1-0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /app /app

ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1

# Default: print the Phase 12 transcript. Override for an interactive shell:
#     docker run --rm -it bonded-subsat-channel bash
ENTRYPOINT ["python", "-m", "pytest",
            "tests/test_integration.py::test_phase12_full_system_integration",
            "-v", "-s"]
