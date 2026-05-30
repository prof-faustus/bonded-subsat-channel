# One-command quickstart for bonded-subsat-channel (Windows / PowerShell).
#
#   .\scripts\quickstart.ps1                  # full flow: venv + tests + demo
#   .\scripts\quickstart.ps1 -WithDocker      # also build + run the docker image
#   .\scripts\quickstart.ps1 -Cleanup         # remove venv + docker image
#
# Total wall time (no docker): ~30 s on a modern host.
# Read it before running it; this is research code, not a black box.
#
# The script does only reversible work. Nothing is force-deleted without
# an explicit -Cleanup.

[CmdletBinding()]
param(
    [switch]$WithDocker,
    [switch]$Cleanup,
    [string]$PythonBin = "python"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvDir = Join-Path $RepoRoot ".venv-quickstart"
$DockerImage = "bonded-subsat-channel:quickstart"

function Section($msg) {
    Write-Host ""
    Write-Host ("=" * 72)
    Write-Host "  $msg"
    Write-Host ("=" * 72)
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
if ($Cleanup) {
    Section "Cleanup"
    if (Test-Path $VenvDir) {
        Write-Host "removing $VenvDir"
        Remove-Item $VenvDir -Recurse -Force
    }
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        if (docker image inspect $DockerImage 2>$null) {
            Write-Host "removing docker image $DockerImage"
            docker image rm $DockerImage | Out-Null
        }
    }
    Write-Host "Cleanup done."
    return
}

Set-Location $RepoRoot

# ---------------------------------------------------------------------------
# Step 1 — prerequisites
# ---------------------------------------------------------------------------
Section "Step 1 - checking prerequisites"
if (-not (Get-Command $PythonBin -ErrorAction SilentlyContinue)) {
    Write-Error "python not found on PATH; install Python 3.11+ first"
    exit 1
}
$pyVersion = & $PythonBin -c "import sys;print('{}.{}'.format(*sys.version_info[:2]))"
Write-Host "python: $(& $PythonBin -V)  ($pyVersion)"
if ($pyVersion -notin @("3.11", "3.12", "3.13")) {
    Write-Warning "tested on Python 3.11/3.12; you have $pyVersion"
}

# ---------------------------------------------------------------------------
# Step 2 — venv + dependencies
# ---------------------------------------------------------------------------
Section "Step 2 - creating venv and installing dependencies"
if (-not (Test-Path $VenvDir)) {
    & $PythonBin -m venv $VenvDir
}
$activate = Join-Path $VenvDir "Scripts\Activate.ps1"
. $activate
python -m pip install --upgrade pip | Out-Null
python -m pip install -r requirements.txt
python -m pip install pytest-cov bandit
python -V
python -c "import bitcoinx; print('bitcoinx:', getattr(bitcoinx, '__version__', 'ok'))"

# ---------------------------------------------------------------------------
# Step 3 — tests + mypy + bandit
# ---------------------------------------------------------------------------
Section "Step 3 - running tests, mypy, bandit"
python -m pytest -q
python -m mypy src/
python -m bandit -r src/ --severity-level high --confidence-level medium -q
if ($LASTEXITCODE -ne 0) {
    Write-Error "bandit found a high-severity finding; review before continuing"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 4 — tiny-transfers demo
# ---------------------------------------------------------------------------
Section "Step 4 - tiny-transfers demo (sub-satoshi off-chain, integer on-chain)"
python scripts/tiny_transfers_demo.py

# ---------------------------------------------------------------------------
# Step 5 — Phase 12 transcript
# ---------------------------------------------------------------------------
Section "Step 5 - Phase 12 full-system integration transcript"
python -m pytest tests/test_integration.py -v -s

# ---------------------------------------------------------------------------
# Step 6 (optional) — Docker
# ---------------------------------------------------------------------------
if ($WithDocker) {
    Section "Step 6 - building and running the docker image"
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Warning "docker not on PATH; skipping"
    } else {
        docker build -t $DockerImage .
        Write-Host ""
        Write-Host "Running container (Phase 12 transcript):"
        docker run --rm $DockerImage
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Section "Done"
Write-Host "Everything green."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - read docs/QUICKSTART.md for the walkthrough"
Write-Host "  - read docs/REPORT.md for the technical report"
Write-Host "  - read docs/AUDIT.md for the audit and gap-closure record"
Write-Host "  - read docs/PRIVACY.md for what is on-chain visible"
Write-Host ""
Write-Host "To clean up:"
Write-Host "  .\scripts\quickstart.ps1 -Cleanup"
