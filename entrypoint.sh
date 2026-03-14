#!/bin/bash
# entrypoint.sh
# GitHub Actions passes the action.yml inputs as positional arguments $1, $2, $3

set -e   # Stop on any error

# ─── READ INPUTS FROM action.yml ─────────────────────────────────────────────
ANALYSIS_TOOL="${1:-cppcheck}"
SOURCE_DIR="${2:-.}"
FAIL_ON_VULN="${3:-false}"

# ─── ENVIRONMENT SETUP ───────────────────────────────────────────────────────
# NOTE: GitHub Actions ALREADY sets $GITHUB_WORKSPACE to /github/workspace
# DO NOT override it here or the scan will point to the wrong folder.
export SCANS_DIR="/tmp/avr_scans"
export FLASK_SECRET_KEY="headless-ci-mode"

mkdir -p "$SCANS_DIR"

# ─── BANNER ──────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
echo "║       AutoVulRepair — Security Audit v1.0            ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Tool    : ${ANALYSIS_TOOL}"
echo "║  Source  : ${GITHUB_WORKSPACE}/${SOURCE_DIR}"
echo "║  Fail    : ${FAIL_ON_VULN}"
echo "║  Scans   : ${SCANS_DIR}"
echo "╚══════════════════════════════════════════════════════╝"

# ─── RUN THE PYTHON PIPELINE ─────────────────────────────────────────────────
cd /app

python cli.py \
    --tool           "${ANALYSIS_TOOL}" \
    --source-dir     "${GITHUB_WORKSPACE}/${SOURCE_DIR}" \
    --github-event-path "${GITHUB_EVENT_PATH:-/dev/null}" \
    --github-token   "${GITHUB_TOKEN:-}"

PIPELINE_EXIT=$?

# ─── EXIT CODE HANDLING ──────────────────────────────────────────────────────
if [ "$PIPELINE_EXIT" -ne 0 ]; then
    if [ "${FAIL_ON_VULN}" = "true" ]; then
        echo "::error title=AutoVulRepair::Vulnerabilities detected. Failing build (fail_on_vuln=true)."
        exit 1
    else
        echo "::warning title=AutoVulRepair::Vulnerabilities found, but fail_on_vuln=false. Build continues."
        exit 0
    fi
fi

echo "✅ AutoVulRepair: Scan complete. No critical issues."
exit 0
