#!/usr/bin/env bash
# Esegue gli scanner disponibili e salva i report SARIF/JSON in out/
set -u
cd "$(dirname "$0")/.." && mkdir -p out
have() { command -v "$1" >/dev/null 2>&1 || { echo "[salto] $1 non installato"; return 1; }; }
have semgrep  && semgrep scan --config auto --sarif -o out/semgrep.sarif projects/
have gitleaks && gitleaks detect --source . --report-format sarif --report-path out/gitleaks.sarif   # include la storia git
have trivy    && trivy fs --scanners vuln,secret,misconfig,license --format sarif -o out/trivy-fs.sarif .
have checkov  && checkov -d . --framework terraform,kubernetes,dockerfile,github_actions -o sarif --output-file-path out/
have hadolint && for d in projects/*/Dockerfile; do hadolint "$d" > "out/hadolint-$(basename "$(dirname "$d")").txt"; done
have bandit   && bandit -r projects/01-flask-shop -f json -o out/bandit.json
have osv-scanner && osv-scanner scan -r . --format json --output out/osv.json
echo "Report in out/. Confrontare con EXPECTED.md"
