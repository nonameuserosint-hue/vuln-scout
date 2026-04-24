#!/usr/bin/env bash
set -euo pipefail

python3 whitebox-pentest/scripts/doctor.py --strict
python3 whitebox-pentest/scripts/scan_orchestrator.py . --profile quick --format sarif --output findings.sarif
python3 whitebox-pentest/scripts/report.py .claude/findings.json --fail-on high
