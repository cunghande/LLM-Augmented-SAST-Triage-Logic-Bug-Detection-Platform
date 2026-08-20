#!/bin/sh
set -eu

repository="${SAST_TRIAGE_REPOSITORY:-/workspace/repository}"

test -d "${repository}"
test -r "${repository}"
docker info --format 'Docker server: {{.ServerVersion}}'
docker image inspect sast-triage-joern:4.0.600 >/dev/null
python --version
semgrep --version
gitleaks version
python -c 'import sast_triage; print("sast-triage import: OK")'
printf '%s\n' 'Docker/Joern/scanner preflight: OK'
