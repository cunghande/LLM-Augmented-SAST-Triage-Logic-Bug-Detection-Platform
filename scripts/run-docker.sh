#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 TARGET_REPOSITORY [OUTPUT_DIRECTORY] [fake|real]" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
project_root=$(CDPATH= cd -- "${script_dir}/.." && pwd -P)
target=$(CDPATH= cd -- "$1" && pwd -P)
provider=${3:-fake}

case "$provider" in
    fake|real) ;;
    *) echo "Provider must be fake or real." >&2; exit 2 ;;
esac

if [ "$#" -ge 2 ] && [ -n "$2" ]; then
    mkdir -p -- "$2"
    output=$(CDPATH= cd -- "$2" && pwd -P)
else
    timestamp=$(date -u +%Y%m%d-%H%M%SZ)
    repo_name=$(basename -- "$target")
    mkdir -p -- "${project_root}/triage-runs/${repo_name}-${timestamp}"
    output=$(CDPATH= cd -- "${project_root}/triage-runs/${repo_name}-${timestamp}" && pwd -P)
fi

export TARGET_REPO="$target"
export OUTPUT_DIR="$output"
export REPOSITORY_ID="$(basename -- "$target")"
export TRIAGE_PROVIDER="$provider"

cd "$project_root"
docker info --format 'Docker server: {{.ServerVersion}}'
docker compose build joern-image sast-triage
docker compose run --rm doctor
docker compose run --rm sast-triage

printf 'Reports: %s\n' "$output"
