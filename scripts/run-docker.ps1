[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetRepository,

    [Parameter(Position = 1)]
    [string]$OutputDirectory = "",

    [ValidateSet("fake", "real")]
    [string]$Provider = "fake"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$target = (Resolve-Path -LiteralPath $TargetRepository).Path
if (-not (Test-Path -LiteralPath $target -PathType Container)) {
    throw "TargetRepository must be an existing directory."
}

if (-not $OutputDirectory) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssZ")
    $repoName = Split-Path -Leaf $target
    $OutputDirectory = Join-Path $projectRoot "triage-runs\$repoName-$timestamp"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path

$env:TARGET_REPO = $target
$env:OUTPUT_DIR = $output
$env:REPOSITORY_ID = Split-Path -Leaf $target
$env:TRIAGE_PROVIDER = $Provider

Push-Location $projectRoot
try {
    docker info --format "Docker server: {{.ServerVersion}}"
    docker compose build joern-image sast-triage
    docker compose run --rm doctor
    docker compose run --rm sast-triage
}
finally {
    Pop-Location
}

Write-Output "Reports: $output"
