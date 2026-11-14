$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceDir = Join-Path $repoRoot 'src/main/resources/static/lib'
$targetDir = Join-Path $repoRoot 'extension/lib'
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Copy-Item -Path (Join-Path $sourceDir '*.js') -Destination $targetDir -Force
Write-Output 'Shared client modules synchronized.'
