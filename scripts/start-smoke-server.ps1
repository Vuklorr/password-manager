# Test-only H2 server. Never use this configuration for real credentials.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$reportPath = Join-Path $repoRoot 'target/surefire-reports/TEST-dev.vault.VaultIntegrationTest.xml'
if (-not (Test-Path -LiteralPath $reportPath)) { throw 'Run mvn test first.' }
$testReport = [xml](Get-Content -LiteralPath $reportPath)
$testClasspath = ($testReport.testsuite.properties.property | Where-Object name -eq 'java.class.path').value
if (-not $testClasspath) { throw 'Test runtime classpath not found.' }
& java -cp $testClasspath dev.vault.VaultApplication --server.port=8080
