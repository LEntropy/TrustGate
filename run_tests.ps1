# Runs all tests and writes test-results\report.html
#   1) unit tests (JUnit 5) in a Maven container
#   2) starts Tomcat + Oracle with docker compose (if not running yet)
#   3) end-to-end test over real HTTP
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force test-results | Out-Null

Write-Host "`n==== [1/3] Unit tests (JUnit 5) ====" -ForegroundColor Cyan
docker run --rm -v "${PSScriptRoot}:/src" -v trustgate-m2:/root/.m2 -w /src maven:3.9-eclipse-temurin-17 mvn -B -q -pl core -am test
$unit = $LASTEXITCODE
Get-ChildItem core/target/surefire-reports/*.txt | ForEach-Object { Get-Content $_ | Select-String "Tests run" }

Write-Host "`n==== [2/3] Start Tomcat + Oracle ====" -ForegroundColor Cyan
docker compose up -d --build
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing http://localhost:8080/idp/jwks).StatusCode -eq 200) { $ready = $true; break } } catch {}
    Start-Sleep -Seconds 2
}
if (-not $ready) { Write-Host "IdP did not start; see: docker compose logs app" -ForegroundColor Red; exit 1 }

Write-Host "`n==== [3/3] End-to-end test ====" -ForegroundColor Cyan
$env:PYTHONIOENCODING = "utf-8"
python tools/e2e_test.py http://localhost:8080 test-results/e2e.json
$e2e = $LASTEXITCODE

python tools/make_report.py
Write-Host "Report: $PSScriptRoot\test-results\report.html" -ForegroundColor Green
if ($unit -ne 0 -or $e2e -ne 0) { exit 1 }
