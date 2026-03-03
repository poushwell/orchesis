$ErrorActionPreference = "Stop"

Write-Host "=== Orchesis Stress Test ==="
Write-Host "Running 4 frameworks × 3 attacks × 2 modes = 24 tests"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$frameworks = @("openclaw", "crewai", "langgraph", "openai_agents")
foreach ($framework in $frameworks) {
    Write-Host ""
    Write-Host "--- Framework: $framework ---"
    Set-Location $framework
    Write-Host "Running WITHOUT Orchesis..."
    try { python run_without_orchesis.py } catch { Write-Host "[WARN] $($_.Exception.Message)" }
    Write-Host "Running WITH Orchesis..."
    try { python run_with_orchesis.py } catch { Write-Host "[WARN] $($_.Exception.Message)" }
    Set-Location ..
}

Write-Host ""
Write-Host "=== Analyzing Results ==="
python analyze_results.py
Write-Host "Done! See results/summary.md"
