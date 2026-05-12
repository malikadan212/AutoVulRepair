# Batch Crash Analysis Script for AutoVulRepair (PowerShell)
# This script analyzes multiple crash files using the GDB debug script

param(
    [string]$HarnessBinary = ".\harness.exe",
    [string]$CrashDir = ".\crashes",
    [string]$OutputDir = ".\crash_analysis",
    [string]$GdbScript = ".\gdb_debug_script.gdb"
)

# Configuration
$ErrorActionPreference = "Continue"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "=== AutoVulRepair Batch Crash Analysis ===" -ForegroundColor Green
Write-Host "Harness Binary: $HarnessBinary"
Write-Host "Crash Directory: $CrashDir"
Write-Host "Output Directory: $OutputDir"
Write-Host "GDB Script: $GdbScript"
Write-Host ""

# Check if harness binary exists
if (-not (Test-Path $HarnessBinary)) {
    Write-Host "Error: Harness binary not found: $HarnessBinary" -ForegroundColor Red
    exit 1
}

# Check if GDB script exists
if (-not (Test-Path $GdbScript)) {
    Write-Host "Error: GDB script not found: $GdbScript" -ForegroundColor Red
    exit 1
}

# Check if crash directory exists
if (-not (Test-Path $CrashDir)) {
    Write-Host "Error: Crash directory not found: $CrashDir" -ForegroundColor Red
    exit 1
}

# Get crash files
$crashFiles = Get-ChildItem -Path $CrashDir -Filter "crash-*" -File

if ($crashFiles.Count -eq 0) {
    Write-Host "Warning: No crash files found in $CrashDir" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($crashFiles.Count) crash files to analyze" -ForegroundColor Green
Write-Host ""

# Analyze each crash
$crashNum = 0
foreach ($crashFile in $crashFiles) {
    $crashNum++
    $crashBasename = $crashFile.Name
    
    Write-Host "[$crashNum/$($crashFiles.Count)] Analyzing $crashBasename..." -ForegroundColor Yellow
    
    # Create output subdirectory for this crash
    $crashOutputDir = Join-Path $OutputDir $crashBasename
    New-Item -ItemType Directory -Force -Path $crashOutputDir | Out-Null
    
    # Prepare GDB command
    $gdbCommands = @(
        "run < $($crashFile.FullName)",
        "triage-crash",
        "generate-repro",
        "generate-core-file $crashOutputDir\core",
        "quit"
    )
    
    # Run GDB analysis
    try {
        $gdbOutput = Join-Path $crashOutputDir "gdb_output.txt"
        
        # Build GDB command line
        $gdbArgs = @(
            "-batch",
            "-x", $GdbScript,
            $HarnessBinary
        )
        
        foreach ($cmd in $gdbCommands) {
            $gdbArgs += "-ex"
            $gdbArgs += $cmd
        }
        
        # Execute GDB with timeout
        $process = Start-Process -FilePath "gdb" -ArgumentList $gdbArgs `
            -RedirectStandardOutput $gdbOutput `
            -RedirectStandardError "$crashOutputDir\gdb_error.txt" `
            -NoNewWindow -PassThru -Wait
        
        # Wait with timeout (60 seconds)
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            Write-Host "  Warning: GDB analysis timed out" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Error running GDB: $_" -ForegroundColor Red
    }
    
    # Move generated files to crash-specific directory
    $filesToMove = @(
        "gdb_debug_session.log",
        "crash_triage_report.txt",
        "reproduction_kit.txt"
    )
    
    foreach ($file in $filesToMove) {
        if (Test-Path $file) {
            Move-Item -Path $file -Destination $crashOutputDir -Force
        }
    }
    
    # Copy the crash input
    Copy-Item -Path $crashFile.FullName -Destination (Join-Path $crashOutputDir "crash_input") -Force
    
    # Extract crash type from triage report
    $triageReport = Join-Path $crashOutputDir "crash_triage_report.txt"
    if (Test-Path $triageReport) {
        $crashType = Select-String -Path $triageReport -Pattern "signal" -SimpleMatch | Select-Object -First 1
        if ($crashType) {
            Write-Host "  Crash Type: $($crashType.Line)" -ForegroundColor Green
        }
    }
    
    Write-Host "  Output saved to: $crashOutputDir" -ForegroundColor Green
    Write-Host ""
}

# Generate summary report
Write-Host "=== Generating Summary Report ===" -ForegroundColor Green

$summaryFile = Join-Path $OutputDir "SUMMARY.md"
$summaryContent = @"
# Crash Analysis Summary

**Analysis Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Harness Binary:** $HarnessBinary
**Total Crashes Analyzed:** $($crashFiles.Count)

## Crash Details

"@

# Analyze each crash report
$crashDirs = Get-ChildItem -Path $OutputDir -Directory -Filter "crash-*"

foreach ($crashDir in $crashDirs) {
    $crashName = $crashDir.Name
    
    $summaryContent += @"

### $crashName

"@
    
    # Extract key information from triage report
    $triageReport = Join-Path $crashDir.FullName "crash_triage_report.txt"
    if (Test-Path $triageReport) {
        $summaryContent += "``````n"
        
        # Get signal information
        $content = Get-Content $triageReport -Raw
        if ($content -match "Signal Information[\s\S]{0,500}") {
            $summaryContent += $matches[0] + "`n"
        }
        
        $summaryContent += "``````n`n"
        
        # Extract backtrace
        $summaryContent += "**Backtrace:**`n``````n"
        if ($content -match "STACK TRACE[\s\S]{0,1000}") {
            $summaryContent += $matches[0] + "`n"
        }
        $summaryContent += "``````n`n"
    }
    
    $summaryContent += @"
**Files:**
- [Full Triage Report](./$crashName/crash_triage_report.txt)
- [Reproduction Kit](./$crashName/reproduction_kit.txt)
- [GDB Session Log](./$crashName/gdb_debug_session.log)
- [Core Dump](./$crashName/core)
- [Crash Input](./$crashName/crash_input)

---

"@
}

# Add statistics
$uniqueCrashes = 0
$triageReports = Get-ChildItem -Path $OutputDir -Recurse -Filter "crash_triage_report.txt"
if ($triageReports) {
    $signals = $triageReports | ForEach-Object {
        Select-String -Path $_.FullName -Pattern "signal" -SimpleMatch | Select-Object -First 1
    } | Select-Object -Unique
    $uniqueCrashes = $signals.Count
}

$summaryContent += @"

## Statistics

| Metric | Value |
|--------|-------|
| Total Crashes | $($crashFiles.Count) |
| Unique Crash Types | $uniqueCrashes |

## Next Steps

1. Review each crash triage report for exploitability
2. Prioritize crashes based on severity and uniqueness
3. Create bug reports with reproduction kits
4. Verify fixes with saved crash inputs

"@

# Write summary to file
Set-Content -Path $summaryFile -Value $summaryContent

Write-Host "Summary report generated: $summaryFile" -ForegroundColor Green
Write-Host ""
Write-Host "=== Analysis Complete ===" -ForegroundColor Green
Write-Host "Results saved to: $OutputDir" -ForegroundColor Green
Write-Host ""
Write-Host "To view the summary:"
Write-Host "  Get-Content $summaryFile"
Write-Host ""
Write-Host "To debug a specific crash interactively:"
Write-Host "  gdb -x $GdbScript $HarnessBinary"
Write-Host "  (gdb) run < $CrashDir\crash-<hash>"
