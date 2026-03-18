# GDB Debug Script - Quick Reference

## Installation

No installation required! Just use the script with GDB:

```bash
gdb -x gdb_debug_script.gdb <your_binary>
```

## Common Use Cases

### 1. Debug a Fuzzing Harness Crash

```bash
# Interactive debugging
gdb -x gdb_debug_script.gdb ./harness_binary
(gdb) run < crash_input
# When it crashes...
(gdb) crash-info
(gdb) triage-crash
(gdb) generate-repro
```

### 2. Batch Analysis (Automated)

```bash
# Analyze crash and exit automatically
gdb -batch -x gdb_debug_script.gdb ./harness_binary -ex "batch-analyze"
```

### 3. Analyze Fuzzing Input

```bash
gdb -x gdb_debug_script.gdb ./harness_binary
(gdb) break LLVMFuzzerTestOneInput
(gdb) run
# When stopped at breakpoint...
(gdb) fuzz-input
```

### 4. Debug AddressSanitizer Crash

```bash
gdb -x gdb_debug_script.gdb ./harness_asan
(gdb) run < crash_input
# When ASan detects error...
(gdb) asan-bt
(gdb) crash-info
```

### 5. Multiple Crashes Analysis

**Linux/macOS:**
```bash
./batch_crash_analysis.sh ./harness ./crashes ./analysis_output
```

**Windows (PowerShell):**
```powershell
.\batch_crash_analysis.ps1 -HarnessBinary .\harness.exe -CrashDir .\crashes -OutputDir .\analysis_output
```

## Quick Command Reference

| Command | Purpose |
|---------|---------|
| `crash-info` | Show comprehensive crash details |
| `triage-crash` | Automated crash triage + report |
| `generate-repro` | Create reproduction kit |
| `fuzz-input` | Analyze fuzzing input data |
| `heap-info` | Display heap information |
| `stack-info` | Display stack information |
| `check-overflow` | Check for buffer overflow |
| `check-uaf` | Check for use-after-free |
| `asan-bt` | AddressSanitizer backtrace |
| `batch-analyze` | Fully automated analysis |
| `help-autovul` | Show all commands |

## Output Files

After running the script, you'll get:

- `gdb_debug_session.log` - Complete session log
- `crash_triage_report.txt` - Detailed crash analysis
- `reproduction_kit.txt` - Full reproduction info
- `crash_core_dump` - Core dump (if generated)

## Integration with AutoVulRepair

### Module 5: Fuzz Execution

When fuzzing finds crashes:

```bash
cd scans/<scan_id>/harnesses/<harness_name>
gdb -x ../../../../gdb_debug_script.gdb ./harness_binary
(gdb) run < ../crashes/crash-<hash>
(gdb) triage-crash
```

### Module 6: Crash Triage

Automated triage of all crashes:

```bash
cd scans/<scan_id>/harnesses/<harness_name>
../../../../batch_crash_analysis.sh ./harness_binary ../crashes ./triage_results
```

### Module 7: Reproduction Kit

Generate reproduction kits:

```bash
gdb -batch -x gdb_debug_script.gdb ./harness \
    -ex "run < crash_input" \
    -ex "generate-repro" \
    -ex "quit"
```

## Tips

1. **Always compile with debug symbols:** `-g` flag
2. **Use sanitizers:** `-fsanitize=address,undefined`
3. **Save crash inputs** for later analysis
4. **Check logs** in `gdb_debug_session.log`
5. **Review triage reports** for exploitability

## Troubleshooting

### GDB not found
```bash
# Linux
sudo apt-get install gdb

# macOS
brew install gdb

# Windows (WSL2)
sudo apt-get install gdb
```

### Script not loading
```bash
# Use absolute path
gdb -x /full/path/to/gdb_debug_script.gdb ./binary
```

### No symbols loaded
```bash
# Recompile with debug symbols
clang++ -g -O0 harness.cpp -o harness
```

## Examples

### Example 1: Simple Crash Analysis

```bash
$ gdb -x gdb_debug_script.gdb ./harness
(gdb) run < crash-abc123
# Crash occurs...
(gdb) crash-info

=== CRASH ANALYSIS ===
Signal: SIGSEGV (Segmentation fault)
Address: 0x41414141
Backtrace:
  #0  0x41414141 in ?? ()
  #1  0x00000000004012a3 in vulnerable_function ()
  #2  0x0000000000401156 in LLVMFuzzerTestOneInput ()
```

### Example 2: Batch Analysis

```bash
$ ./batch_crash_analysis.sh ./harness ./crashes ./results

=== AutoVulRepair Batch Crash Analysis ===
Found 5 crash files to analyze

[1/5] Analyzing crash-abc123...
  Crash Type: SIGSEGV
  Output saved to: ./results/crash-abc123

[2/5] Analyzing crash-def456...
  Crash Type: SIGABRT
  Output saved to: ./results/crash-def456

...

Summary report generated: ./results/SUMMARY.md
```

### Example 3: Fuzzing Input Analysis

```bash
$ gdb -x gdb_debug_script.gdb ./harness
(gdb) break LLVMFuzzerTestOneInput
(gdb) run
(gdb) fuzz-input

=== FUZZING INPUT ANALYSIS ===
Input Data Pointer: 0x7ffff7fb0000
Input Size: 256
First 256 bytes:
0x7ffff7fb0000: 41 41 41 41 42 42 42 42 ...
```

## Need More Help?

See the full documentation:
- [GDB_DEBUG_GUIDE.md](./GDB_DEBUG_GUIDE.md) - Complete guide
- [README.md](./README.md) - AutoVulRepair overview
- [USER_GUIDE.md](./USER_GUIDE.md) - User guide

Or get help in GDB:
```gdb
(gdb) help-autovul
```
