# GDB Debug Script - User Guide

## Overview

The `gdb_debug_script.gdb` provides automated debugging capabilities for the AutoVulRepair fuzzing harnesses and crash analysis. It includes specialized commands for vulnerability detection, crash triage, and reproduction kit generation.

## Quick Start

### Basic Usage

```bash
# Debug a compiled fuzzing harness
gdb -x gdb_debug_script.gdb ./harness_binary

# Debug with a specific input file
gdb -x gdb_debug_script.gdb --args ./harness_binary input_file

# Batch mode (automated crash analysis)
gdb -batch -x gdb_debug_script.gdb ./harness_binary -ex "batch-analyze"
```

### Debugging a Crash

```bash
# Load the binary and crash input
gdb -x gdb_debug_script.gdb ./harness_binary

# In GDB, run with the crashing input
(gdb) run < crash_input.bin

# When it crashes, analyze it
(gdb) triage-crash
(gdb) generate-repro
```

## Available Commands

### Crash Analysis Commands

#### `crash-info`
Displays comprehensive crash information including:
- Signal information
- Register state
- Full backtrace with local variables
- Memory at crash point
- Stack contents
- Shared libraries

**Usage:**
```gdb
(gdb) crash-info
```

#### `triage-crash`
Automated crash triage that:
- Analyzes crash signal
- Determines crash location
- Examines crash context
- Generates exploitability assessment
- Saves report to `crash_triage_report.txt`

**Usage:**
```gdb
(gdb) triage-crash
```

#### `generate-repro`
Creates a complete reproduction kit with:
- Binary information
- Full backtrace
- Register state
- Memory mappings
- Disassembly
- Local variables and arguments
- Saves to `reproduction_kit.txt`

**Usage:**
```gdb
(gdb) generate-repro
```

### Memory Analysis Commands

#### `heap-info`
Displays heap memory information and allocations.

**Usage:**
```gdb
(gdb) heap-info
```

#### `stack-info`
Shows stack frame information, backtrace, and stack memory contents.

**Usage:**
```gdb
(gdb) stack-info
```

#### `mem-search`
Search memory for a specific pattern.

**Usage:**
```gdb
(gdb) mem-search 0x400000 0x41414141
```

### Vulnerability Detection Commands

#### `check-overflow`
Checks for buffer overflow indicators including stack canary corruption.

**Usage:**
```gdb
(gdb) check-overflow
```

#### `check-uaf`
Examines potential use-after-free conditions.

**Usage:**
```gdb
(gdb) check-uaf
```

### Fuzzing-Specific Commands

#### `fuzz-input`
Analyzes the fuzzing input data passed to `LLVMFuzzerTestOneInput`:
- Input data pointer
- Input size
- First 256 bytes of input (hex dump)
- Input as string

**Usage:**
```gdb
# Set breakpoint in fuzzing harness
(gdb) break LLVMFuzzerTestOneInput
(gdb) run
# When stopped at breakpoint
(gdb) fuzz-input
```

### Sanitizer Support Commands

#### `asan-bt`
Displays AddressSanitizer-specific backtrace with full context.

**Usage:**
```gdb
(gdb) asan-bt
```

#### `ubsan-bt`
Shows UndefinedBehaviorSanitizer backtrace with context.

**Usage:**
```gdb
(gdb) ubsan-bt
```

### Batch Mode

#### `batch-analyze`
Fully automated crash analysis mode that:
1. Runs the program
2. Detects crashes
3. Performs triage
4. Generates reproduction kit
5. Creates core dump
6. Exits automatically

**Usage:**
```bash
# From command line
gdb -batch -x gdb_debug_script.gdb ./harness_binary -ex "batch-analyze"

# Or from within GDB
(gdb) batch-analyze
```

## Integration with AutoVulRepair Modules

### Module 5: Fuzz Execution

When fuzzing harnesses crash during execution:

```bash
# Navigate to the harness directory
cd scans/<scan_id>/harnesses/<harness_name>

# Debug the crash
gdb -x ../../../../gdb_debug_script.gdb ./harness_binary

# Load the crashing input
(gdb) run < crash-<hash>

# Analyze
(gdb) triage-crash
```

### Module 6: Crash Triage

Automated crash triage workflow:

```bash
# Batch analyze all crashes
for crash in crash-*; do
    gdb -batch -x gdb_debug_script.gdb ./harness_binary \
        -ex "run < $crash" \
        -ex "triage-crash" \
        -ex "quit"
done
```

### Module 7: Reproduction Kit Generator

Generate reproduction kits for all unique crashes:

```bash
# For each unique crash
gdb -batch -x gdb_debug_script.gdb ./harness_binary \
    -ex "run < crash_input" \
    -ex "generate-repro" \
    -ex "generate-core-file crash.core" \
    -ex "quit"
```

## Automatic Features

The script automatically:

1. **Enables logging** - All output saved to `gdb_debug_session.log`
2. **Sets breakpoints** on:
   - `LLVMFuzzerTestOneInput` - Main fuzzing entry point
   - `LLVMFuzzerInitialize` - Fuzzer initialization
   - Common memory functions (`malloc`, `free`, `memcpy`, etc.)
   - Dangerous string functions (`strcpy`, `strcat`, `sprintf`, `gets`)

3. **Catches signals**:
   - `SIGABRT` - Abort signal (sanitizer errors)
   - `SIGSEGV` - Segmentation fault
   - `SIGBUS` - Bus error
   - `SIGFPE` - Floating point exception
   - `SIGILL` - Illegal instruction

4. **Auto-displays** at each stop:
   - Register state
   - Stack trace
   - Code context
   - Disassembly

## Output Files

The script generates several output files:

| File | Description |
|------|-------------|
| `gdb_debug_session.log` | Complete GDB session log |
| `crash_triage_report.txt` | Detailed crash triage analysis |
| `reproduction_kit.txt` | Full reproduction information |
| `crash_core_dump` | Core dump file (if generated) |
| `.gdb_history` | Command history for future sessions |

## Advanced Usage

### Custom Breakpoints

```gdb
# Break on specific function
(gdb) break vulnerable_function

# Conditional breakpoint
(gdb) break malloc if $rdi > 1000000

# Break on memory access
(gdb) watch *0x601234
```

### Examining Fuzzing Input

```gdb
# Break at fuzzer entry
(gdb) break LLVMFuzzerTestOneInput

# Run and examine input
(gdb) run
(gdb) fuzz-input

# Examine specific bytes
(gdb) x/100xb $rdi

# Save input to file
(gdb) dump binary memory input_dump.bin $rdi $rdi+$rsi
```

### Debugging with AddressSanitizer

```bash
# Compile with ASan
clang++ -fsanitize=address -g harness.cpp -o harness

# Debug with GDB
gdb -x gdb_debug_script.gdb ./harness

# When ASan detects an error
(gdb) asan-bt
(gdb) crash-info
```

### Scripting Multiple Crashes

Create a bash script to analyze multiple crashes:

```bash
#!/bin/bash
# analyze_crashes.sh

for crash_file in crashes/crash-*; do
    echo "Analyzing $crash_file..."
    
    gdb -batch -x gdb_debug_script.gdb ./harness_binary <<EOF
run < $crash_file
triage-crash
generate-repro
quit
EOF
    
    # Rename output files
    mv crash_triage_report.txt "triage_$(basename $crash_file).txt"
    mv reproduction_kit.txt "repro_$(basename $crash_file).txt"
done
```

## Troubleshooting

### GDB Can't Find Source Files

```gdb
# Set source directory
(gdb) directory /path/to/source

# Or in the script, add:
# set substitute-path /old/path /new/path
```

### Symbols Not Loaded

Ensure binaries are compiled with debug symbols:
```bash
clang++ -g -O0 harness.cpp -o harness
```

### Script Not Loading

```bash
# Verify script path
gdb -x /full/path/to/gdb_debug_script.gdb ./binary

# Check for syntax errors
gdb -batch -x gdb_debug_script.gdb -ex "quit"
```

### Sanitizer Conflicts

If using sanitizers, disable GDB's internal checks:
```gdb
(gdb) set environment ASAN_OPTIONS=abort_on_error=1
(gdb) handle SIGSEGV nostop noprint pass
```

## Best Practices

1. **Always compile with debug symbols** (`-g` flag)
2. **Use sanitizers** during fuzzing (`-fsanitize=address,undefined`)
3. **Save crash inputs** for reproduction
4. **Document crash conditions** in triage reports
5. **Generate core dumps** for offline analysis
6. **Keep GDB updated** for best compatibility

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
- name: Analyze Crashes
  run: |
    for crash in crashes/*; do
      gdb -batch -x gdb_debug_script.gdb ./harness \
        -ex "run < $crash" \
        -ex "triage-crash" \
        -ex "quit"
    done
    
- name: Upload Triage Reports
  uses: actions/upload-artifact@v2
  with:
    name: crash-reports
    path: crash_triage_report.txt
```

## References

- [GDB Documentation](https://sourceware.org/gdb/documentation/)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [AutoVulRepair Architecture](./Architecture_Diagrams.md)

## Getting Help

For more information:
```gdb
(gdb) help-autovul          # Show all custom commands
(gdb) help <command>        # Detailed help for specific command
(gdb) help breakpoints      # GDB built-in help topics
```
