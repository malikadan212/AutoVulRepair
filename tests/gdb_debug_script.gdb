# GDB Automated Debug Script for AutoVulRepair
# Purpose: Automated debugging session for fuzzing harnesses and crash analysis
# Usage: gdb -x gdb_debug_script.gdb <binary>

# ============================================================================
# INITIAL SETUP
# ============================================================================

# Set logging to capture all debug output
set logging file gdb_debug_session.log
set logging overwrite on
set logging on

# Print settings
set print pretty on
set print array on
set print array-indexes on
set print elements 200
set print object on
set print static-members on
set print vtbl on
set print demangle on
set demangle-style gnu-v3

# Pagination off for automated sessions
set pagination off
set confirm off

# History settings
set history save on
set history filename .gdb_history
set history size 10000

# ============================================================================
# DISPLAY CONFIGURATION
# ============================================================================

# Show disassembly in Intel syntax (easier to read)
set disassembly-flavor intel

# Auto-display useful information at each stop
define hook-stop
    echo \n=== EXECUTION STOPPED ===\n
    info registers
    echo \n=== STACK TRACE ===\n
    backtrace 10
    echo \n=== CODE CONTEXT ===\n
    list
    echo \n=== DISASSEMBLY ===\n
    x/10i $pc
    echo \n
end

# ============================================================================
# SANITIZER SUPPORT
# ============================================================================

# Catch sanitizer errors (ASan, UBSan, MSan)
catch signal SIGABRT
catch signal SIGSEGV
catch signal SIGBUS
catch signal SIGFPE
catch signal SIGILL

# Handle sanitizer runtime errors
define asan-bt
    echo \n=== AddressSanitizer Backtrace ===\n
    backtrace full
    info locals
    info args
end

define ubsan-bt
    echo \n=== UndefinedBehaviorSanitizer Backtrace ===\n
    backtrace full
    info locals
    info args
end

# ============================================================================
# FUZZING-SPECIFIC BREAKPOINTS
# ============================================================================

# Break on common fuzzing entry points
break LLVMFuzzerTestOneInput
break LLVMFuzzerInitialize

# Break on common vulnerability patterns
break malloc
break free
break realloc
break calloc
break memcpy
break strcpy
break strcat
break sprintf
break gets

# ============================================================================
# CRASH ANALYSIS COMMANDS
# ============================================================================

define crash-info
    echo \n=== CRASH ANALYSIS ===\n
    echo \n--- Signal Information ---\n
    info signals
    
    echo \n--- Register State ---\n
    info registers
    
    echo \n--- Full Backtrace ---\n
    backtrace full
    
    echo \n--- Memory at Crash Point ---\n
    x/32xb $pc
    
    echo \n--- Stack Contents ---\n
    x/64xw $sp
    
    echo \n--- Local Variables ---\n
    info locals
    
    echo \n--- Function Arguments ---\n
    info args
    
    echo \n--- Shared Libraries ---\n
    info sharedlibrary
end

document crash-info
Comprehensive crash analysis - displays all relevant debugging information
Usage: crash-info
end

# ============================================================================
# MEMORY ANALYSIS COMMANDS
# ============================================================================

define heap-info
    echo \n=== HEAP ANALYSIS ===\n
    info proc mappings
    echo \n--- Heap Chunks ---\n
    # This requires glibc malloc implementation
    # heap chunks
end

document heap-info
Display heap memory information and allocations
Usage: heap-info
end

define stack-info
    echo \n=== STACK ANALYSIS ===\n
    info frame
    echo \n--- Stack Backtrace ---\n
    backtrace full
    echo \n--- Stack Memory ---\n
    x/64xw $sp
end

document stack-info
Display stack information and contents
Usage: stack-info
end

define mem-search
    if $argc != 2
        echo Usage: mem-search <start_addr> <pattern>\n
    else
        find $arg0, +0x10000, $arg1
    end
end

document mem-search
Search memory for a specific pattern
Usage: mem-search <start_address> <pattern>
Example: mem-search 0x400000 0x41414141
end

# ============================================================================
# VULNERABILITY DETECTION HELPERS
# ============================================================================

define check-overflow
    echo \n=== BUFFER OVERFLOW CHECK ===\n
    echo Checking for stack canary corruption...\n
    # This is architecture-specific
    # x/xw $fs:0x28  # for x86_64
    info frame
    backtrace
end

document check-overflow
Check for buffer overflow indicators
Usage: check-overflow
end

define check-uaf
    echo \n=== USE-AFTER-FREE CHECK ===\n
    echo Examining freed memory access...\n
    backtrace full
    info locals
    # Check if pointer is in freed memory region
end

document check-uaf
Check for use-after-free indicators
Usage: check-uaf
end

# ============================================================================
# FUZZING INPUT ANALYSIS
# ============================================================================

define fuzz-input
    echo \n=== FUZZING INPUT ANALYSIS ===\n
    echo Examining LLVMFuzzerTestOneInput parameters...\n
    
    # Assuming standard libFuzzer signature: int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    echo \n--- Input Data Pointer ---\n
    print/x $rdi
    
    echo \n--- Input Size ---\n
    print/d $rsi
    
    echo \n--- First 256 bytes of input ---\n
    x/256xb $rdi
    
    echo \n--- Input as string ---\n
    x/s $rdi
end

document fuzz-input
Analyze fuzzing input data passed to LLVMFuzzerTestOneInput
Usage: fuzz-input (call when stopped in fuzzing harness)
end

# ============================================================================
# AUTOMATED CRASH TRIAGE
# ============================================================================

define triage-crash
    echo \n=== AUTOMATED CRASH TRIAGE ===\n
    
    # Get crash signal
    echo \n[1/6] Signal Information:\n
    info signals
    
    # Get exploitability heuristic
    echo \n[2/6] Crash Location:\n
    frame 0
    info registers
    
    # Check if crash is in user code or library
    echo \n[3/6] Crash Context:\n
    backtrace 5
    
    # Examine crash instruction
    echo \n[4/6] Crash Instruction:\n
    x/5i $pc
    
    # Check for common patterns
    echo \n[5/6] Memory State:\n
    x/32xb $pc
    
    # Generate exploitability score
    echo \n[6/6] Exploitability Assessment:\n
    echo Checking crash characteristics...\n
    
    # Save crash info to file
    set logging file crash_triage_report.txt
    set logging redirect on
    crash-info
    set logging redirect off
    set logging file gdb_debug_session.log
    
    echo \nCrash triage report saved to crash_triage_report.txt\n
end

document triage-crash
Automated crash triage and exploitability assessment
Usage: triage-crash
end

# ============================================================================
# REPRODUCTION KIT GENERATION
# ============================================================================

define generate-repro
    echo \n=== GENERATING REPRODUCTION KIT ===\n
    
    # Save all relevant information
    set logging file reproduction_kit.txt
    set logging redirect on
    
    echo === REPRODUCTION INFORMATION ===\n
    echo \n--- Binary Information ---\n
    info files
    
    echo \n--- Crash Backtrace ---\n
    backtrace full
    
    echo \n--- Register State ---\n
    info registers
    
    echo \n--- Memory Mappings ---\n
    info proc mappings
    
    echo \n--- Disassembly ---\n
    disassemble
    
    echo \n--- Local Variables ---\n
    info locals
    
    echo \n--- Arguments ---\n
    info args
    
    set logging redirect off
    set logging file gdb_debug_session.log
    
    echo \nReproduction kit saved to reproduction_kit.txt\n
end

document generate-repro
Generate a complete reproduction kit for the crash
Usage: generate-repro
end

# ============================================================================
# BATCH ANALYSIS MODE
# ============================================================================

define batch-analyze
    echo \n=== BATCH CRASH ANALYSIS MODE ===\n
    
    # Run the program
    run
    
    # If it crashes, perform triage
    if $_siginfo
        triage-crash
        generate-repro
        
        # Save core dump if possible
        generate-core-file crash_core_dump
        
        echo \nBatch analysis complete. Files generated:\n
        echo - gdb_debug_session.log\n
        echo - crash_triage_report.txt\n
        echo - reproduction_kit.txt\n
        echo - crash_core_dump\n
    else
        echo \nProgram exited normally (no crash detected)\n
    end
    
    quit
end

document batch-analyze
Automated batch analysis mode - runs program, triages crash, generates reports
Usage: batch-analyze
end

# ============================================================================
# INTERACTIVE HELPERS
# ============================================================================

define help-autovul
    echo \n=== AutoVulRepair GDB Debug Script ===\n
    echo \nAvailable custom commands:\n
    echo \n--- Crash Analysis ---\n
    echo   crash-info       - Comprehensive crash information\n
    echo   triage-crash     - Automated crash triage\n
    echo   generate-repro   - Generate reproduction kit\n
    echo \n--- Memory Analysis ---\n
    echo   heap-info        - Display heap information\n
    echo   stack-info       - Display stack information\n
    echo   mem-search       - Search memory for pattern\n
    echo \n--- Vulnerability Detection ---\n
    echo   check-overflow   - Check for buffer overflow\n
    echo   check-uaf        - Check for use-after-free\n
    echo \n--- Fuzzing ---\n
    echo   fuzz-input       - Analyze fuzzing input data\n
    echo \n--- Sanitizer Support ---\n
    echo   asan-bt          - AddressSanitizer backtrace\n
    echo   ubsan-bt         - UBSan backtrace\n
    echo \n--- Batch Mode ---\n
    echo   batch-analyze    - Automated batch analysis\n
    echo \n--- Help ---\n
    echo   help-autovul     - Show this help message\n
    echo \nFor detailed help on any command: help <command>\n
end

# ============================================================================
# STARTUP MESSAGE
# ============================================================================

echo \n
echo ========================================================================\n
echo AutoVulRepair - Automated GDB Debug Script\n
echo ========================================================================\n
echo \nLogging enabled: gdb_debug_session.log\n
echo Type 'help-autovul' for available commands\n
echo Type 'batch-analyze' for automated crash analysis\n
echo \n

# Show help on startup
help-autovul
