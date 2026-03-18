#!/bin/bash
# Batch Crash Analysis Script for AutoVulRepair
# This script analyzes multiple crash files using the GDB debug script

set -e

# Configuration
HARNESS_BINARY="${1:-./harness}"
CRASH_DIR="${2:-./crashes}"
OUTPUT_DIR="${3:-./crash_analysis}"
GDB_SCRIPT="$(dirname "$0")/gdb_debug_script.gdb"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}=== AutoVulRepair Batch Crash Analysis ===${NC}"
echo "Harness Binary: $HARNESS_BINARY"
echo "Crash Directory: $CRASH_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "GDB Script: $GDB_SCRIPT"
echo ""

# Check if harness binary exists
if [ ! -f "$HARNESS_BINARY" ]; then
    echo -e "${RED}Error: Harness binary not found: $HARNESS_BINARY${NC}"
    exit 1
fi

# Check if GDB script exists
if [ ! -f "$GDB_SCRIPT" ]; then
    echo -e "${RED}Error: GDB script not found: $GDB_SCRIPT${NC}"
    exit 1
fi

# Check if crash directory exists
if [ ! -d "$CRASH_DIR" ]; then
    echo -e "${RED}Error: Crash directory not found: $CRASH_DIR${NC}"
    exit 1
fi

# Count crash files
crash_count=$(find "$CRASH_DIR" -type f -name "crash-*" | wc -l)
if [ "$crash_count" -eq 0 ]; then
    echo -e "${YELLOW}Warning: No crash files found in $CRASH_DIR${NC}"
    exit 0
fi

echo -e "${GREEN}Found $crash_count crash files to analyze${NC}"
echo ""

# Analyze each crash
crash_num=0
for crash_file in "$CRASH_DIR"/crash-*; do
    crash_num=$((crash_num + 1))
    crash_basename=$(basename "$crash_file")
    
    echo -e "${YELLOW}[$crash_num/$crash_count] Analyzing $crash_basename...${NC}"
    
    # Create output subdirectory for this crash
    crash_output_dir="$OUTPUT_DIR/$crash_basename"
    mkdir -p "$crash_output_dir"
    
    # Run GDB analysis
    timeout 60s gdb -batch -x "$GDB_SCRIPT" "$HARNESS_BINARY" \
        -ex "run < $crash_file" \
        -ex "triage-crash" \
        -ex "generate-repro" \
        -ex "generate-core-file $crash_output_dir/core" \
        -ex "quit" \
        > "$crash_output_dir/gdb_output.txt" 2>&1 || true
    
    # Move generated files to crash-specific directory
    [ -f "gdb_debug_session.log" ] && mv gdb_debug_session.log "$crash_output_dir/"
    [ -f "crash_triage_report.txt" ] && mv crash_triage_report.txt "$crash_output_dir/"
    [ -f "reproduction_kit.txt" ] && mv reproduction_kit.txt "$crash_output_dir/"
    
    # Copy the crash input
    cp "$crash_file" "$crash_output_dir/crash_input"
    
    # Extract crash type from triage report
    if [ -f "$crash_output_dir/crash_triage_report.txt" ]; then
        crash_type=$(grep -i "signal" "$crash_output_dir/crash_triage_report.txt" | head -n 1 || echo "Unknown")
        echo -e "${GREEN}  Crash Type: $crash_type${NC}"
    fi
    
    echo -e "${GREEN}  Output saved to: $crash_output_dir${NC}"
    echo ""
done

# Generate summary report
echo -e "${GREEN}=== Generating Summary Report ===${NC}"

summary_file="$OUTPUT_DIR/SUMMARY.md"
cat > "$summary_file" << EOF
# Crash Analysis Summary

**Analysis Date:** $(date)
**Harness Binary:** $HARNESS_BINARY
**Total Crashes Analyzed:** $crash_count

## Crash Details

EOF

# Analyze each crash report
for crash_dir in "$OUTPUT_DIR"/crash-*; do
    if [ -d "$crash_dir" ]; then
        crash_name=$(basename "$crash_dir")
        
        echo "### $crash_name" >> "$summary_file"
        echo "" >> "$summary_file"
        
        # Extract key information from triage report
        if [ -f "$crash_dir/crash_triage_report.txt" ]; then
            echo '```' >> "$summary_file"
            grep -A 5 "Signal Information" "$crash_dir/crash_triage_report.txt" >> "$summary_file" || true
            echo '```' >> "$summary_file"
            echo "" >> "$summary_file"
            
            # Extract backtrace
            echo "**Backtrace:**" >> "$summary_file"
            echo '```' >> "$summary_file"
            grep -A 10 "STACK TRACE" "$crash_dir/crash_triage_report.txt" >> "$summary_file" || true
            echo '```' >> "$summary_file"
            echo "" >> "$summary_file"
        fi
        
        echo "**Files:**" >> "$summary_file"
        echo "- [Full Triage Report](./$crash_name/crash_triage_report.txt)" >> "$summary_file"
        echo "- [Reproduction Kit](./$crash_name/reproduction_kit.txt)" >> "$summary_file"
        echo "- [GDB Session Log](./$crash_name/gdb_debug_session.log)" >> "$summary_file"
        echo "- [Core Dump](./$crash_name/core)" >> "$summary_file"
        echo "- [Crash Input](./$crash_name/crash_input)" >> "$summary_file"
        echo "" >> "$summary_file"
        echo "---" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
done

# Add statistics
echo "## Statistics" >> "$summary_file"
echo "" >> "$summary_file"
echo "| Metric | Value |" >> "$summary_file"
echo "|--------|-------|" >> "$summary_file"
echo "| Total Crashes | $crash_count |" >> "$summary_file"

# Count unique crash types
unique_crashes=$(grep -h "signal" "$OUTPUT_DIR"/crash-*/crash_triage_report.txt 2>/dev/null | sort -u | wc -l || echo "0")
echo "| Unique Crash Types | $unique_crashes |" >> "$summary_file"

echo "" >> "$summary_file"
echo "## Next Steps" >> "$summary_file"
echo "" >> "$summary_file"
echo "1. Review each crash triage report for exploitability" >> "$summary_file"
echo "2. Prioritize crashes based on severity and uniqueness" >> "$summary_file"
echo "3. Create bug reports with reproduction kits" >> "$summary_file"
echo "4. Verify fixes with saved crash inputs" >> "$summary_file"

echo -e "${GREEN}Summary report generated: $summary_file${NC}"
echo ""
echo -e "${GREEN}=== Analysis Complete ===${NC}"
echo -e "${GREEN}Results saved to: $OUTPUT_DIR${NC}"
echo ""
echo "To view the summary:"
echo "  cat $summary_file"
echo ""
echo "To debug a specific crash interactively:"
echo "  gdb -x $GDB_SCRIPT $HARNESS_BINARY"
echo "  (gdb) run < $CRASH_DIR/crash-<hash>"
