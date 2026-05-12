"""
Self-contained Stage 1 patch test.
Creates a synthetic vulnerable C++ source, runs it through the Stage 1 engine,
and prints before/after for every patch generated.
"""
import sys
import os
import types

# Stub out heavy AI deps that Stage 1 doesn't need
for _m in ['langgraph', 'langgraph.graph', 'langchain', 'langchain_core',
           'langchain_openai', 'openai', 'anthropic']:
    if _m not in sys.modules:
        sys.modules[_m] = types.ModuleType(_m)
_lg = sys.modules['langgraph.graph']
_lg.StateGraph = object
_lg.END = 'END'

sys.path.insert(0, os.path.dirname(__file__))
from src.repair.stage1.repair_engine import Stage1RepairEngine

# ---------------------------------------------------------------------------
# Synthetic vulnerable source — line numbers are exact, no inline comments
# ---------------------------------------------------------------------------
SOURCE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_null_ptr_strcpy() {
    char* null_ptr = nullptr;
    strcpy(null_ptr, "This will crash");
    printf("done\\n");
}

void test_conditional_null(bool allocate) {
    char* conditional_ptr = nullptr;
    if (allocate) {
        conditional_ptr = (char*)malloc(100);
    }
    strcpy(conditional_ptr, "Potential null dereference");
    printf("Data: %s\\n", conditional_ptr);
    if (conditional_ptr) free(conditional_ptr);
}

struct TestStruct { int value; char name[50]; };
void test_struct_null() {
    TestStruct* struct_ptr = nullptr;
    struct_ptr->value = 42;
    strcpy(struct_ptr->name, "test");
}

void test_array_bounds() {
    int array[10];
    for (int i = 0; i <= 15; i++) {
        array[i] = i * i;
    }
}

void test_uninit() {
    int uninitialized_int;
    char* uninitialized_ptr;
    int result;
    int uninitialized_size;
    printf("%d\\n", uninitialized_int);
}

void test_sprintf() {
    char buffer[10];
    int number = 123456789;
    sprintf(buffer, "Number: %d and more text", number);
}

void test_gets() {
    char buffer[50];
    gets(buffer);
}
"""

# ---------------------------------------------------------------------------
# Compute exact line numbers from the source above
# ---------------------------------------------------------------------------
def line_of(source, snippet):
    for i, l in enumerate(source.splitlines(), 1):
        if snippet in l:
            return i
    raise ValueError(f"Snippet not found: {snippet!r}")

L_null_strcpy      = line_of(SOURCE, 'strcpy(null_ptr')
L_cond_strcpy      = line_of(SOURCE, 'strcpy(conditional_ptr')
L_cond_printf      = line_of(SOURCE, 'printf("Data:')
L_struct_value     = line_of(SOURCE, 'struct_ptr->value')
L_struct_strcpy    = line_of(SOURCE, 'strcpy(struct_ptr->name')
L_array_access     = line_of(SOURCE, 'array[i] = i * i')
L_uninit_int       = line_of(SOURCE, 'int uninitialized_int;')
L_uninit_ptr       = line_of(SOURCE, 'char* uninitialized_ptr;')
L_uninit_result    = line_of(SOURCE, 'int result;')
L_uninit_size      = line_of(SOURCE, 'int uninitialized_size;')
L_sprintf          = line_of(SOURCE, 'sprintf(buffer')
L_gets             = line_of(SOURCE, 'gets(buffer)')

# ---------------------------------------------------------------------------
# Vulnerability list
# ---------------------------------------------------------------------------
VULNS = [
    {'id': 'vuln-001', 'finding_id': 'vuln-001', 'cwe': '476', 'rule_id': 'nullPointer',
     'file': 'test.cpp', 'line': L_null_strcpy,
     'message': 'Null pointer dereference: null_ptr', 'symbol': 'null_ptr'},

    {'id': 'vuln-002', 'finding_id': 'vuln-002', 'cwe': '476', 'rule_id': 'nullPointer',
     'file': 'test.cpp', 'line': L_cond_strcpy,
     'message': 'Possible null pointer dereference: conditional_ptr', 'symbol': 'conditional_ptr'},

    {'id': 'vuln-003', 'finding_id': 'vuln-003', 'cwe': '476', 'rule_id': 'nullPointer',
     'file': 'test.cpp', 'line': L_cond_printf,
     'message': 'Possible null pointer dereference: conditional_ptr', 'symbol': 'conditional_ptr'},

    {'id': 'vuln-004', 'finding_id': 'vuln-004', 'cwe': '476', 'rule_id': 'nullPointer',
     'file': 'test.cpp', 'line': L_struct_value,
     'message': 'Null pointer dereference: struct_ptr', 'symbol': 'struct_ptr'},

    {'id': 'vuln-005', 'finding_id': 'vuln-005', 'cwe': '476', 'rule_id': 'nullPointer',
     'file': 'test.cpp', 'line': L_struct_strcpy,
     'message': 'Null pointer dereference: struct_ptr', 'symbol': 'struct_ptr'},

    {'id': 'vuln-006', 'finding_id': 'vuln-006', 'cwe': '788', 'rule_id': 'arrayIndexOutOfBounds',
     'file': 'test.cpp', 'line': L_array_access,
     'message': "Array 'array[10]' accessed at index 15, which is out of bounds.", 'symbol': 'array'},

    {'id': 'vuln-007', 'finding_id': 'vuln-007', 'cwe': '457', 'rule_id': 'uninitvar',
     'file': 'test.cpp', 'line': L_uninit_int,
     'message': 'Uninitialized variable: uninitialized_int', 'symbol': 'uninitialized_int'},

    {'id': 'vuln-008', 'finding_id': 'vuln-008', 'cwe': '457', 'rule_id': 'uninitvar',
     'file': 'test.cpp', 'line': L_uninit_ptr,
     'message': 'Uninitialized variable: uninitialized_ptr', 'symbol': 'uninitialized_ptr'},

    {'id': 'vuln-009', 'finding_id': 'vuln-009', 'cwe': '457', 'rule_id': 'uninitvar',
     'file': 'test.cpp', 'line': L_uninit_result,
     'message': 'Uninitialized variable: result', 'symbol': 'result'},

    {'id': 'vuln-010', 'finding_id': 'vuln-010', 'cwe': '457', 'rule_id': 'uninitvar',
     'file': 'test.cpp', 'line': L_uninit_size,
     'message': 'Uninitialized variable: uninitialized_size', 'symbol': 'uninitialized_size'},

    {'id': 'vuln-011', 'finding_id': 'vuln-011', 'cwe': '120', 'rule_id': 'bufferAccessOutOfBounds',
     'file': 'test.cpp', 'line': L_sprintf,
     'message': 'Buffer is accessed out of bounds: buffer', 'symbol': 'buffer'},

    {'id': 'vuln-012', 'finding_id': 'vuln-012', 'cwe': '477', 'rule_id': 'getsCalled',
     'file': 'test.cpp', 'line': L_gets,
     'message': "Obsolete function 'gets' called.", 'symbol': 'buffer'},
]

# ---------------------------------------------------------------------------
# Run the engine
# ---------------------------------------------------------------------------
def run():
    engine = Stage1RepairEngine()
    source_files = {'test.cpp': SOURCE}

    print("=" * 70)
    print("STAGE 1 PATCH TEST — AutoVulRepair")
    print("=" * 70)
    print(f"Vulnerabilities submitted : {len(VULNS)}")
    print()

    results = engine.batch_repair(VULNS, source_files)
    patches = results['patches']
    stats   = results['stats']

    print(f"Patches generated : {stats['patches_generated']}")
    print(f"Patches failed    : {stats['patches_failed']}")
    print(f"By category       : {stats['by_category']}")
    print()
    print("=" * 70)

    patched_ids = {p.get('vulnerability_id') for p in patches}

    for p in patches:
        vuln_id  = p.get('vulnerability_id', '?')
        line     = p.get('line', '?')
        category = p.get('category', '?')
        conf     = p.get('confidence', 0)
        original = p.get('original', '').strip()
        repaired = p.get('repaired', '').strip()

        print(f"\n[{vuln_id}]  line {line}  |  {category}  |  confidence {conf:.0%}")
        print(f"  BEFORE: {original}")
        for i, rline in enumerate(repaired.splitlines()):
            label = "  AFTER :" if i == 0 else "         "
            print(f"{label} {rline}")
        changed = repaired and repaired != original
        print(f"  STATUS: {'PATCHED' if changed else 'NO CHANGE'}")

    # Show which vulns got no patch
    failed = [v for v in VULNS if v['finding_id'] not in patched_ids]
    if failed:
        print(f"\n--- {len(failed)} vulnerabilities NOT patched ---")
        for v in failed:
            print(f"  [{v['id']}] line {v['line']} — {v['message'][:60]}")

    print()
    print("=" * 70)
    print(f"RESULT: {len(patches)}/{len(VULNS)} vulnerabilities patched")
    print("=" * 70)

if __name__ == '__main__':
    run()
