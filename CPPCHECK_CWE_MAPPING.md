# Cppcheck Vulnerability Types and CWE Mapping

This document provides a comprehensive reference of all vulnerability types that Cppcheck can detect, organized by category with their corresponding CWE (Common Weakness Enumeration) identifiers.

## 🔴 Critical Security Vulnerabilities

### Memory Safety Issues

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `bufferAccessOutOfBounds` | **CWE-119** | Critical | Buffer overflow in functions like sprintf, strcpy |
| `arrayIndexOutOfBounds` | **CWE-823** | Critical | Array index out of bounds (can be CWE-125 for read, CWE-787 for write) |
| `possibleBufferAccessOutOfBounds` | **CWE-120** | High | Potential buffer overflow in strcpy, strcat |
| `outOfBounds` | **CWE-805** | High | Out of bounds access in readlink, snprintf |
| `pointerOutOfBounds` | **CWE-823** | High | Pointer arithmetic out of bounds |
| `negativeIndex` | **CWE-786** | High | Negative array index (CWE-127 for read, CWE-124 for write) |
| `possibleReadlinkBufferOverrun` | **CWE-805** | High | Buffer overrun in readlink() |
| `strncatUsage` | **CWE-805** | Medium | Incorrect strncat usage |
| `terminateStrncpy` | **CWE-170** | Medium | strncpy doesn't null-terminate |
| `bufferNotZeroTerminated` | **CWE-170** | Medium | Buffer not zero-terminated |
| `insecureCmdLineArgs` | **CWE-120** | High | Insecure command line argument handling |
| `arrayIndexThenCheck` | **CWE-129** | Medium | Array index used before bounds check |

### Memory Leaks and Use-After-Free

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `memleak` | **CWE-401** | High | Memory leak detected |
| `memleakOnRealloc` | **CWE-401** | High | Memory leak on realloc failure |
| `resourceLeak` | **CWE-404** | High | Resource leak (file descriptors, sockets, etc.) |
| `deallocDealloc` | **CWE-415** | Critical | Double free |
| `deallocuse` | **CWE-416** | Critical | Use after free |
| `mismatchAllocDealloc` | **CWE-762** | High | Mismatched allocation/deallocation (malloc/delete, new/free) |
| `autovarInvalidDeallocation` | **CWE-590** | High | Invalid deallocation of auto variable |
| `unusedAllocatedMemory` | **CWE-401** | Medium | Allocated memory never used |
| `publicAllocationError` | **CWE-401** | Medium | Public allocation error |
| `leakNoVarFunctionCall` | **CWE-401** | Medium | Memory leak in function call |

### Null Pointer Dereference

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `nullPointer` | **CWE-476** | High | Null pointer dereference |

### Integer Overflow/Underflow

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `integerOverflow` | **CWE-190** | High | Integer overflow |
| `udivError` | **CWE-195** | Medium | Unsigned division error |
| `zerodiv` | **CWE-369** | High | Division by zero |

### Uninitialized Variables

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `uninitvar` | **CWE-456** | High | Uninitialized variable used |
| `uninitdata` | **CWE-456** | High | Uninitialized data |
| `uninitstring` | **CWE-170** | Medium | Uninitialized string |
| `noConstructor` | **CWE-456** | Medium | Class has no constructor |

### Auto Variable Issues

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `returnAddressOfAutoVariable` | **CWE-562** | Critical | Returning address of auto variable |
| `returnLocalVariable` | **CWE-562** | Critical | Returning local variable |
| `autoVariables` | **CWE-562** | Critical | Auto variable issues |
| `returnAddressOfFunctionParameter` | **CWE-562** | Critical | Returning address of function parameter |
| `returnReference` | **CWE-562** | Critical | Returning reference to local variable |
| `returnTempReference` | **CWE-562** | Critical | Returning temporary reference |
| `returnAutocstr` | **CWE-562** | Critical | Returning auto c-string |
| `returnTempPointer` | **CWE-562** | Critical | Returning temporary pointer |

## 🟡 Medium Security Issues

### Input Validation

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `invalidscanf` | **CWE-120** | Medium | Invalid scanf usage |
| `wrongPrintfScanfArgs` | **CWE-686** | Medium | Wrong printf/scanf arguments |
| `dangerousUsageStrtol` | **CWE-676** | Medium | Dangerous strtol usage |

### Type Confusion

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `AssignmentAddressToInteger` | **CWE-843** | Medium | Assigning address to integer |
| `AssignmentIntegerToAddress` | **CWE-843** | Medium | Assigning integer to address |
| `cstyleCast` | **CWE-704** | Low | C-style cast used |
| `assignBoolToPointer` | **CWE-587** | Medium | Assigning bool to pointer |

### Size Calculation Errors

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `mismatchSize` | **CWE-131** | High | Mismatched size in allocation |
| `sizeofwithnumericparameter` | **CWE-131** | Medium | sizeof with numeric parameter |
| `sizeofwithsilentarraypointer` | **CWE-131** | Medium | sizeof with array pointer |
| `sizeofsizeof` | **CWE-131** | Medium | sizeof(sizeof(...)) |
| `sizeofCalculation` | **CWE-131** | Medium | sizeof in calculation |
| `sizeArgumentAsChar` | **CWE-805** | Medium | Size argument as char |

### Logic Errors

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `assignIfError` | **CWE-561** | Low | Assignment in if condition |
| `comparisonError` | **CWE-561** | Low | Comparison error |
| `multiCondition` | **CWE-561** | Low | Multiple conditions match |
| `incorrectLogicOperator` | **CWE-561** | Medium | Incorrect logic operator |
| `secondAlwaysTrueFalseWhenFirstTrue` | **CWE-561** | Medium | Second condition always true/false |
| `staticStringCompare` | **CWE-561** | Low | Static string comparison |
| `duplicateIf` | **CWE-398** | Low | Duplicate if condition |
| `duplicateExpression` | **CWE-398** | Low | Duplicate expression |
| `duplicateBreak` | **CWE-398** | Low | Duplicate break statement |

### Boolean Logic Issues

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `comparisonOfBoolWithInt` | **CWE-670** | Medium | Comparing bool with int |
| `incorrectStringBooleanError` | **CWE-571** | Medium | Incorrect string boolean |
| `stringCompare` | **CWE-571** | Medium | String comparison issue |
| `unsignedPositive` | **CWE-571** | Low | Unsigned always positive |

### Switch Statement Issues

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `switchCaseFallThrough` | **CWE-484** | Medium | Switch case fall through |
| `redundantAssignInSwitch` | **CWE-484** | Low | Redundant assignment in switch |
| `redundantStrcpyInSwitch` | **CWE-484** | Low | Redundant strcpy in switch |

### Exception Handling

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `catchExceptionByValue` | **CWE-253** | Low | Catching exception by value |

### Thread Safety

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `nonreentrantFunctions` | **CWE-663** | Medium | Non-reentrant function usage |

### Deprecated Functions

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `obsoleteFunctions` | **CWE-477** | Low | Obsolete function usage (gets, etc.) |

### String Handling

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `incorrectStringCompare` | **CWE-687** | Medium | Incorrect string comparison |
| `strPlusChar` | **CWE-468** | Medium | String + char issue |

### Character Handling

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `charArrayIndex` | **CWE-194** | Medium | Char used as array index |
| `charBitOp` | **CWE-194** | Medium | Char used in bit operation |

### Math Operations

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `wrongmathcall` | **CWE-687** | Medium | Wrong math function call |
| `clarifyCalculation` | **CWE-783** | Low | Unclear calculation precedence |
| `clarifyCondition` | **CWE-783** | Low | Unclear condition precedence |

### Resource Management

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `fflushOnInputStream` | **CWE-665** | Medium | fflush on input stream |
| `memsetZeroBytes` | **CWE-687** | Medium | memset with zero bytes |
| `memsetClass` | **CWE-686** | Medium | memset on class with virtual functions |

### API Misuse

| Cppcheck Error ID | CWE | Severity | Description |
|------------------|-----|----------|-------------|
| `boostForeachError` | **CWE-573** | Medium | Boost foreach API violation |
| `passedByValue` | **CWE-686** | Low | Large object passed by value |
| `unusedScopedObject` | **CWE-826** | Medium | Unused scoped object |

## 📊 Summary Statistics

### By Severity
- **Critical**: 11 vulnerability types (Use-after-free, Double free, Return local variable, etc.)
- **High**: 15 vulnerability types (Buffer overflow, Memory leak, Null pointer, etc.)
- **Medium**: 35+ vulnerability types (Input validation, Type confusion, Logic errors, etc.)
- **Low**: 15+ vulnerability types (Code quality, Style issues, etc.)

### Most Common CWE Categories
1. **CWE-119/120/787/823**: Buffer overflow variants (8 checks)
2. **CWE-401/404/415/416**: Memory management (8 checks)
3. **CWE-456/562**: Uninitialized/Auto variables (11 checks)
4. **CWE-131**: Buffer size calculation (6 checks)
5. **CWE-561/571**: Logic errors (7 checks)

## 🔍 How CWE Extraction Works

When Cppcheck runs, it outputs results in XML format with CWE attributes:

```xml
<error id="bufferAccessOutOfBounds" severity="error" msg="Buffer overflow" cwe="119">
    <location file="test.c" line="10"/>
</error>
```

Our implementation extracts the `cwe` attribute and formats it as `CWE-XXX` for consistency.

## 📝 Notes

1. **CWE Availability**: Not all Cppcheck error IDs have CWE mappings. Some style/quality checks don't map to security weaknesses.

2. **Version Differences**: CWE mappings may vary between Cppcheck versions. This mapping is based on Cppcheck 2.x series.

3. **Specificity**: Some generic error IDs (like `arrayIndexOutOfBounds`) can map to more specific CWEs if read/write direction is detected:
   - Read: CWE-125 (Out-of-bounds Read)
   - Write: CWE-787 (Out-of-bounds Write)

4. **Stack vs Heap**: Some buffer issues can be further classified:
   - Stack: CWE-121 (Stack-based Buffer Overflow)
   - Heap: CWE-122 (Heap-based Buffer Overflow)

## 🔗 References

- [Cppcheck Official Documentation](https://cppcheck.sourceforge.io/)
- [CWE Database](https://cwe.mitre.org/)
- [Red Hat CWE Mapping](https://people.redhat.com/sgrubb/swa/cwe/cppcheck-mapping.txt)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

## 🚀 Usage in AutoVulRepair

When a scan is performed:

1. Cppcheck runs and generates XML output
2. Our parser extracts vulnerabilities with CWE IDs
3. Each vulnerability is enriched with:
   - Severity level (critical/high/medium/low)
   - Priority score (0-10)
   - CWE classification
   - File location and line number
4. AI repair system uses CWE context to generate appropriate fixes

Example output:
```json
{
  "id": "cppcheck_bufferAccessOutOfBounds_42",
  "severity": "high",
  "description": "Buffer overflow when copying user input",
  "file": "src/main.c",
  "line": 42,
  "tool": "cppcheck",
  "rule_id": "bufferAccessOutOfBounds",
  "cwe": "CWE-119",
  "priority_score": 9.0
}
```
