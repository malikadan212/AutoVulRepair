# Stage 1 Repair Engine — Comprehensive Test Results

**Test Run Summary:** 240 tests | ✅ 240 passed | ❌ 0 failed | ⏱️ 2.33s

---

## 1. Null Pointer Dereference (CWE-476) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | strcpy to ptr declared as nullptr → allocates memory | ✅ PASS |
| 2 | Conditional ptr + strcpy → guard | ✅ PASS |
| 3 | Conditional ptr + printf → early return guard | ✅ PASS |
| 4 | Struct member allocation | ✅ PASS |
| 5 | Struct member strcpy → early return guard | ✅ PASS |
| 6 | ptr->field int assignment | ✅ PASS |
| 7 | Cppcheck: reported line is declaration, deref 3 lines later | ✅ PASS |
| 8 | Cppcheck: deref 10+ lines later | ✅ PASS |
| 9 | Symbol extraction: "Null pointer dereference: my_ptr" | ✅ PASS |
| 10 | Symbol extraction: "Possible null pointer dereference: conditional_ptr" | ✅ PASS |
| 11 | Symbol extraction from declaration in message | ✅ PASS |
| 12 | NULL (not nullptr) macro declaration | ✅ PASS |
| 13 | Multiple null pointers — first one patched | ✅ PASS |
| 14 | Pointer used in function call | ✅ PASS |
| 15 | Idempotency: already has null check | ✅ PASS |
| 16 | Very long variable name | ✅ PASS |
| 17 | Underscore variable name | ✅ PASS |
| 18 | Global pointer dereference | ✅ PASS |
| 19 | Pointer with typedef type | ✅ PASS |
| 20 | Pointer in nested if block, deref 20 lines after decl | ✅ PASS |
| 21 | Forward scan stops at function end | ✅ PASS |
| 22 | Message with type keywords that should be skipped | ✅ PASS |
| 23 | Pointer to struct with arrow chain | ✅ PASS |
| 24 | Pointer reassigned to malloc before deref | ✅ PASS |
| 25 | No deref found in 60 lines → returns None | ✅ PASS |
| 26 | Pointer parameter (not local nullptr) — direct deref line | ✅ PASS |
| 27 | Member pointer: obj->subptr->field | ✅ PASS |
| 28 | Array pointer access where arr is null | ✅ PASS |
| 29 | Multiple deref lines — patches first one found | ✅ PASS |
| 30 | Line number out of range | ✅ PASS |

---

## 2. Uninitialized Variables (CWE-457) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | int uninit → = 0 | ✅ PASS |
| 2 | char* uninit → = NULL | ✅ PASS |
| 3 | float uninit → = 0.0f | ✅ PASS |
| 4 | double uninit → = 0.0 | ✅ PASS |
| 5 | size_t uninit → = 0 | ✅ PASS |
| 6 | int array uninit (limitation documented) | ✅ PASS |
| 7 | struct uninit → = {0} | ✅ PASS |
| 8 | long uninit → = 0 | ✅ PASS |
| 9 | unsigned int uninit → = 0 | ✅ PASS |
| 10 | Symbol from message "Uninitialized variable: my_var" | ✅ PASS |
| 11 | Symbol from message containing "variable my_var" | ✅ PASS |
| 12 | Symbol from single-quotes 'my_var' | ✅ PASS |
| 13 | Declaration line different from usage line (search backward) | ✅ PASS |
| 14 | Already initialized → returns None | ✅ PASS |
| 15 | Variable used 10 lines after declaration | ✅ PASS |
| 16 | Variable in nested block | ✅ PASS |
| 17 | short type | ✅ PASS |
| 18 | signed char type | ✅ PASS |
| 19 | Variable name with numbers | ✅ PASS |
| 20 | Very long variable name | ✅ PASS |
| 21 | Variable inside for-loop init | ✅ PASS |
| 22 | ssize_t type | ✅ PASS |
| 23 | int32_t type | ✅ PASS |
| 24 | Pointer type → NULL | ✅ PASS |
| 25 | Line out of range → returns None | ✅ PASS |
| 26 | Missing symbol and line number → None | ✅ PASS |
| 27 | original != repaired (basic sanity) | ✅ PASS |
| 28 | double pointer → NULL | ✅ PASS |
| 29 | patch returns diff string | ✅ PASS |
| 30 | patch confidence high | ✅ PASS |

---

## 3. Integer Overflow (CWE-190/191/197) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | int a + b → precondition guard | ✅ PASS |
| 2 | int a + constant | ✅ PASS |
| 3 | int a * b → multiplication guard | ✅ PASS |
| 4 | int a * positive constant | ✅ PASS |
| 5 | unsigned int a - b → underflow guard | ✅ PASS |
| 6 | signed int a - b → signed underflow guard | ✅ PASS |
| 7 | Left shift operation | ✅ PASS |
| 8 | Narrowing cast long to int | ✅ PASS |
| 9 | Narrowing cast int to char | ✅ PASS |
| 10 | Narrowing cast int to short | ✅ PASS |
| 11 | Signed integer overflow rule ID | ✅ PASS |
| 12 | Multiply var * negative constant | ✅ PASS |
| 13 | Square same variable | ✅ PASS |
| 14 | Multiply two different vars | ✅ PASS |
| 15 | Constant only → no repair | ✅ PASS |
| 16 | max_int + 1 | ✅ PASS |
| 17 | size * large constant | ✅ PASS |
| 18 | int32_t type | ✅ PASS |
| 19 | long long type | ✅ PASS |
| 20 | unsigned long type | ✅ PASS |
| 21 | Idempotency: already has check | ✅ PASS |
| 22 | Line out of range | ✅ PASS |
| 23 | Fixer generates abort | ✅ PASS |
| 24 | Fixer generates if-else | ✅ PASS |
| 25 | Shift by 32 bits | ✅ PASS |
| 26 | count * sizeof pattern | ✅ PASS |
| 27 | Fixer: original differs from repaired | ✅ PASS |
| 28 | Fixer confidence | ✅ PASS |
| 29 | Subtraction unsigned underflow | ✅ PASS |
| 30 | Add precondition mentions MAX | ✅ PASS |

---

## 4. Buffer Overflow (CWE-120/788) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | strcpy → strncpy | ✅ PASS |
| 2 | strcat → strncat | ✅ PASS |
| 3 | sprintf → snprintf | ✅ PASS |
| 4 | gets → fgets | ✅ PASS |
| 5 | memcpy boundary check | ✅ PASS |
| 6 | memset boundary check | ✅ PASS |
| 7 | Array index bounds check | ✅ PASS |
| 8 | Pointer arithmetic bounds check | ✅ PASS |
| 9 | strcpy struct member | ✅ PASS |
| 10 | sprintf no extra args | ✅ PASS |
| 11 | Comment line returns none | ✅ PASS |
| 12 | Empty line returns none | ✅ PASS |
| 13 | fgets already present | ✅ PASS |
| 14 | strcat long args | ✅ PASS |
| 15 | memcpy strlen size | ✅ PASS |
| 16 | vsprintf not in scanner | ✅ PASS |
| 17 | read syscall | ✅ PASS |
| 18 | fread boundary check | ✅ PASS |
| 19 | Scan strcpy status vulnerable | ✅ PASS |
| 20 | Scan strcpy api field | ✅ PASS |
| 21 | Fix strcpy original differs | ✅ PASS |
| 22 | Fix gets original differs | ✅ PASS |
| 23 | Fix strcat original differs | ✅ PASS |
| 24 | Fix sprintf original differs | ✅ PASS |
| 25 | strncpy scanned | ✅ PASS |
| 26 | Scan returns dest field | ✅ PASS |
| 27 | Line num in result | ✅ PASS |
| 28 | Patch has repaired key | ✅ PASS |
| 29 | False positive returns none | ✅ PASS |
| 30 | sprintf repaired is snprintf | ✅ PASS |

---

## 5. Format String (CWE-134) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | printf direct var | ✅ PASS |
| 2 | fprintf direct var | ✅ PASS |
| 3 | sprintf direct var | ✅ PASS |
| 4 | syslog direct var | ✅ PASS |
| 5 | printf argv | ✅ PASS |
| 6 | Already safe %s returns none | ✅ PASS |
| 7 | printf literal behavior | ✅ PASS |
| 8 | printf with format specifier returns none | ✅ PASS |
| 9 | err function | ✅ PASS |
| 10 | warn function | ✅ PASS |
| 11 | Complex ternary routes to stage2 | ✅ PASS |
| 12 | Dynamic format strcat routes to stage2 | ✅ PASS |
| 13 | printf local buf | ✅ PASS |
| 14 | fprintf stderr | ✅ PASS |
| 15 | vprintf | ✅ PASS |
| 16 | Line out of range | ✅ PASS |
| 17 | Missing line number | ✅ PASS |
| 18 | snprintf direct var | ✅ PASS |
| 19 | log function | ✅ PASS |
| 20 | logf function | ✅ PASS |
| 21 | error function | ✅ PASS |
| 22 | warnx function | ✅ PASS |
| 23 | errx function | ✅ PASS |
| 24 | Already safe with newline | ✅ PASS |
| 25 | Original differs from repaired | ✅ PASS |
| 26 | Confidence returned | ✅ PASS |
| 27 | Function field set | ✅ PASS |
| 28 | vsprintf direct var | ✅ PASS |
| 29 | syslog variable priority | ✅ PASS |
| 30 | Patch has diff | ✅ PASS |

---

## 6. Dangerous API (CWE-676) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | gets → fgets | ✅ PASS |
| 2 | strcat → strncat | ✅ PASS |
| 3 | strcpy → strncpy | ✅ PASS |
| 4 | sprintf → snprintf | ✅ PASS |
| 5 | vsprintf → vsnprintf | ✅ PASS |
| 6 | scanf unbounded | ✅ PASS |
| 7 | fscanf unbounded | ✅ PASS |
| 8 | gets different buffer | ✅ PASS |
| 9 | strcat spaces in args | ✅ PASS |
| 10 | strcpy expression source | ✅ PASS |
| 11 | sprintf multiple args | ✅ PASS |
| 12 | Non-dangerous api returns none | ✅ PASS |
| 13 | Line out of range | ✅ PASS |
| 14 | Missing line number | ✅ PASS |
| 15 | fgets already safe | ✅ PASS |
| 16 | Long arg expressions | ✅ PASS |
| 17 | strcpy dest with spaces | ✅ PASS |
| 18 | sprintf no extra args | ✅ PASS |
| 19 | scanf literal no %s | ✅ PASS |
| 20 | fscanf %d only | ✅ PASS |
| 21 | vsprintf complex valist | ✅ PASS |
| 22 | gets with trailing comment | ✅ PASS |
| 23 | api field set | ✅ PASS |
| 24 | confidence field set | ✅ PASS |
| 25 | diff field set | ✅ PASS |
| 26 | strncpy already safe | ✅ PASS |
| 27 | strncat already safe | ✅ PASS |
| 28 | snprintf already safe | ✅ PASS |
| 29 | vsnprintf already safe | ✅ PASS |
| 30 | Original differs from repaired | ✅ PASS |

---

## 7. MemFix (CWE-401/415/416) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | Simple malloc no free | ✅ PASS |
| 2 | calloc no free | ✅ PASS |
| 3 | Patch has cwe field | ✅ PASS |
| 4 | Double free CWE-415 | ✅ PASS |
| 5 | CWE-401 classification | ✅ PASS |
| 6 | CWE-415 classification | ✅ PASS |
| 7 | memleak cppcheck id | ✅ PASS |
| 8 | double free cppcheck id | ✅ PASS |
| 9 | Single malloc single path | ✅ PASS |
| 10 | No allocations returns patch | ✅ PASS |
| 11 | malloc with cast | ✅ PASS |
| 12 | patch_id present | ✅ PASS |
| 13 | method field | ✅ PASS |
| 14 | vulnerability_id in patch | ✅ PASS |
| 15 | Line out of range | ✅ PASS |
| 16 | malloc in if condition | ✅ PASS |
| 17 | malloc struct | ✅ PASS |
| 18 | calloc zero count | ✅ PASS |
| 19 | Multiple mallocs | ✅ PASS |
| 20 | confidence field | ✅ PASS |
| 21 | description field | ✅ PASS |
| 22 | file field | ✅ PASS |
| 23 | Double free simple fix | ✅ PASS |
| 24 | malloc size zero | ✅ PASS |
| 25 | Patch has original field | ✅ PASS |
| 26 | Patch has repaired field | ✅ PASS |
| 27 | malloc in loop | ✅ PASS |
| 28 | CWE-416 classification | ✅ PASS |
| 29 | malloc struct cast | ✅ PASS |
| 30 | Patch diff field present | ✅ PASS |

---

## 8. Use-After-Free CETS (CWE-416) — 30 Tests

| # | Test Case | Status |
|---|-----------|--------|
| 1 | malloc instrumented | ✅ PASS |
| 2 | free instrumented | ✅ PASS |
| 3 | deref_load instrumented | ✅ PASS |
| 4 | deref_store instrumented | ✅ PASS |
| 5 | ptr field basic deref | ✅ PASS |
| 6 | ptr derivation add | ✅ PASS |
| 7 | ptr derivation idx | ✅ PASS |
| 8 | address_of_local | ✅ PASS |
| 9 | cast_int_to_ptr | ✅ PASS |
| 10 | basic deref | ✅ PASS |
| 11 | Already instrumented returns none | ✅ PASS |
| 12 | Inter-procedural routes to stage2 | ✅ PASS |
| 13 | Intra-procedural patches | ✅ PASS |
| 14 | Line out of range | ✅ PASS |
| 15 | Missing line number | ✅ PASS |
| 16 | CWE-416 classification | ✅ PASS |
| 17 | deallocuse cppcheck id | ✅ PASS |
| 18 | use_after_free cppcheck id | ✅ PASS |
| 19 | CETS confidence malloc | ✅ PASS |
| 20 | CETS confidence free | ✅ PASS |
| 21 | CETS confidence deref | ✅ PASS |
| 22 | malloc with cast | ✅ PASS |
| 23 | malloc struct pointer | ✅ PASS |
| 24 | free complex expression | ✅ PASS |
| 25 | ptr derivation add expression | ✅ PASS |
| 26 | ptr derivation idx complex | ✅ PASS |
| 27 | instrumentation_type field | ✅ PASS |
| 28 | requires_cets_runtime flag | ✅ PASS |
| 29 | Original differs from repaired | ✅ PASS |
| 30 | deref_load own line | ✅ PASS |

---

## Summary

| Module | Tests | Passed | Failed | Success Rate |
|--------|-------|--------|--------|--------------|
| Null Pointer | 30 | 30 | 0 | 100% |
| Uninitialized Var | 30 | 30 | 0 | 100% |
| Integer Overflow | 30 | 30 | 0 | 100% |
| Buffer Overflow | 30 | 30 | 0 | 100% |
| Format String | 30 | 30 | 0 | 100% |
| Dangerous API | 30 | 30 | 0 | 100% |
| MemFix | 30 | 30 | 0 | 100% |
| Use-After-Free CETS | 30 | 30 | 0 | 100% |
| **TOTAL** | **240** | **240** | **0** | **100%** |

---

**Generated:** 2026-04-17 07:21:07
