-- Insert sample AI patch data
INSERT INTO patches (user_id, scan_id, vulnerability_id, patch_content, status, confidence_score, file_path, line_number, patch_type, ai_model, created_at, applied_at)
VALUES 
    ('124624936', NULL, 'CWE-120-001', 'strncpy(dest, src, sizeof(dest) - 1);', 'applied', 92.5, '/src/main.c', 45, 'buffer_overflow_fix', 'gpt-4', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
    ('124624936', NULL, 'CWE-476-002', 'if (ptr != NULL) { ptr->value = 10; }', 'applied', 88.3, '/src/utils.c', 123, 'null_check', 'claude-3', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days'),
    ('124624936', NULL, 'CWE-401-003', 'free(buffer); buffer = NULL;', 'applied', 95.7, '/src/memory.c', 67, 'memory_leak_fix', 'gpt-4', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days'),
    ('124624936', NULL, 'CWE-787-004', 'memcpy(dest, src, min(len, MAX_SIZE));', 'pending', 85.2, '/src/parser.c', 234, 'buffer_overflow_fix', 'gemini-pro', NOW() - INTERVAL '1 day', NULL),
    ('124624936', NULL, 'CWE-190-005', 'if (a > INT_MAX - b) return ERROR;', 'applied', 91.8, '/src/calc.c', 89, 'integer_overflow_fix', 'gpt-4', NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days'),
    ('124624936', NULL, 'CWE-416-006', 'ptr = NULL; // Use after free prevention', 'rejected', 78.4, '/src/handler.c', 156, 'use_after_free_fix', 'claude-3', NOW() - INTERVAL '6 days', NULL),
    ('124624936', NULL, 'CWE-125-007', 'if (index < array_size) { value = array[index]; }', 'applied', 93.1, '/src/array.c', 78, 'bounds_check', 'gpt-4', NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days'),
    ('124624936', NULL, 'CWE-134-008', 'snprintf(buffer, sizeof(buffer), "%s", user_input);', 'applied', 89.6, '/src/format.c', 201, 'format_string_fix', 'gemini-pro', NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days');

-- Insert sample fuzzing data
INSERT INTO fuzzing_results (user_id, scan_id, target_binary, test_case_id, crash_found, coverage_percent, execution_time_ms, fuzzer_type, iterations, unique_crashes, created_at)
VALUES
    ('124624936', NULL, '/bin/parser', 'fuzz-001', FALSE, 67.5, 1250, 'afl++', 10000, 0, NOW() - INTERVAL '1 day'),
    ('124624936', NULL, '/bin/parser', 'fuzz-002', TRUE, 72.3, 2340, 'afl++', 15000, 1, NOW() - INTERVAL '2 days'),
    ('124624936', NULL, '/bin/network', 'fuzz-003', FALSE, 54.8, 890, 'libfuzzer', 8000, 0, NOW() - INTERVAL '3 days'),
    ('124624936', NULL, '/bin/network', 'fuzz-004', TRUE, 61.2, 3120, 'libfuzzer', 20000, 2, NOW() - INTERVAL '4 days'),
    ('124624936', NULL, '/bin/crypto', 'fuzz-005', FALSE, 78.9, 1560, 'honggfuzz', 12000, 0, NOW() - INTERVAL '5 days'),
    ('124624936', NULL, '/bin/crypto', 'fuzz-006', FALSE, 82.1, 1780, 'honggfuzz', 14000, 0, NOW() - INTERVAL '6 days'),
    ('124624936', NULL, '/bin/parser', 'fuzz-007', TRUE, 75.6, 2890, 'afl++', 18000, 1, NOW() - INTERVAL '7 days'),
    ('124624936', NULL, '/bin/image', 'fuzz-008', FALSE, 45.3, 670, 'libfuzzer', 6000, 0, NOW() - INTERVAL '8 days'),
    ('124624936', NULL, '/bin/image', 'fuzz-009', FALSE, 51.7, 920, 'libfuzzer', 9000, 0, NOW() - INTERVAL '9 days'),
    ('124624936', NULL, '/bin/network', 'fuzz-010', TRUE, 68.4, 4230, 'afl++', 25000, 3, NOW() - INTERVAL '10 days'),
    ('124624936', NULL, '/bin/crypto', 'fuzz-011', FALSE, 85.2, 2100, 'honggfuzz', 16000, 0, NOW() - INTERVAL '11 days'),
    ('124624936', NULL, '/bin/parser', 'fuzz-012', FALSE, 79.8, 1890, 'afl++', 13000, 0, NOW() - INTERVAL '12 days');

-- Verify the data was inserted
SELECT 'AI Patches Summary:' as info;
SELECT 
    COUNT(*) as total_patches,
    SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) as applied_patches,
    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_patches,
    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_patches,
    ROUND(AVG(confidence_score), 2) as avg_confidence
FROM patches 
WHERE user_id = '124624936';

SELECT 'Fuzzing Results Summary:' as info;
SELECT 
    COUNT(*) as total_tests,
    SUM(CASE WHEN crash_found THEN 1 ELSE 0 END) as crashes_found,
    COUNT(DISTINCT target_binary) as unique_targets,
    ROUND(AVG(coverage_percent), 2) as avg_coverage
FROM fuzzing_results 
WHERE user_id = '124624936';
