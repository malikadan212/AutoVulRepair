-- Insert sample AI patch data with 100% success rate and high confidence
INSERT INTO patches (user_id, scan_id, vulnerability_id, patch_content, status, confidence_score, file_path, line_number, patch_type, ai_model, created_at, applied_at)
VALUES 
    ('124624936', NULL, 'CWE-120-001', 'strncpy(dest, src, sizeof(dest) - 1);', 'applied', 98.5, '/src/main.c', 45, 'buffer_overflow_fix', 'gpt-4', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
    ('124624936', NULL, 'CWE-476-002', 'if (ptr != NULL) { ptr->value = 10; }', 'applied', 99.2, '/src/utils.c', 123, 'null_check', 'claude-3', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days'),
    ('124624936', NULL, 'CWE-401-003', 'free(buffer); buffer = NULL;', 'applied', 97.8, '/src/memory.c', 67, 'memory_leak_fix', 'gpt-4', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days'),
    ('124624936', NULL, 'CWE-787-004', 'memcpy(dest, src, min(len, MAX_SIZE));', 'applied', 98.9, '/src/parser.c', 234, 'buffer_overflow_fix', 'gemini-pro', NOW() - INTERVAL '1 day', NOW() - INTERVAL '12 hours'),
    ('124624936', NULL, 'CWE-190-005', 'if (a > INT_MAX - b) return ERROR;', 'applied', 99.5, '/src/calc.c', 89, 'integer_overflow_fix', 'gpt-4', NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days'),
    ('124624936', NULL, 'CWE-416-006', 'ptr = NULL; // Use after free prevention', 'applied', 96.7, '/src/handler.c', 156, 'use_after_free_fix', 'claude-3', NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days'),
    ('124624936', NULL, 'CWE-125-007', 'if (index < array_size) { value = array[index]; }', 'applied', 99.8, '/src/array.c', 78, 'bounds_check', 'gpt-4', NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days'),
    ('124624936', NULL, 'CWE-134-008', 'snprintf(buffer, sizeof(buffer), "%s", user_input);', 'applied', 98.1, '/src/format.c', 201, 'format_string_fix', 'gemini-pro', NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days'),
    ('124624936', NULL, 'CWE-78-009', 'execve(safe_path, args, env); // Command injection fix', 'applied', 97.3, '/src/exec.c', 145, 'command_injection_fix', 'gpt-4', NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days'),
    ('124624936', NULL, 'CWE-89-010', 'prepared_stmt = prepare("SELECT * FROM users WHERE id = ?");', 'applied', 99.9, '/src/database.c', 312, 'sql_injection_fix', 'claude-3', NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days');

-- Verify the data
SELECT 'AI Patches Summary (100% Success):' as info;
SELECT 
    COUNT(*) as total_patches,
    SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) as applied_patches,
    ROUND(AVG(confidence_score), 1) as avg_confidence,
    ROUND((SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END)::numeric / COUNT(*)) * 100, 1) as success_rate
FROM patches 
WHERE user_id = '124624936';
