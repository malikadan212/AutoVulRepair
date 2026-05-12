-- Migration: Add AI Patching and Fuzzing tables
-- Description: Creates tables for tracking AI-generated patches and fuzzing test results

-- Patches table for AI-generated vulnerability fixes
CREATE TABLE IF NOT EXISTS patches (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(36),
    vulnerability_id VARCHAR(255),
    patch_content TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, applied, rejected, failed
    confidence_score DECIMAL(5,2) DEFAULT 0.0,  -- 0-100
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    applied_at TIMESTAMP,
    file_path VARCHAR(500),
    line_number INTEGER,
    patch_type VARCHAR(100),  -- buffer_overflow_fix, null_check, memory_leak_fix, etc.
    ai_model VARCHAR(100),  -- gpt-4, claude, gemini, etc.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_patches_user_id ON patches(user_id);
CREATE INDEX IF NOT EXISTS idx_patches_scan_id ON patches(scan_id);
CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);

-- Fuzzing results table for tracking fuzzing test execution
CREATE TABLE IF NOT EXISTS fuzzing_results (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(36),
    target_binary VARCHAR(500) NOT NULL,
    test_case_id VARCHAR(255),
    crash_found BOOLEAN DEFAULT FALSE,
    coverage_percent DECIMAL(5,2) DEFAULT 0.0,  -- 0-100
    execution_time_ms INTEGER,
    input_data TEXT,
    crash_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fuzzer_type VARCHAR(100),  -- afl, libfuzzer, honggfuzz, etc.
    iterations INTEGER DEFAULT 0,
    unique_crashes INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_fuzzing_user_id ON fuzzing_results(user_id);
CREATE INDEX IF NOT EXISTS idx_fuzzing_scan_id ON fuzzing_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_fuzzing_target ON fuzzing_results(target_binary);
CREATE INDEX IF NOT EXISTS idx_fuzzing_crash ON fuzzing_results(crash_found);

-- Add comments for documentation
COMMENT ON TABLE patches IS 'Stores AI-generated patches for vulnerabilities';
COMMENT ON TABLE fuzzing_results IS 'Stores results from fuzzing test executions';

COMMENT ON COLUMN patches.confidence_score IS 'AI confidence in patch correctness (0-100)';
COMMENT ON COLUMN patches.status IS 'Patch lifecycle status: pending, applied, rejected, failed';
COMMENT ON COLUMN fuzzing_results.coverage_percent IS 'Code coverage achieved during fuzzing (0-100)';
COMMENT ON COLUMN fuzzing_results.crash_found IS 'Whether this test case triggered a crash';
