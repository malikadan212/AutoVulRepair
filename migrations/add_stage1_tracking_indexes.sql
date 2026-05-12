-- Migration: Add indexes for Stage 1 tracking metadata
-- Purpose: Optimize queries for AI Repair dashboard filtering
-- Date: 2026-05-13

-- Index for needs_ai_repair flag (used by AI Repair dashboard)
CREATE INDEX IF NOT EXISTS idx_static_findings_needs_ai_repair 
ON static_findings ((metadata_json->>'needs_ai_repair'))
WHERE (metadata_json->>'needs_ai_repair')::boolean = true;

-- Index for stage1_attempted flag
CREATE INDEX IF NOT EXISTS idx_static_findings_stage1_attempted 
ON static_findings ((metadata_json->>'stage1_attempted'))
WHERE (metadata_json->>'stage1_attempted')::boolean = true;

-- Index for stage1_failed flag
CREATE INDEX IF NOT EXISTS idx_static_findings_stage1_failed 
ON static_findings ((metadata_json->>'stage1_failed'))
WHERE (metadata_json->>'stage1_failed')::boolean = true;

-- Add comments to document the indexes
COMMENT ON INDEX idx_static_findings_needs_ai_repair IS 'Optimizes AI Repair dashboard queries for vulnerabilities needing AI repair';
COMMENT ON INDEX idx_static_findings_stage1_attempted IS 'Tracks which vulnerabilities were processed by Stage 1';
COMMENT ON INDEX idx_static_findings_stage1_failed IS 'Tracks which vulnerabilities failed Stage 1 repair';

-- Verify the indexes
SELECT 
    indexname,
    indexdef
FROM pg_indexes 
WHERE tablename = 'static_findings' 
AND indexname LIKE 'idx_static_findings_%';
