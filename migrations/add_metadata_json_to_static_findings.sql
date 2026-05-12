-- Migration: Add metadata_json column to static_findings table
-- Purpose: Support false positive detection and other metadata storage
-- Date: 2026-04-16

-- Add metadata_json column to static_findings table
ALTER TABLE static_findings 
ADD COLUMN IF NOT EXISTS metadata_json JSONB DEFAULT '{}'::jsonb;

-- Create index for faster queries on false positive flag
CREATE INDEX IF NOT EXISTS idx_static_findings_metadata_false_positive 
ON static_findings ((metadata_json->>'is_false_positive'));

-- Add comment to document the column
COMMENT ON COLUMN static_findings.metadata_json IS 'Stores false positive detection results and other metadata';

-- Verify the migration
SELECT 
    column_name, 
    data_type, 
    column_default,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'static_findings' 
AND column_name = 'metadata_json';
