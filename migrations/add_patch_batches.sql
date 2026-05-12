-- Migration: Add Patch Batches System
-- Description: Enables coordinated application of Stage 1 + Stage 2 patches
-- Date: 2026-04-16

-- Create patch_batches table
CREATE TABLE IF NOT EXISTS patch_batches (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scan_id VARCHAR(36) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'generating', -- 'generating', 'ready', 'applied', 'failed'
    
    -- Stage tracking
    stage1_complete BOOLEAN DEFAULT FALSE,
    stage2_complete BOOLEAN DEFAULT FALSE,
    stage1_patches_count INT DEFAULT 0,
    stage2_patches_count INT DEFAULT 0,
    total_patches_count INT DEFAULT 0,
    
    -- Vulnerability counts
    stage1_vulnerabilities_count INT DEFAULT 0,
    stage2_vulnerabilities_count INT DEFAULT 0,
    
    -- Timing
    created_at TIMESTAMP DEFAULT NOW(),
    stage1_completed_at TIMESTAMP,
    stage2_completed_at TIMESTAMP,
    applied_at TIMESTAMP,
    
    -- Application details
    applied_by VARCHAR(36) REFERENCES users(id),
    commit_sha VARCHAR(255),
    pr_url TEXT,
    branch_name VARCHAR(255),
    
    -- Metadata
    notes TEXT,
    
    UNIQUE(scan_id)
);

-- Add batch_id to patches table if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='patches' AND column_name='batch_id') THEN
        ALTER TABLE patches ADD COLUMN batch_id VARCHAR(36) REFERENCES patch_batches(id) ON DELETE SET NULL;
    END IF;
END $$;

-- Add stage column to patches table if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='patches' AND column_name='stage') THEN
        ALTER TABLE patches ADD COLUMN stage INT DEFAULT 1 CHECK (stage IN (1, 2));
    END IF;
END $$;

-- Add selected_for_application column if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='patches' AND column_name='selected_for_application') THEN
        ALTER TABLE patches ADD COLUMN selected_for_application BOOLEAN DEFAULT TRUE;
    END IF;
END $$;

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_patches_batch_id ON patches(batch_id);
CREATE INDEX IF NOT EXISTS idx_patches_stage ON patches(stage);
CREATE INDEX IF NOT EXISTS idx_patch_batches_scan_id ON patch_batches(scan_id);
CREATE INDEX IF NOT EXISTS idx_patch_batches_status ON patch_batches(status);

-- Create function to update total_patches_count automatically
CREATE OR REPLACE FUNCTION update_batch_total_patches()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE patch_batches
    SET total_patches_count = stage1_patches_count + stage2_patches_count
    WHERE id = NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to auto-update total count
DROP TRIGGER IF EXISTS trigger_update_batch_total ON patch_batches;
CREATE TRIGGER trigger_update_batch_total
    AFTER UPDATE OF stage1_patches_count, stage2_patches_count ON patch_batches
    FOR EACH ROW
    EXECUTE FUNCTION update_batch_total_patches();

-- Add comments for documentation
COMMENT ON TABLE patch_batches IS 'Manages coordinated application of Stage 1 and Stage 2 patches';
COMMENT ON COLUMN patch_batches.status IS 'Current status: generating, ready, applied, failed';
COMMENT ON COLUMN patch_batches.stage1_complete IS 'Whether Stage 1 patch generation is complete';
COMMENT ON COLUMN patch_batches.stage2_complete IS 'Whether Stage 2 (AI) patch generation is complete';
COMMENT ON COLUMN patches.batch_id IS 'Links patch to a batch for coordinated application';
COMMENT ON COLUMN patches.stage IS 'Which stage generated this patch: 1 (deterministic) or 2 (AI)';
COMMENT ON COLUMN patches.selected_for_application IS 'Whether user selected this patch for application';
