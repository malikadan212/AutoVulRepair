-- Migration: Add webhook_events table for tracking webhook activity
-- Date: 2026-05-13

CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delivery_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    action VARCHAR(50),
    repository_full_name VARCHAR(255),
    installation_id INTEGER,
    sender_login VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'received',
    scan_id VARCHAR(255),
    error_message TEXT,
    payload_summary JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_webhook_events_repository ON webhook_events(repository_full_name);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_scan_id ON webhook_events(scan_id);

-- Add comment
COMMENT ON TABLE webhook_events IS 'Tracks all webhook events received from GitHub for visibility and debugging';
