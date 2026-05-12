-- Migration: Add GitHub App Integration Tables
-- Created: 2024-04-11
-- Description: Adds tables for GitHub App installations, repositories, and token caching

-- GitHub App installations table
CREATE TABLE IF NOT EXISTS github_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id BIGINT UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_account_login VARCHAR(255) NOT NULL,
    github_account_id BIGINT,
    github_account_type VARCHAR(50),
    repository_selection VARCHAR(50),
    permissions JSONB,
    is_active BOOLEAN DEFAULT true,
    installed_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_github_installations_user_id ON github_installations(user_id);
CREATE INDEX IF NOT EXISTS idx_github_installations_installation_id ON github_installations(installation_id);
CREATE INDEX IF NOT EXISTS idx_github_installations_active ON github_installations(is_active);

-- Installation repositories table
CREATE TABLE IF NOT EXISTS installation_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id UUID NOT NULL REFERENCES github_installations(id) ON DELETE CASCADE,
    repository_full_name VARCHAR(255) NOT NULL,
    repository_id BIGINT NOT NULL,
    repository_name VARCHAR(255),
    repository_private BOOLEAN DEFAULT false,
    repository_language VARCHAR(100),
    automation_enabled BOOLEAN DEFAULT false,
    auto_scan_on_push BOOLEAN DEFAULT true,
    auto_create_prs BOOLEAN DEFAULT true,
    auto_scan_on_pr BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{"scan_schedule": "on_push", "severity_threshold": "medium", "create_issues": false, "block_prs_on_critical": false}',
    is_active BOOLEAN DEFAULT true,
    last_scanned_at TIMESTAMP,
    last_scan_status VARCHAR(50),
    added_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_installation_repositories_installation_id ON installation_repositories(installation_id);
CREATE INDEX IF NOT EXISTS idx_installation_repositories_full_name ON installation_repositories(repository_full_name);
CREATE INDEX IF NOT EXISTS idx_installation_repositories_automation ON installation_repositories(automation_enabled);
CREATE INDEX IF NOT EXISTS idx_installation_repositories_active ON installation_repositories(is_active);

-- GitHub App token cache table
CREATE TABLE IF NOT EXISTS github_app_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id BIGINT UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Index for token lookups
CREATE INDEX IF NOT EXISTS idx_github_app_tokens_installation_id ON github_app_tokens(installation_id);
CREATE INDEX IF NOT EXISTS idx_github_app_tokens_expires_at ON github_app_tokens(expires_at);

-- Update trigger for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
CREATE TRIGGER update_github_installations_updated_at 
    BEFORE UPDATE ON github_installations 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_installation_repositories_updated_at 
    BEFORE UPDATE ON installation_repositories 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_github_app_tokens_updated_at 
    BEFORE UPDATE ON github_app_tokens 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE github_installations IS 'Tracks GitHub App installations by users';
COMMENT ON TABLE installation_repositories IS 'Repositories accessible through GitHub App installations';
COMMENT ON TABLE github_app_tokens IS 'Cached GitHub App installation access tokens';

COMMENT ON COLUMN github_installations.installation_id IS 'GitHub App installation ID from GitHub API';
COMMENT ON COLUMN github_installations.repository_selection IS 'all or selected - how user installed the app';
COMMENT ON COLUMN installation_repositories.automation_enabled IS 'Whether automation is enabled for this repository';
COMMENT ON COLUMN installation_repositories.settings IS 'JSON configuration for repository automation settings';