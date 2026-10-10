-- =====================================================================
-- NexusEdge Edge Platform: AI Compute Provider Key Vault
-- Migration: 0002_ai_providers_vault.sql
-- Subsystem: Control Plane AI Infrastructure Management
-- Complies with Constitutional Data Isolation (Rule 8) & Security (Rules 18, 19)
-- =====================================================================

CREATE TABLE IF NOT EXISTS ai_providers (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    endpoint VARCHAR(512) NOT NULL,
    provider_type VARCHAR(32) NOT NULL,
    api_key TEXT NOT NULL DEFAULT '',
    cost_per_m_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    priority INT NOT NULL DEFAULT 10,
    sovereignty_jurisdiction VARCHAR(32) NOT NULL DEFAULT '',
    failover_cooldown_secs BIGINT NOT NULL DEFAULT 60,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_providers_project ON ai_providers(project_id);
