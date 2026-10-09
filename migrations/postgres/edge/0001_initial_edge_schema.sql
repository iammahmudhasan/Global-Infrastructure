-- =====================================================================
-- NexusEdge Edge Platform: Initial Relational Schema
-- Migration: 0001_initial_edge_schema.sql
-- Subsystem: Control Plane & Edge Configuration Management
-- Complies with Constitutional Data Isolation (Rule 8)
-- =====================================================================

-- 0. Schema Migration Version Tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 1. Organizations & Tenancy
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) UNIQUE NOT NULL,
    tier VARCHAR(32) NOT NULL DEFAULT 'enterprise', -- 'starter', 'growth', 'enterprise'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'member', -- 'owner', 'admin', 'member'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS project_quotas (
    project_id VARCHAR(64) PRIMARY KEY,
    max_domains INT NOT NULL DEFAULT 50
);

-- 2. Domains & Onboarding
CREATE TABLE IF NOT EXISTS domains (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_VERIFICATION', -- 'PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED'
    onboarding_type VARCHAR(32) NOT NULL DEFAULT 'CNAME',       -- 'CNAME', 'NAMESERVER'
    cname_target VARCHAR(255) NOT NULL,                        -- e.g. 'cname-123.edge.nexusedge.net'
    allowed_pops TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS domain_verifications (
    id VARCHAR(64) PRIMARY KEY,
    domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    token VARCHAR(128) NOT NULL,
    verification_type VARCHAR(32) NOT NULL DEFAULT 'DNS_CNAME', -- 'DNS_CNAME', 'DNS_TXT', 'HTTP_TOKEN'
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Origins & Routing Topology
CREATE TABLE IF NOT EXISTS origin_pools (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    lb_algorithm VARCHAR(32) NOT NULL DEFAULT 'ROUND_ROBIN', -- 'ROUND_ROBIN', 'LEAST_LATENCY', 'WEIGHTED'
    allowed_pops TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS origins (
    id VARCHAR(64) PRIMARY KEY,
    pool_id VARCHAR(64) NOT NULL REFERENCES origin_pools(id) ON DELETE CASCADE,
    address VARCHAR(255) NOT NULL, -- FQDN (e.g. 'origin.example.net') or IP ('203.0.113.10')
    port INT NOT NULL DEFAULT 443,
    protocol VARCHAR(16) NOT NULL DEFAULT 'HTTPS', -- 'HTTP', 'HTTPS'
    weight INT NOT NULL DEFAULT 100,
    healthy BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_pops TEXT[] NOT NULL DEFAULT '{}',
    sni VARCHAR(255) NOT NULL DEFAULT '',
    ca_bundle_path VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS routes (
    id VARCHAR(64) PRIMARY KEY,
    domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    pool_id VARCHAR(64) NOT NULL,
    path_prefix VARCHAR(255) NOT NULL DEFAULT '/',
    priority INT NOT NULL DEFAULT 0,
    timeout_ms INT NOT NULL DEFAULT 10000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Edge Policies (Security & Cache)
CREATE TABLE IF NOT EXISTS security_policies (
    id VARCHAR(64) PRIMARY KEY,
    domain_id VARCHAR(64) UNIQUE NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    waf_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    waf_mode VARCHAR(32) NOT NULL DEFAULT 'BLOCK', -- 'BLOCK', 'LOG'
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_rpm INT NOT NULL DEFAULT 1000,
    waf_rules_json JSONB NOT NULL DEFAULT '[]',
    rate_limit_rules_json JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cache_policies (
    id VARCHAR(64) PRIMARY KEY,
    domain_id VARCHAR(64) UNIQUE NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    cache_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    default_ttl_seconds INT NOT NULL DEFAULT 3600,
    respect_origin_headers BOOLEAN NOT NULL DEFAULT TRUE,
    cache_rules_json JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Certificates & TLS Lifecycle
CREATE TABLE IF NOT EXISTS certificates (
    id VARCHAR(64) PRIMARY KEY,
    domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_ISSUANCE', -- 'PENDING_ISSUANCE', 'ACTIVE', 'PENDING_CHALLENGE', 'SUPERSEDED', 'EXPIRED'
    issuer VARCHAR(64) NOT NULL DEFAULT 'LETS_ENCRYPT',
    cert_sn VARCHAR(128) NOT NULL DEFAULT '',
    cert_pem TEXT NOT NULL DEFAULT '',
    private_key_pem TEXT NOT NULL DEFAULT '',
    fingerprint_sha256 VARCHAR(128) NOT NULL DEFAULT '',
    key_type VARCHAR(32) NOT NULL DEFAULT 'ECDSA',
    domains TEXT[] NOT NULL DEFAULT '{}',
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    issued_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tls_settings (
    domain_id VARCHAR(64) PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    enforce_https BOOLEAN NOT NULL DEFAULT TRUE,
    min_tls_version VARCHAR(32) NOT NULL DEFAULT 'TLSv1.2'
);

CREATE TABLE IF NOT EXISTS acme_challenges (
    token VARCHAR(128) PRIMARY KEY,
    id VARCHAR(64) NOT NULL,
    certificate_id VARCHAR(64) NOT NULL,
    domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL DEFAULT 'HTTP-01',
    key_authorization TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- 6. Fleet Nodes & Observability Samples
CREATE TABLE IF NOT EXISTS edge_nodes (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    region VARCHAR(64) NOT NULL,
    ip_address INET NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ONLINE',
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64) NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for Line-Rate Query Performance
CREATE INDEX IF NOT EXISTS idx_domains_hostname ON domains(hostname);
CREATE INDEX IF NOT EXISTS idx_domains_project ON domains(project_id);
CREATE INDEX IF NOT EXISTS idx_origins_pool ON origins(pool_id);
CREATE INDEX IF NOT EXISTS idx_routes_domain ON routes(domain_id);
CREATE INDEX IF NOT EXISTS idx_certificates_domain_status ON certificates(domain_id, status);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_token ON acme_challenges(token);
