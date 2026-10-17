package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
)

// ValidateProductionDatabaseURL enforces that database connection strings used in production
// strictly mandate TLS encryption. Unencrypted connections (sslmode=disable, allow, prefer)
// or omitted sslmode are strictly forbidden per Rule 1 and Rule 18.
func ValidateProductionDatabaseURL(databaseURL string) error {
	raw := strings.TrimSpace(databaseURL)
	if raw == "" {
		return errors.New("database URL cannot be empty in production")
	}

	sslmode := ""
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid database URL: %w", err)
		}
		sslmode = strings.ToLower(parsed.Query().Get("sslmode"))
	} else {
		// Key-value DSN format: e.g. "host=... port=... sslmode=..."
		parts := strings.Fields(raw)
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && strings.ToLower(strings.TrimSpace(kv[0])) == "sslmode" {
				sslmode = strings.ToLower(strings.Trim(strings.TrimSpace(kv[1]), `'"'`))
				break
			}
		}
	}

	if sslmode != "verify-full" {
		return fmt.Errorf("production database connection strictly mandates sslmode=verify-full (rejecting %q) to guarantee server certificate and hostname verification (Rule 1, Rule 18)", sslmode)
	}

	// Verify sslrootcert is provided in connection parameters or PGSSLROOTCERT env var
	sslrootcert := ""
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		if parsed, err := url.Parse(raw); err == nil {
			sslrootcert = parsed.Query().Get("sslrootcert")
		}
	} else {
		for _, part := range strings.Fields(raw) {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && strings.ToLower(strings.TrimSpace(kv[0])) == "sslrootcert" {
				sslrootcert = strings.Trim(strings.TrimSpace(kv[1]), `'"'`)
				break
			}
		}
	}

	if sslrootcert == "" && os.Getenv("PGSSLROOTCERT") == "" {
		return errors.New("production database connection strictly requires sslrootcert parameter or PGSSLROOTCERT environment variable when using sslmode=verify-full")
	}

	return nil
}

// PostgresRepository provides a durable, ACID-compliant PostgreSQL storage implementation
// of the Repository interface. It combines transactional relational writes with a
// synchronized write-through in-memory cache to guarantee sub-millisecond line-rate read performance.
type PostgresRepository struct {
	db    *sql.DB
	cache *Store
}

var _ Repository = (*PostgresRepository)(nil)

// NewPostgresRepository establishes a connection to PostgreSQL, executes initial schema migrations,
// and warms up the line-rate in-memory cache with persisted state.
func NewPostgresRepository(databaseURL string) (*PostgresRepository, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, errors.New("empty PostgreSQL database URL")
	}

	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "production" {
		if err := ValidateProductionDatabaseURL(databaseURL); err != nil {
			return nil, fmt.Errorf("enforce production database TLS: %w", err)
		}
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return NewPostgresRepositoryFromDB(db)
}

// NewPostgresRepositoryFromDB initializes migrations and cache from an existing *sql.DB handle.
func NewPostgresRepositoryFromDB(db *sql.DB) (*PostgresRepository, error) {
	repo := &PostgresRepository{
		db:    db,
		cache: NewStore(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := repo.migrateSchema(ctx); err != nil {
		return nil, fmt.Errorf("migrate edge schema: %w", err)
	}

	if err := repo.warmupCache(ctx); err != nil {
		return nil, fmt.Errorf("warm up cache from postgres: %w", err)
	}

	return repo, nil
}

// Close closes the underlying database pool.
func (r *PostgresRepository) Close() error {
	return r.db.Close()
}

func (r *PostgresRepository) migrateSchema(ctx context.Context) error {
	// Serialize schema migrations across concurrent replicas using PostgreSQL session advisory lock
	const migrationAdvisoryLockID = 74291048201
	_, _ = r.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockID)
	defer func() {
		_, _ = r.db.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockID)
	}()

	// 0. Ensure schema_migrations table exists for versioned tracking
	_, err := r.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(64) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	migrations := []struct {
		version string
		stmts   []string
	}{
		{
			version: "0001_initial_edge_schema",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS organizations (
					id VARCHAR(64) PRIMARY KEY,
					name VARCHAR(255) NOT NULL,
					slug VARCHAR(64) UNIQUE NOT NULL,
					tier VARCHAR(32) NOT NULL DEFAULT 'enterprise',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS projects (
					id VARCHAR(64) PRIMARY KEY,
					org_id VARCHAR(64) NOT NULL,
					name VARCHAR(255) NOT NULL,
					slug VARCHAR(64) NOT NULL,
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS project_quotas (
					project_id VARCHAR(64) PRIMARY KEY,
					max_domains INT NOT NULL DEFAULT 50
				);`,
				`CREATE TABLE IF NOT EXISTS domains (
					id VARCHAR(64) PRIMARY KEY,
					project_id VARCHAR(64) NOT NULL,
					hostname VARCHAR(255) UNIQUE NOT NULL,
					status VARCHAR(32) NOT NULL DEFAULT 'PENDING_VERIFICATION',
					onboarding_type VARCHAR(32) NOT NULL DEFAULT 'CNAME',
					cname_target VARCHAR(255) NOT NULL,
					allowed_pops TEXT[] NOT NULL DEFAULT '{}',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS domain_verifications (
					id VARCHAR(64) PRIMARY KEY,
					domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
					token VARCHAR(128) NOT NULL,
					verification_type VARCHAR(32) NOT NULL DEFAULT 'DNS_CNAME',
					is_verified BOOLEAN NOT NULL DEFAULT FALSE,
					verified_at TIMESTAMPTZ,
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS origin_pools (
					id VARCHAR(64) PRIMARY KEY,
					project_id VARCHAR(64) NOT NULL,
					name VARCHAR(255) NOT NULL,
					lb_algorithm VARCHAR(32) NOT NULL DEFAULT 'ROUND_ROBIN',
					allowed_pops TEXT[] NOT NULL DEFAULT '{}',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS origins (
					id VARCHAR(64) PRIMARY KEY,
					pool_id VARCHAR(64) NOT NULL REFERENCES origin_pools(id) ON DELETE CASCADE,
					address VARCHAR(255) NOT NULL,
					port INT NOT NULL DEFAULT 443,
					protocol VARCHAR(16) NOT NULL DEFAULT 'HTTPS',
					weight INT NOT NULL DEFAULT 100,
					healthy BOOLEAN NOT NULL DEFAULT TRUE,
					allowed_pops TEXT[] NOT NULL DEFAULT '{}',
					sni VARCHAR(255) NOT NULL DEFAULT '',
					ca_bundle_path VARCHAR(255) NOT NULL DEFAULT '',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS routes (
					id VARCHAR(64) PRIMARY KEY,
					domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
					pool_id VARCHAR(64) NOT NULL,
					path_prefix VARCHAR(255) NOT NULL DEFAULT '/',
					priority INT NOT NULL DEFAULT 0,
					timeout_ms INT NOT NULL DEFAULT 10000,
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS security_policies (
					id VARCHAR(64) PRIMARY KEY,
					domain_id VARCHAR(64) UNIQUE NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
					waf_enabled BOOLEAN NOT NULL DEFAULT TRUE,
					waf_mode VARCHAR(32) NOT NULL DEFAULT 'BLOCK',
					rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
					rate_limit_rpm INT NOT NULL DEFAULT 1000,
					waf_rules_json JSONB NOT NULL DEFAULT '[]',
					rate_limit_rules_json JSONB NOT NULL DEFAULT '[]',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS cache_policies (
					id VARCHAR(64) PRIMARY KEY,
					domain_id VARCHAR(64) UNIQUE NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
					cache_enabled BOOLEAN NOT NULL DEFAULT TRUE,
					default_ttl_seconds INT NOT NULL DEFAULT 3600,
					respect_origin_headers BOOLEAN NOT NULL DEFAULT TRUE,
					cache_rules_json JSONB NOT NULL DEFAULT '[]',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS certificates (
					id VARCHAR(64) PRIMARY KEY,
					domain_id VARCHAR(64) NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
					status VARCHAR(32) NOT NULL DEFAULT 'PENDING_ISSUANCE',
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
				);`,
				`CREATE TABLE IF NOT EXISTS tls_settings (
					domain_id VARCHAR(64) PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
					enforce_https BOOLEAN NOT NULL DEFAULT TRUE,
					min_tls_version VARCHAR(32) NOT NULL DEFAULT 'TLSv1.2'
				);`,
				`CREATE TABLE IF NOT EXISTS acme_challenges (
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
				);`,
				`CREATE TABLE IF NOT EXISTS edge_nodes (
					id VARCHAR(64) PRIMARY KEY,
					name VARCHAR(255) NOT NULL,
					region VARCHAR(64) NOT NULL,
					ip_address INET NOT NULL,
					status VARCHAR(32) NOT NULL DEFAULT 'ONLINE',
					last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE TABLE IF NOT EXISTS audit_logs (
					id VARCHAR(64) PRIMARY KEY,
					org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
					actor VARCHAR(255) NOT NULL,
					action VARCHAR(64) NOT NULL,
					resource_type VARCHAR(64) NOT NULL,
					resource_id VARCHAR(64) NOT NULL,
					details JSONB,
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE INDEX IF NOT EXISTS idx_domains_hostname ON domains(hostname);`,
				`CREATE INDEX IF NOT EXISTS idx_domains_project ON domains(project_id);`,
				`CREATE INDEX IF NOT EXISTS idx_origins_pool ON origins(pool_id);`,
				`CREATE INDEX IF NOT EXISTS idx_routes_domain ON routes(domain_id);`,
				`CREATE INDEX IF NOT EXISTS idx_certificates_domain_status ON certificates(domain_id, status);`,
				`CREATE INDEX IF NOT EXISTS idx_acme_challenges_token ON acme_challenges(token);`,
			},
		},
		{
			version: "0002_ai_providers_vault",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS ai_providers (
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
				);`,
				`CREATE INDEX IF NOT EXISTS idx_ai_providers_project ON ai_providers(project_id);`,
			},
		},
		{
			version: "0003_audit_trail_chain",
			stmts: []string{
				`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS project_id VARCHAR(64) NOT NULL DEFAULT '';`,
				`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64) NOT NULL DEFAULT '';`,
				`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(128) NOT NULL DEFAULT '';`,
				`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash VARCHAR(128) NOT NULL DEFAULT '';`,
				`ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_org_id_fkey;`,
				`ALTER TABLE audit_logs ALTER COLUMN org_id DROP NOT NULL;`,
				`ALTER TABLE audit_logs ALTER COLUMN org_id SET DEFAULT '';`,
				`CREATE INDEX IF NOT EXISTS idx_audit_logs_project ON audit_logs(project_id);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);`,
			},
		},
		{
			version: "0004_durable_health_monitors_and_policies",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS health_monitors (
					id VARCHAR(64) PRIMARY KEY,
					pool_id VARCHAR(64) NOT NULL REFERENCES origin_pools(id) ON DELETE CASCADE,
					protocol VARCHAR(32) NOT NULL DEFAULT 'HTTP',
					path VARCHAR(255) NOT NULL DEFAULT '/healthz',
					port INT NOT NULL DEFAULT 80,
					interval_seconds INT NOT NULL DEFAULT 10,
					timeout_seconds INT NOT NULL DEFAULT 2,
					healthy_threshold INT NOT NULL DEFAULT 2,
					unhealthy_threshold INT NOT NULL DEFAULT 3,
					expected_status_codes INT[] NOT NULL DEFAULT '{200}'
				);`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_health_monitors_pool ON health_monitors(pool_id);`,
				`ALTER TABLE tls_settings ADD COLUMN IF NOT EXISTS hsts BOOLEAN NOT NULL DEFAULT FALSE;`,
				`ALTER TABLE tls_settings ADD COLUMN IF NOT EXISTS hsts_max_age INT NOT NULL DEFAULT 0;`,
				`ALTER TABLE cache_policies ADD COLUMN IF NOT EXISTS query_handling VARCHAR(32) NOT NULL DEFAULT 'INCLUDE_ALL';`,
				`ALTER TABLE cache_policies ADD COLUMN IF NOT EXISTS strip_cookies BOOLEAN NOT NULL DEFAULT FALSE;`,
			},
		},
		{
			version: "0005_outbox_events_and_desired_state",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS outbox_events (
					event_id VARCHAR(64) PRIMARY KEY,
					aggregate_type VARCHAR(64) NOT NULL,
					aggregate_id VARCHAR(64) NOT NULL,
					event_type VARCHAR(64) NOT NULL,
					payload JSONB NOT NULL,
					status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
					retry_count INT NOT NULL DEFAULT 0,
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					processed_at TIMESTAMPTZ
				);`,
				`CREATE INDEX IF NOT EXISTS idx_outbox_events_status ON outbox_events(status, created_at);`,
				`CREATE INDEX IF NOT EXISTS idx_outbox_events_aggregate ON outbox_events(aggregate_type, aggregate_id);`,
				`ALTER TABLE domains ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;`,
			},
		},
	}

	for _, m := range migrations {
		var exists bool
		err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", m.version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration version %s: %w", m.version, err)
		}
		if exists {
			continue
		}

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx for migration %s: %w", m.version, err)
		}

		for _, stmt := range m.stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("exec migration (%s): %w", stmt[:minInt(len(stmt), 40)], err)
			}
		}

		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.version, err)
		}
	}

	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *PostgresRepository) warmupCache(ctx context.Context) error {
	// 1. Quotas
	qRows, err := r.db.QueryContext(ctx, "SELECT project_id, max_domains FROM project_quotas")
	if err != nil {
		return fmt.Errorf("query project_quotas: %w", err)
	}
	defer qRows.Close()
	for qRows.Next() {
		var pid string
		var md int
		if err := qRows.Scan(&pid, &md); err != nil {
			return fmt.Errorf("scan project_quota: %w", err)
		}
		_ = r.cache.SetProjectQuota(pid, ProjectQuota{MaxDomains: md})
	}
	if err := qRows.Err(); err != nil {
		return fmt.Errorf("iterate project_quotas: %w", err)
	}

	// 2. Domains
	domRows, err := r.db.QueryContext(ctx, "SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at FROM domains")
	if err != nil {
		return fmt.Errorf("query domains: %w", err)
	}
	defer domRows.Close()
	for domRows.Next() {
		var d model.Domain
		var pops pq.StringArray
		if err := domRows.Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return fmt.Errorf("scan domain: %w", err)
		}
		d.AllowedPoPs = []string(pops)
		if err := r.cache.SaveDomain(&d); err != nil {
			return fmt.Errorf("cache save domain %s: %w", d.ID, err)
		}
	}
	if err := domRows.Err(); err != nil {
		return fmt.Errorf("iterate domains: %w", err)
	}

	// 3. Origin Pools & Origins
	poolRows, err := r.db.QueryContext(ctx, "SELECT id, project_id, name, lb_algorithm, allowed_pops FROM origin_pools")
	if err != nil {
		return fmt.Errorf("query origin_pools: %w", err)
	}
	defer poolRows.Close()
	for poolRows.Next() {
		var p model.OriginPool
		var pops pq.StringArray
		if err := poolRows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.LBAlgorithm, &pops); err != nil {
			return fmt.Errorf("scan origin_pool: %w", err)
		}
		p.AllowedPoPs = []string(pops)
		if err := r.cache.SaveOriginPoolBypass(&p); err != nil {
			return fmt.Errorf("cache save origin_pool %s: %w", p.ID, err)
		}
	}
	if err := poolRows.Err(); err != nil {
		return fmt.Errorf("iterate origin_pools: %w", err)
	}

	origRows, err := r.db.QueryContext(ctx, "SELECT id, pool_id, address, port, protocol, weight, healthy, allowed_pops, sni, ca_bundle_path FROM origins")
	if err != nil {
		return fmt.Errorf("query origins: %w", err)
	}
	defer origRows.Close()
	for origRows.Next() {
		var o model.Origin
		var pops pq.StringArray
		if err := origRows.Scan(&o.ID, &o.PoolID, &o.Address, &o.Port, &o.Protocol, &o.Weight, &o.Healthy, &pops, &o.SNI, &o.CABundlePath); err != nil {
			return fmt.Errorf("scan origin: %w", err)
		}
		o.AllowedPoPs = []string(pops)
		if err := r.cache.AddOrigin(&o); err != nil {
			return fmt.Errorf("cache save origin %s: %w", o.ID, err)
		}
	}
	if err := origRows.Err(); err != nil {
		return fmt.Errorf("iterate origins: %w", err)
	}

	// 4. Routes
	routeRows, err := r.db.QueryContext(ctx, "SELECT id, domain_id, pool_id, path_prefix, priority, timeout_ms FROM routes")
	if err != nil {
		return fmt.Errorf("query routes: %w", err)
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var rt model.Route
		if err := routeRows.Scan(&rt.ID, &rt.DomainID, &rt.PoolID, &rt.PathPrefix, &rt.Priority, &rt.TimeoutMs); err != nil {
			return fmt.Errorf("scan route: %w", err)
		}
		if err := r.cache.SaveRoute(&rt); err != nil {
			return fmt.Errorf("cache save route %s: %w", rt.ID, err)
		}
	}
	if err := routeRows.Err(); err != nil {
		return fmt.Errorf("iterate routes: %w", err)
	}

	// 5. Security Policies
	secRows, err := r.db.QueryContext(ctx, "SELECT id, domain_id, waf_enabled, waf_mode, rate_limit_enabled, rate_limit_rpm, waf_rules_json, rate_limit_rules_json FROM security_policies")
	if err != nil {
		return fmt.Errorf("query security_policies: %w", err)
	}
	defer secRows.Close()
	for secRows.Next() {
		var sp model.SecurityPolicy
		var wafJSON, rlJSON []byte
		if err := secRows.Scan(&sp.ID, &sp.DomainID, &sp.WAFEnabled, &sp.WAFMode, &sp.RateLimitEnabled, &sp.RateLimitRPM, &wafJSON, &rlJSON); err != nil {
			return fmt.Errorf("scan security_policy: %w", err)
		}
		if len(wafJSON) > 0 {
			if err := json.Unmarshal(wafJSON, &sp.WAFRules); err != nil {
				return fmt.Errorf("unmarshal waf_rules: %w", err)
			}
		}
		if len(rlJSON) > 0 {
			if err := json.Unmarshal(rlJSON, &sp.RateLimitRules); err != nil {
				return fmt.Errorf("unmarshal rate_limit_rules: %w", err)
			}
		}
		if err := r.cache.SaveSecurityPolicy(&sp); err != nil {
			return fmt.Errorf("cache save security_policy %s: %w", sp.ID, err)
		}
	}
	if err := secRows.Err(); err != nil {
		return fmt.Errorf("iterate security_policies: %w", err)
	}

	// 6. Cache Policies
	cacheRows, err := r.db.QueryContext(ctx, "SELECT id, domain_id, cache_enabled, default_ttl_seconds, respect_origin_headers, query_handling, strip_cookies, cache_rules_json FROM cache_policies")
	if err != nil {
		return fmt.Errorf("query cache_policies: %w", err)
	}
	defer cacheRows.Close()
	for cacheRows.Next() {
		var cp model.CachePolicy
		var rulesJSON []byte
		var qHandling string
		if err := cacheRows.Scan(&cp.ID, &cp.DomainID, &cp.CacheEnabled, &cp.DefaultTTLSeconds, &cp.RespectOriginHeaders, &qHandling, &cp.StripCookies, &rulesJSON); err != nil {
			return fmt.Errorf("scan cache_policy: %w", err)
		}
		cp.QueryHandling = model.QueryStringHandling(qHandling)
		if len(rulesJSON) > 0 {
			if err := json.Unmarshal(rulesJSON, &cp.CacheRules); err != nil {
				return fmt.Errorf("unmarshal cache_rules: %w", err)
			}
		}
		if err := r.cache.SaveCachePolicy(&cp); err != nil {
			return fmt.Errorf("cache save cache_policy %s: %w", cp.ID, err)
		}
	}
	if err := cacheRows.Err(); err != nil {
		return fmt.Errorf("iterate cache_policies: %w", err)
	}

	// 7. Certificates (Order by issued_at ASC so latest active certificate is deterministically applied to cache last)
	certRows, err := r.db.QueryContext(ctx, "SELECT id, domain_id, status, issuer, cert_sn, cert_pem, private_key_pem, fingerprint_sha256, key_type, domains, auto_renew, issued_at, expires_at FROM certificates WHERE status IN ('ACTIVE', 'PENDING_CHALLENGE') ORDER BY issued_at ASC NULLS FIRST")
	if err != nil {
		return fmt.Errorf("query certificates: %w", err)
	}
	defer certRows.Close()
	for certRows.Next() {
		var c model.Certificate
		var doms pq.StringArray
		var issuedAt, expiresAt sql.NullTime
		if err := certRows.Scan(&c.ID, &c.DomainID, &c.Status, &c.Issuer, &c.SerialNumber, &c.CertPEM, &c.PrivateKeyPEM, &c.FingerprintSHA256, &c.KeyType, &doms, &c.AutoRenew, &issuedAt, &expiresAt); err != nil {
			return fmt.Errorf("scan certificate: %w", err)
		}
		c.Domains = []string(doms)
		if issuedAt.Valid {
			c.IssuedAt = issuedAt.Time
		}
		if expiresAt.Valid {
			c.ExpiresAt = expiresAt.Time
		}
		if c.PrivateKeyPEM != "" {
			rawStored := c.PrivateKeyPEM
			decrypted, decErr := security.DecryptSecret(rawStored)
			if decErr != nil {
				return fmt.Errorf("decrypt certificate private key %s: %w", c.ID, decErr)
			}
			c.PrivateKeyPEM = decrypted

			// Transparent fail-closed application-level migration: encrypt legacy plaintext keys at rest
			if !security.IsEncrypted(rawStored) {
				enc, encErr := security.EncryptSecret(rawStored)
				if encErr != nil {
					return fmt.Errorf("encrypt certificate private key %s: %w", c.ID, encErr)
				}
				res, err := r.db.ExecContext(ctx, "UPDATE certificates SET private_key_pem = $1 WHERE id = $2 AND private_key_pem = $3", enc, c.ID, rawStored)
				if err != nil {
					return fmt.Errorf("migrate plaintext certificate private key %s: %w", c.ID, err)
				}
				rows, _ := res.RowsAffected()
				if rows == 0 {
					var currentKey string
					if err := r.db.QueryRowContext(ctx, "SELECT private_key_pem FROM certificates WHERE id = $1", c.ID).Scan(&currentKey); err != nil || !security.IsEncrypted(currentKey) {
						return fmt.Errorf("failed to migrate plaintext certificate private key %s: concurrent conflict or unmodified", c.ID)
					}
				}
			}
		}
		if err := r.cache.SaveCertificate(&c); err != nil {
			return fmt.Errorf("cache save certificate %s: %w", c.ID, err)
		}
	}
	if err := certRows.Err(); err != nil {
		return fmt.Errorf("iterate certificates: %w", err)
	}

	// 8. TLS Settings
	tlsRows, err := r.db.QueryContext(ctx, "SELECT domain_id, enforce_https, min_tls_version, hsts, hsts_max_age FROM tls_settings")
	if err != nil {
		return fmt.Errorf("query tls_settings: %w", err)
	}
	defer tlsRows.Close()
	for tlsRows.Next() {
		var domID string
		var s model.TLSSettings
		if err := tlsRows.Scan(&domID, &s.EnforceHTTPS, &s.MinTLSVersion, &s.HSTS, &s.HSTSMaxAge); err != nil {
			return fmt.Errorf("scan tls_settings: %w", err)
		}
		if err := r.cache.SaveTLSSettings(domID, &s); err != nil {
			return fmt.Errorf("cache save tls_settings %s: %w", domID, err)
		}
	}
	if err := tlsRows.Err(); err != nil {
		return fmt.Errorf("iterate tls_settings: %w", err)
	}

	// 9. ACME Challenges
	chRows, err := r.db.QueryContext(ctx, "SELECT id, token, certificate_id, domain_id, hostname, type, key_authorization, status, created_at, expires_at FROM acme_challenges WHERE expires_at > NOW()")
	if err != nil {
		return fmt.Errorf("query acme_challenges: %w", err)
	}
	defer chRows.Close()
	for chRows.Next() {
		var ch model.ACMEChallenge
		if err := chRows.Scan(&ch.ID, &ch.Token, &ch.CertificateID, &ch.DomainID, &ch.Hostname, &ch.Type, &ch.KeyAuthorization, &ch.Status, &ch.CreatedAt, &ch.ExpiresAt); err != nil {
			return fmt.Errorf("scan acme_challenge: %w", err)
		}
		if err := r.cache.SaveACMEChallenge(&ch); err != nil {
			return fmt.Errorf("cache save acme_challenge %s: %w", ch.ID, err)
		}
	}
	if err := chRows.Err(); err != nil {
		return fmt.Errorf("iterate acme_challenges: %w", err)
	}

	// 10. AI Compute Providers
	aiRows, err := r.db.QueryContext(ctx, "SELECT id, project_id, name, endpoint, provider_type, api_key, cost_per_m_tokens, priority, sovereignty_jurisdiction, failover_cooldown_secs, enabled, created_at, updated_at FROM ai_providers")
	if err != nil {
		return fmt.Errorf("query ai_providers: %w", err)
	}
	defer aiRows.Close()

	for aiRows.Next() {
		var p model.AIProvider
		if err := aiRows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Endpoint, &p.ProviderType, &p.APIKey, &p.CostPerMTokens, &p.Priority, &p.SovereigntyJurisdiction, &p.FailoverCooldownSecs, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return fmt.Errorf("scan ai_provider: %w", err)
		}
		if p.APIKey != "" {
			rawStored := p.APIKey
			decrypted, decErr := security.DecryptSecret(rawStored)
			if decErr != nil {
				return fmt.Errorf("decrypt ai_provider secret %s: %w", p.ID, decErr)
			}
			p.APIKey = decrypted

			// Transparent fail-closed application-level migration: encrypt legacy plaintext keys at rest
			if !security.IsEncrypted(rawStored) {
				enc, encErr := security.EncryptSecret(rawStored)
				if encErr != nil {
					return fmt.Errorf("encrypt ai_provider secret %s: %w", p.ID, encErr)
				}
				res, err := r.db.ExecContext(ctx, "UPDATE ai_providers SET api_key = $1 WHERE id = $2 AND api_key = $3", enc, p.ID, rawStored)
				if err != nil {
					return fmt.Errorf("migrate plaintext ai_provider secret %s: %w", p.ID, err)
				}
				rows, _ := res.RowsAffected()
				if rows == 0 {
					var currentKey string
					if err := r.db.QueryRowContext(ctx, "SELECT api_key FROM ai_providers WHERE id = $1", p.ID).Scan(&currentKey); err != nil || !security.IsEncrypted(currentKey) {
						return fmt.Errorf("failed to migrate plaintext ai_provider secret %s: concurrent conflict or unmodified", p.ID)
					}
				}
			}
		}
		if err := r.cache.SaveAIProvider(&p); err != nil {
			return fmt.Errorf("cache save ai_provider: %w", err)
		}
	}
	if err := aiRows.Err(); err != nil {
		return fmt.Errorf("iterate ai_providers: %w", err)
	}

	// 11. Health Monitors
	hmRows, err := r.db.QueryContext(ctx, "SELECT id, pool_id, protocol, path, port, interval_seconds, timeout_seconds, healthy_threshold, unhealthy_threshold, expected_status_codes FROM health_monitors")
	if err != nil {
		return fmt.Errorf("query health_monitors: %w", err)
	}
	defer hmRows.Close()
	for hmRows.Next() {
		var hm model.HealthMonitor
		var codes pq.Int64Array
		if err := hmRows.Scan(&hm.ID, &hm.PoolID, &hm.Protocol, &hm.Path, &hm.Port, &hm.IntervalSeconds, &hm.TimeoutSeconds, &hm.HealthyThreshold, &hm.UnhealthyThreshold, &codes); err != nil {
			return fmt.Errorf("scan health_monitor: %w", err)
		}
		for _, c := range codes {
			hm.ExpectedStatusCodes = append(hm.ExpectedStatusCodes, int(c))
		}
		if err := r.cache.SaveHealthMonitor(&hm); err != nil {
			return fmt.Errorf("cache save health_monitor %s: %w", hm.ID, err)
		}
	}
	if err := hmRows.Err(); err != nil {
		return fmt.Errorf("iterate health_monitors: %w", err)
	}

	// 12. Audit Logs (Ordered by created_at ASC to seed cryptographic hash chain)
	auditRows, err := r.db.QueryContext(ctx, "SELECT id, COALESCE(org_id, ''), COALESCE(project_id, ''), actor, action, resource_type, resource_id, COALESCE(client_ip, ''), details, COALESCE(prev_hash, ''), COALESCE(hash, ''), created_at FROM audit_logs ORDER BY created_at ASC")
	if err != nil {
		return fmt.Errorf("query audit_logs: %w", err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var l model.AuditLog
		var detailsJSON []byte
		if err := auditRows.Scan(&l.ID, &l.OrgID, &l.ProjectID, &l.Actor, &l.Action, &l.ResourceType, &l.ResourceID, &l.ClientIP, &detailsJSON, &l.PrevHash, &l.Hash, &l.CreatedAt); err != nil {
			return fmt.Errorf("scan audit_log: %w", err)
		}
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &l.Details); err != nil {
				return fmt.Errorf("unmarshal audit_log details %s: %w", l.ID, err)
			}
		}
		if err := r.cache.SaveAuditLog(&l); err != nil {
			return fmt.Errorf("cache save audit_log %s: %w", l.ID, err)
		}
	}
	if err := auditRows.Err(); err != nil {
		return fmt.Errorf("iterate audit_logs: %w", err)
	}

	return nil
}

// -------------------------------------------------------------------------
// Quotas
// -------------------------------------------------------------------------

func (r *PostgresRepository) SetProjectQuota(projectID string, quota ProjectQuota) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO project_quotas (project_id, max_domains) VALUES ($1, $2)
		 ON CONFLICT (project_id) DO UPDATE SET max_domains = EXCLUDED.max_domains`,
		projectID, quota.MaxDomains,
	)
	if err != nil {
		return fmt.Errorf("persist project quota: %w", err)
	}
	return r.cache.SetProjectQuota(projectID, quota)
}

func (r *PostgresRepository) GetProjectQuota(projectID string) ProjectQuota {
	return r.cache.GetProjectQuota(projectID)
}

func pqStringArray(arr []string) interface{} {
	if arr == nil {
		return pq.Array([]string{})
	}
	return pq.Array(arr)
}

// -------------------------------------------------------------------------
// Domains
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveDomain(d *model.Domain) error {
	if err := ValidateAllowedPoPs(d.AllowedPoPs); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if d.ProjectID != "" {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO projects (id, org_id, name, slug) VALUES ($1, 'org-default', $1, $1) ON CONFLICT (id) DO NOTHING`,
			d.ProjectID,
		)
		if err != nil {
			return fmt.Errorf("upsert project: %w", err)
		}
	}

	now := time.Now().UTC()
	createdAt := d.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO domains (id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1)
		 ON CONFLICT (id) DO UPDATE SET
		   hostname = EXCLUDED.hostname,
		   status = EXCLUDED.status,
		   onboarding_type = EXCLUDED.onboarding_type,
		   cname_target = EXCLUDED.cname_target,
		   allowed_pops = EXCLUDED.allowed_pops,
		   updated_at = EXCLUDED.updated_at,
		   version = domains.version + 1`,
		d.ID, d.ProjectID, d.Hostname, string(d.Status), d.OnboardingType, d.CNAMETarget,
		pqStringArray(d.AllowedPoPs), createdAt, now,
	)
	if err != nil {
		return fmt.Errorf("upsert domain: %w", err)
	}

	eventID := fmt.Sprintf("evt-%d-%s", time.Now().UnixNano(), d.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":       d.ID,
		"project_id":      d.ProjectID,
		"hostname":        d.Hostname,
		"status":          string(d.Status),
		"onboarding_type": d.OnboardingType,
		"cname_target":    d.CNAMETarget,
		"allowed_pops":    d.AllowedPoPs,
		"updated_at":      now.Format(time.RFC3339),
	})
	_, err = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'domain', $2, 'domain.config.changed', $3, 'PENDING')`,
		eventID, d.ID, payloadJSON,
	)
	if err != nil {
		return fmt.Errorf("record outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit domain tx: %w", err)
	}

	// Cache is a disposable line-rate projection. If cache write fails, do NOT fail the call
	// because PostgreSQL committed atomically as the system of record.
	_ = r.cache.SaveDomain(d)
	return nil
}

func (r *PostgresRepository) GetDomain(id string) (*model.Domain, error) {
	d, err := r.cache.GetDomain(id)
	if err == nil && d != nil {
		return d, nil
	}
	// Fallback to authoritative PostgreSQL system-of-record if cache projection has not yet refreshed
	return r.getDomainFromDB(id)
}

func (r *PostgresRepository) GetDomainByHost(hostname string) (*model.Domain, error) {
	d, err := r.cache.GetDomainByHost(hostname)
	if err == nil && d != nil {
		return d, nil
	}
	// Fallback to authoritative PostgreSQL system-of-record if cache projection has not yet refreshed
	return r.getDomainByHostFromDB(hostname)
}

func (r *PostgresRepository) getDomainFromDB(id string) (*model.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var d model.Domain
	var pops pq.StringArray
	err := r.db.QueryRowContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at FROM domains WHERE id = $1",
		id,
	).Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query domain %s: %w", id, err)
	}
	d.AllowedPoPs = []string(pops)
	_ = r.cache.SaveDomain(&d)
	return &d, nil
}

func (r *PostgresRepository) getDomainByHostFromDB(hostname string) (*model.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var d model.Domain
	var pops pq.StringArray
	err := r.db.QueryRowContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at FROM domains WHERE hostname = $1",
		hostname,
	).Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query domain by host %s: %w", hostname, err)
	}
	d.AllowedPoPs = []string(pops)
	_ = r.cache.SaveDomain(&d)
	return &d, nil
}

func (r *PostgresRepository) ListDomainsByProject(projectID string) []*model.Domain {
	return r.cache.ListDomainsByProject(projectID)
}

func (r *PostgresRepository) ListDomains() []*model.Domain {
	return r.cache.ListDomains()
}

func (r *PostgresRepository) UpdateDomainStatus(id string, status model.DomainStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		"UPDATE domains SET status = $1, version = version + 1, updated_at = NOW() WHERE id = $2",
		string(status), id,
	)
	if err != nil {
		return fmt.Errorf("update domain status: %w", err)
	}

	eventID := fmt.Sprintf("evt-status-%d-%s", time.Now().UnixNano(), id)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id": id,
		"status":    string(status),
	})
	_, err = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'domain', $2, 'domain.status.changed', $3, 'PENDING')`,
		eventID, id, payloadJSON,
	)
	if err != nil {
		return fmt.Errorf("record outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit status tx: %w", err)
	}

	return r.cache.UpdateDomainStatus(id, status)
}

func (r *PostgresRepository) DeleteDomain(domainID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	eventID := fmt.Sprintf("evt-del-%d-%s", time.Now().UnixNano(), domainID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":  domainID,
		"deleted_at": time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'domain', $2, 'domain.deleted', $3, 'PENDING')`,
		eventID, domainID, payloadJSON,
	)

	_, err = tx.ExecContext(ctx, "DELETE FROM domains WHERE id = $1", domainID)
	if err != nil {
		return fmt.Errorf("delete domain from postgres: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete tx: %w", err)
	}

	return r.cache.DeleteDomain(domainID)
}

func (r *PostgresRepository) SweepExpiredPendingDomains(maxAge time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cutoff := time.Now().UTC().Add(-maxAge)
	rows, err := r.db.QueryContext(ctx,
		"SELECT id FROM domains WHERE status = 'PENDING_VERIFICATION' AND created_at < $1",
		cutoff,
	)
	if err == nil {
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		for _, id := range ids {
			_ = r.DeleteDomain(id)
		}
	}

	return r.cache.SweepExpiredPendingDomains(maxAge)
}

// -------------------------------------------------------------------------
// Origin Pools & Origins
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveOriginPool(p *model.OriginPool) error {
	if err := ValidateAllowedPoPs(p.AllowedPoPs); err != nil {
		return err
	}
	for _, o := range p.Origins {
		if err := ValidateAllowedPoPs(o.AllowedPoPs); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if p.ProjectID != "" {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO projects (id, org_id, name, slug) VALUES ($1, 'org-default', $1, $1) ON CONFLICT (id) DO NOTHING`,
			p.ProjectID,
		)
		if err != nil {
			return fmt.Errorf("upsert project for pool: %w", err)
		}
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO origin_pools (id, project_id, name, lb_algorithm, allowed_pops)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name,
		   lb_algorithm = EXCLUDED.lb_algorithm,
		   allowed_pops = EXCLUDED.allowed_pops`,
		p.ID, p.ProjectID, p.Name, string(p.LBAlgorithm), pqStringArray(p.AllowedPoPs),
	)
	if err != nil {
		return fmt.Errorf("upsert origin pool: %w", err)
	}

	// Delete and re-insert origins within transaction
	if _, err := tx.ExecContext(ctx, "DELETE FROM origins WHERE pool_id = $1", p.ID); err != nil {
		return fmt.Errorf("delete existing origins for pool: %w", err)
	}
	for _, o := range p.Origins {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO origins (id, pool_id, address, port, protocol, weight, healthy, allowed_pops, sni, ca_bundle_path)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			o.ID, p.ID, o.Address, o.Port, string(o.Protocol), o.Weight, o.Healthy,
			pqStringArray(o.AllowedPoPs), o.SNI, o.CABundlePath,
		)
		if err != nil {
			return fmt.Errorf("insert origin in tx: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit origin pool tx: %w", err)
	}

	return r.cache.SaveOriginPool(p)
}

func (r *PostgresRepository) SaveOriginPoolBypass(p *model.OriginPool) error {
	return r.SaveOriginPool(p)
}

func (r *PostgresRepository) AddOrigin(o *model.Origin) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO origins (id, pool_id, address, port, protocol, weight, healthy, allowed_pops, sni, ca_bundle_path)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (id) DO UPDATE SET
		   address = EXCLUDED.address,
		   port = EXCLUDED.port,
		   protocol = EXCLUDED.protocol,
		   weight = EXCLUDED.weight,
		   healthy = EXCLUDED.healthy,
		   allowed_pops = EXCLUDED.allowed_pops,
		   sni = EXCLUDED.sni,
		   ca_bundle_path = EXCLUDED.ca_bundle_path`,
		o.ID, o.PoolID, o.Address, o.Port, string(o.Protocol), o.Weight, o.Healthy,
		pqStringArray(o.AllowedPoPs), o.SNI, o.CABundlePath,
	)
	if err != nil {
		return fmt.Errorf("upsert origin: %w", err)
	}

	return r.cache.AddOrigin(o)
}

func (r *PostgresRepository) GetOriginPool(poolID string) (*model.OriginPool, error) {
	return r.cache.GetOriginPool(poolID)
}

// -------------------------------------------------------------------------
// Health Monitoring
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveHealthMonitor(hm *model.HealthMonitor) error {
	if hm == nil {
		return errors.New("health monitor cannot be nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	statusCodes := hm.ExpectedStatusCodes
	if len(statusCodes) == 0 {
		statusCodes = []int{200}
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO health_monitors (id, pool_id, protocol, path, port, interval_seconds, timeout_seconds, healthy_threshold, unhealthy_threshold, expected_status_codes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (pool_id) DO UPDATE SET
		   protocol = EXCLUDED.protocol,
		   path = EXCLUDED.path,
		   port = EXCLUDED.port,
		   interval_seconds = EXCLUDED.interval_seconds,
		   timeout_seconds = EXCLUDED.timeout_seconds,
		   healthy_threshold = EXCLUDED.healthy_threshold,
		   unhealthy_threshold = EXCLUDED.unhealthy_threshold,
		   expected_status_codes = EXCLUDED.expected_status_codes`,
		hm.ID, hm.PoolID, string(hm.Protocol), hm.Path, hm.Port,
		hm.IntervalSeconds, hm.TimeoutSeconds, hm.HealthyThreshold, hm.UnhealthyThreshold,
		pq.Array(statusCodes),
	)
	if err != nil {
		return fmt.Errorf("persist health monitor: %w", err)
	}

	return r.cache.SaveHealthMonitor(hm)
}

func (r *PostgresRepository) GetHealthMonitor(poolID string) *model.HealthMonitor {
	return r.cache.GetHealthMonitor(poolID)
}

func (r *PostgresRepository) SaveOriginHealthState(st *model.OriginEndpointState) error {
	return r.cache.SaveOriginHealthState(st)
}

func (r *PostgresRepository) GetOriginHealthState(originID string) *model.OriginEndpointState {
	return r.cache.GetOriginHealthState(originID)
}

func (r *PostgresRepository) ListPoolHealthStates(poolID string) []*model.OriginEndpointState {
	return r.cache.ListPoolHealthStates(poolID)
}

func (r *PostgresRepository) UpdateOriginHealthy(originID string, healthy bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "UPDATE origins SET healthy = $1 WHERE id = $2", healthy, originID)
	if err != nil {
		return fmt.Errorf("update origin healthy: %w", err)
	}
	return r.cache.UpdateOriginHealthy(originID, healthy)
}

// -------------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveRoute(rt *model.Route) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO routes (id, domain_id, pool_id, path_prefix, priority, timeout_ms)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO UPDATE SET
		   domain_id = EXCLUDED.domain_id,
		   pool_id = EXCLUDED.pool_id,
		   path_prefix = EXCLUDED.path_prefix,
		   priority = EXCLUDED.priority,
		   timeout_ms = EXCLUDED.timeout_ms`,
		rt.ID, rt.DomainID, rt.PoolID, rt.PathPrefix, rt.Priority, rt.TimeoutMs,
	)
	if err != nil {
		return fmt.Errorf("persist route: %w", err)
	}

	return r.cache.SaveRoute(rt)
}

func (r *PostgresRepository) GetRoutes(domainID string) []*model.Route {
	return r.cache.GetRoutes(domainID)
}

// -------------------------------------------------------------------------
// Security Policies & WAF
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveSecurityPolicy(sp *model.SecurityPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	wafJSON, err := json.Marshal(sp.WAFRules)
	if err != nil {
		return fmt.Errorf("marshal waf rules: %w", err)
	}
	rlJSON, err := json.Marshal(sp.RateLimitRules)
	if err != nil {
		return fmt.Errorf("marshal rate limit rules: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO security_policies (id, domain_id, waf_enabled, waf_mode, rate_limit_enabled, rate_limit_rpm, waf_rules_json, rate_limit_rules_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (domain_id) DO UPDATE SET
		   waf_enabled = EXCLUDED.waf_enabled,
		   waf_mode = EXCLUDED.waf_mode,
		   rate_limit_enabled = EXCLUDED.rate_limit_enabled,
		   rate_limit_rpm = EXCLUDED.rate_limit_rpm,
		   waf_rules_json = EXCLUDED.waf_rules_json,
		   rate_limit_rules_json = EXCLUDED.rate_limit_rules_json`,
		sp.ID, sp.DomainID, sp.WAFEnabled, sp.WAFMode, sp.RateLimitEnabled, sp.RateLimitRPM, wafJSON, rlJSON,
	)
	if err != nil {
		return fmt.Errorf("persist security policy: %w", err)
	}

	return r.cache.SaveSecurityPolicy(sp)
}

func (r *PostgresRepository) GetSecurityPolicy(domainID string) *model.SecurityPolicy {
	return r.cache.GetSecurityPolicy(domainID)
}

func (r *PostgresRepository) AddWAFRule(domainID string, rule model.WAFRule) error {
	sp := r.cache.GetSecurityPolicy(domainID)
	if sp == nil {
		dom, _ := r.cache.GetDomain(domainID)
		if dom == nil {
			return fmt.Errorf("domain %s not found", domainID)
		}
		sp = &model.SecurityPolicy{
			ID:         "sec-" + domainID,
			DomainID:   domainID,
			WAFEnabled: true,
		}
	}
	cloned := *sp
	cloned.WAFRules = make([]model.WAFRule, len(sp.WAFRules), len(sp.WAFRules)+1)
	copy(cloned.WAFRules, sp.WAFRules)
	cloned.WAFRules = append(cloned.WAFRules, rule)
	return r.SaveSecurityPolicy(&cloned)
}

func (r *PostgresRepository) GetWAFRules(domainID string) []model.WAFRule {
	return r.cache.GetWAFRules(domainID)
}

func (r *PostgresRepository) DeleteWAFRule(domainID string, ruleID string) error {
	sp := r.cache.GetSecurityPolicy(domainID)
	if sp == nil {
		return fmt.Errorf("security policy for domain %s not found", domainID)
	}
	cloned := *sp
	cloned.WAFRules = make([]model.WAFRule, 0, len(sp.WAFRules))
	found := false
	for _, rw := range sp.WAFRules {
		if rw.ID != ruleID {
			cloned.WAFRules = append(cloned.WAFRules, rw)
		} else {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("rule %s not found", ruleID)
	}
	return r.SaveSecurityPolicy(&cloned)
}

func (r *PostgresRepository) SetRateLimitRules(domainID string, rules []model.RateLimitRule) error {
	sp := r.cache.GetSecurityPolicy(domainID)
	if sp == nil {
		dom, _ := r.cache.GetDomain(domainID)
		if dom == nil {
			return fmt.Errorf("domain %s not found", domainID)
		}
		sp = &model.SecurityPolicy{
			ID:         "sec-" + domainID,
			DomainID:   domainID,
			WAFEnabled: false,
		}
	}
	cloned := *sp
	cloned.RateLimitRules = rules
	return r.SaveSecurityPolicy(&cloned)
}

func (r *PostgresRepository) GetRateLimitRules(domainID string) []model.RateLimitRule {
	return r.cache.GetRateLimitRules(domainID)
}

func (r *PostgresRepository) RecordSecurityEvent(ev model.SecurityEvent) error {
	return r.cache.RecordSecurityEvent(ev)
}

func (r *PostgresRepository) GetSecurityEvents(domainID string, limit int) []model.SecurityEvent {
	return r.cache.GetSecurityEvents(domainID, limit)
}

// -------------------------------------------------------------------------
// Cache Policy & Rules
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveCachePolicy(cp *model.CachePolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rulesJSON, err := json.Marshal(cp.CacheRules)
	if err != nil {
		return fmt.Errorf("marshal cache rules: %w", err)
	}

	qHandling := string(cp.QueryHandling)
	if qHandling == "" {
		qHandling = "INCLUDE_ALL"
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO cache_policies (id, domain_id, cache_enabled, default_ttl_seconds, respect_origin_headers, query_handling, strip_cookies, cache_rules_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (domain_id) DO UPDATE SET
		   cache_enabled = EXCLUDED.cache_enabled,
		   default_ttl_seconds = EXCLUDED.default_ttl_seconds,
		   respect_origin_headers = EXCLUDED.respect_origin_headers,
		   query_handling = EXCLUDED.query_handling,
		   strip_cookies = EXCLUDED.strip_cookies,
		   cache_rules_json = EXCLUDED.cache_rules_json`,
		cp.ID, cp.DomainID, cp.CacheEnabled, cp.DefaultTTLSeconds, cp.RespectOriginHeaders, qHandling, cp.StripCookies, rulesJSON,
	)
	if err != nil {
		return fmt.Errorf("persist cache policy: %w", err)
	}

	return r.cache.SaveCachePolicy(cp)
}

func (r *PostgresRepository) GetCachePolicy(domainID string) *model.CachePolicy {
	return r.cache.GetCachePolicy(domainID)
}

func (r *PostgresRepository) AddCacheRule(domainID string, rule model.CacheRule) error {
	cp := r.cache.GetCachePolicy(domainID)
	if cp == nil {
		dom, _ := r.cache.GetDomain(domainID)
		if dom == nil {
			return fmt.Errorf("domain %s not found", domainID)
		}
		cp = &model.CachePolicy{
			ID:                   "cp-" + domainID,
			DomainID:             domainID,
			CacheEnabled:         true,
			DefaultTTLSeconds:    3600,
			RespectOriginHeaders: true,
			QueryHandling:        model.QueryStringIgnoreAll,
		}
	}
	cloned := *cp
	cloned.CacheRules = make([]model.CacheRule, len(cp.CacheRules), len(cp.CacheRules)+1)
	copy(cloned.CacheRules, cp.CacheRules)
	cloned.CacheRules = append(cloned.CacheRules, rule)
	return r.SaveCachePolicy(&cloned)
}

func (r *PostgresRepository) GetCacheRules(domainID string) []model.CacheRule {
	return r.cache.GetCacheRules(domainID)
}

func (r *PostgresRepository) DeleteCacheRule(domainID string, ruleID string) error {
	cp := r.cache.GetCachePolicy(domainID)
	if cp == nil {
		return fmt.Errorf("cache policy for domain %s not found", domainID)
	}
	cloned := *cp
	cloned.CacheRules = make([]model.CacheRule, 0, len(cp.CacheRules))
	found := false
	for _, rc := range cp.CacheRules {
		if rc.ID != ruleID {
			cloned.CacheRules = append(cloned.CacheRules, rc)
		} else {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("rule %s not found", ruleID)
	}
	return r.SaveCachePolicy(&cloned)
}

// -------------------------------------------------------------------------
// Certificates & ACME
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveCertificate(cert *model.Certificate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var issuedAt, expiresAt *time.Time
	if !cert.IssuedAt.IsZero() {
		issuedAt = &cert.IssuedAt
	}
	if !cert.ExpiresAt.IsZero() {
		expiresAt = &cert.ExpiresAt
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cert tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// If the new certificate is ACTIVE, supersede previous active certificates for this domain
	if cert.Status == model.CertStatusActive {
		_, err = tx.ExecContext(ctx,
			"UPDATE certificates SET status = 'SUPERSEDED' WHERE domain_id = $1 AND id != $2 AND status = 'ACTIVE'",
			cert.DomainID, cert.ID,
		)
		if err != nil {
			return fmt.Errorf("supersede prior active certificates: %w", err)
		}
	}

	storedKey := cert.PrivateKeyPEM
	if storedKey != "" && !security.IsEncrypted(storedKey) {
		enc, encErr := security.EncryptSecret(storedKey)
		if encErr != nil {
			return fmt.Errorf("encrypt certificate private key: %w", encErr)
		}
		storedKey = enc
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO certificates (id, domain_id, status, issuer, cert_sn, cert_pem, private_key_pem, fingerprint_sha256, key_type, domains, auto_renew, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (id) DO UPDATE SET
		   status = EXCLUDED.status,
		   issuer = EXCLUDED.issuer,
		   cert_sn = EXCLUDED.cert_sn,
		   cert_pem = EXCLUDED.cert_pem,
		   private_key_pem = EXCLUDED.private_key_pem,
		   fingerprint_sha256 = EXCLUDED.fingerprint_sha256,
		   key_type = EXCLUDED.key_type,
		   domains = EXCLUDED.domains,
		   auto_renew = EXCLUDED.auto_renew,
		   issued_at = EXCLUDED.issued_at,
		   expires_at = EXCLUDED.expires_at`,
		cert.ID, cert.DomainID, string(cert.Status), cert.Issuer, cert.SerialNumber,
		cert.CertPEM, storedKey, cert.FingerprintSHA256, string(cert.KeyType),
		pqStringArray(cert.Domains), cert.AutoRenew, issuedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("upsert certificate: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cert tx: %w", err)
	}

	return r.cache.SaveCertificate(cert)
}

func (r *PostgresRepository) GetCertificate(domainID string) *model.Certificate {
	return r.cache.GetCertificate(domainID)
}

func (r *PostgresRepository) GetPendingCertificate(domainID string) *model.Certificate {
	return r.cache.GetPendingCertificate(domainID)
}

func (r *PostgresRepository) SaveACMEChallenge(ch *model.ACMEChallenge) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO acme_challenges (token, id, certificate_id, domain_id, hostname, type, key_authorization, status, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (token) DO UPDATE SET
		   status = EXCLUDED.status`,
		ch.Token, ch.ID, ch.CertificateID, ch.DomainID, ch.Hostname, ch.Type, ch.KeyAuthorization, string(ch.Status), ch.CreatedAt, ch.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("persist acme challenge: %w", err)
	}

	return r.cache.SaveACMEChallenge(ch)
}

func (r *PostgresRepository) GetACMEChallengeByToken(token string) *model.ACMEChallenge {
	return r.cache.GetACMEChallengeByToken(token)
}

func (r *PostgresRepository) UpdateACMEChallengeStatus(token string, status model.ChallengeStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		"UPDATE acme_challenges SET status = $1 WHERE token = $2",
		string(status), token,
	)
	if err != nil {
		return fmt.Errorf("update acme challenge status: %w", err)
	}

	return r.cache.UpdateACMEChallengeStatus(token, status)
}

func (r *PostgresRepository) SaveTLSSettings(domainID string, settings *model.TLSSettings) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tls_settings (domain_id, enforce_https, min_tls_version, hsts, hsts_max_age)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (domain_id) DO UPDATE SET
		   enforce_https = EXCLUDED.enforce_https,
		   min_tls_version = EXCLUDED.min_tls_version,
		   hsts = EXCLUDED.hsts,
		   hsts_max_age = EXCLUDED.hsts_max_age`,
		domainID, settings.EnforceHTTPS, settings.MinTLSVersion, settings.HSTS, settings.HSTSMaxAge,
	)
	if err != nil {
		return fmt.Errorf("persist tls settings: %w", err)
	}

	return r.cache.SaveTLSSettings(domainID, settings)
}

func (r *PostgresRepository) GetTLSSettings(domainID string) *model.TLSSettings {
	return r.cache.GetTLSSettings(domainID)
}

// -------------------------------------------------------------------------
// Compiled Topologies
// -------------------------------------------------------------------------

func (r *PostgresRepository) GetActiveTopologies() []*DomainTopology {
	return r.cache.GetActiveTopologies()
}

func (r *PostgresRepository) GetActiveTopologiesForPoP(popID string) []*DomainTopology {
	return r.cache.GetActiveTopologiesForPoP(popID)
}

// -------------------------------------------------------------------------
// AI Compute Providers
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveAIProvider(p *model.AIProvider) error {
	if p == nil {
		return errors.New("provider cannot be nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	encryptedKey := p.APIKey
	if p.APIKey != "" {
		enc, encErr := security.EncryptSecret(p.APIKey)
		if encErr != nil {
			return fmt.Errorf("encrypt ai_provider secret: %w", encErr)
		}
		encryptedKey = enc
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ai_providers (
			id, project_id, name, endpoint, provider_type, api_key,
			cost_per_m_tokens, priority, sovereignty_jurisdiction,
			failover_cooldown_secs, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			endpoint = EXCLUDED.endpoint,
			provider_type = EXCLUDED.provider_type,
			api_key = EXCLUDED.api_key,
			cost_per_m_tokens = EXCLUDED.cost_per_m_tokens,
			priority = EXCLUDED.priority,
			sovereignty_jurisdiction = EXCLUDED.sovereignty_jurisdiction,
			failover_cooldown_secs = EXCLUDED.failover_cooldown_secs,
			enabled = EXCLUDED.enabled,
			updated_at = EXCLUDED.updated_at
	`, p.ID, p.ProjectID, p.Name, p.Endpoint, p.ProviderType, encryptedKey,
		p.CostPerMTokens, p.Priority, p.SovereigntyJurisdiction,
		p.FailoverCooldownSecs, p.Enabled, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("persist ai_provider: %w", err)
	}

	return r.cache.SaveAIProvider(p)
}

func (r *PostgresRepository) GetAIProvider(id string) (*model.AIProvider, error) {
	return r.cache.GetAIProvider(id)
}

func (r *PostgresRepository) ListAIProvidersByProject(projectID string) []*model.AIProvider {
	return r.cache.ListAIProvidersByProject(projectID)
}

func (r *PostgresRepository) ListAIProviders() []*model.AIProvider {
	return r.cache.ListAIProviders()
}

func (r *PostgresRepository) DeleteAIProvider(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "DELETE FROM ai_providers WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete ai_provider: %w", err)
	}

	return r.cache.DeleteAIProvider(id)
}

// -------------------------------------------------------------------------
// Tamper-Evident Audit Logs
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveAuditLog(log *model.AuditLog) error {
	if log == nil {
		return errors.New("audit log cannot be nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	detailsJSON, err := json.Marshal(log.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, org_id, project_id, actor, action, resource_type,
			resource_id, client_ip, details, prev_hash, hash, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO NOTHING
	`, log.ID, log.OrgID, log.ProjectID, log.Actor, log.Action, log.ResourceType,
		log.ResourceID, log.ClientIP, detailsJSON, log.PrevHash, log.Hash, log.CreatedAt)
	if err != nil {
		return fmt.Errorf("persist audit log: %w", err)
	}

	return r.cache.SaveAuditLog(log)
}

func (r *PostgresRepository) ListAuditLogs(projectID string, limit int, offset int) ([]*model.AuditLog, int, error) {
	return r.cache.ListAuditLogs(projectID, limit, offset)
}

func (r *PostgresRepository) GetAuditLog(id string) (*model.AuditLog, error) {
	return r.cache.GetAuditLog(id)
}

func (r *PostgresRepository) GetLastAuditHash() string {
	return r.cache.GetLastAuditHash()
}

// -------------------------------------------------------------------------
// Transactional Outbox Events (Desired-State Configuration Synchronization)
// -------------------------------------------------------------------------

// OutboxEvent represents an atomic desired-state event generated within the same
// database transaction as domain/config mutations for reliable asynchronous reconciliation.
type OutboxEvent struct {
	EventID       string     `json:"event_id"`
	AggregateType string     `json:"aggregate_type"`
	AggregateID   string     `json:"aggregate_id"`
	EventType     string     `json:"event_type"`
	Payload       []byte     `json:"payload"`
	Status        string     `json:"status"`
	RetryCount    int        `json:"retry_count"`
	CreatedAt     time.Time  `json:"created_at"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty"`
}

// GetPendingOutboxEvents retrieves unapplied outbox events ordered by creation timestamp.
func (r *PostgresRepository) GetPendingOutboxEvents(ctx context.Context, limit int) ([]*OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT event_id, aggregate_type, aggregate_id, event_type, payload, status, retry_count, created_at, processed_at
		 FROM outbox_events
		 WHERE status = 'PENDING'
		 ORDER BY created_at ASC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query pending outbox events: %w", err)
	}
	defer rows.Close()

	var events []*OutboxEvent
	for rows.Next() {
		var ev OutboxEvent
		if err := rows.Scan(&ev.EventID, &ev.AggregateType, &ev.AggregateID, &ev.EventType, &ev.Payload, &ev.Status, &ev.RetryCount, &ev.CreatedAt, &ev.ProcessedAt); err != nil {
			return nil, fmt.Errorf("scan outbox event: %w", err)
		}
		events = append(events, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate outbox events: %w", err)
	}
	return events, nil
}

// MarkOutboxEventProcessed marks an outbox event as PROCESSED.
func (r *PostgresRepository) MarkOutboxEventProcessed(ctx context.Context, eventID string) error {
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx,
		"UPDATE outbox_events SET status = 'PROCESSED', processed_at = $1 WHERE event_id = $2",
		now, eventID,
	)
	if err != nil {
		return fmt.Errorf("mark outbox event processed: %w", err)
	}
	return nil
}
