package store

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/alert"
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
	db               *sql.DB
	cache            *Store
	auditHMACKey     []byte
	reconcilerCancel context.CancelFunc
	reconcilerWg     sync.WaitGroup

	reconcileMu               sync.RWMutex
	consecutiveReconcileFails int64
	lastReconcileError        error
	lastReconcileSuccess      time.Time
	lastReconcileDuration     time.Duration
	alerter                   alert.Alerter
	reconcileAlertFailures    int64
}

var _ Repository = (*PostgresRepository)(nil)

// SetAuditHMACKey configures the HMAC signing key used for atomic chain serialization in SaveAuditLog.
func (r *PostgresRepository) SetAuditHMACKey(key []byte) {
	r.auditHMACKey = key
}

// SetAlerter wires an operational alert dispatcher for reconciler threshold notifications.
func (r *PostgresRepository) SetAlerter(a alert.Alerter) {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	r.alerter = a
}

func (r *PostgresRepository) dispatchAlertWithRetry(alerter alert.Alerter, event alert.Event) {
	if alerter == nil || !alerter.IsConfigured() {
		return
	}
	go func() {
		const maxAttempts = 3
		var lastErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := alerter.SendAlert(ctx, event)
			cancel()
			if err == nil {
				return
			}
			lastErr = err
			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt*100) * time.Millisecond)
			}
		}
		r.reconcileMu.Lock()
		r.reconcileAlertFailures++
		r.reconcileMu.Unlock()
		log.Printf("[ALERT DELIVERY ERROR] event=reconciler_alert_delivery_failed type=%s attempts=%d error=%q",
			event.Type, maxAttempts, lastErr.Error())
	}()
}

func (r *PostgresRepository) recordReconcileFailure(err error, dur time.Duration) {
	r.reconcileMu.Lock()
	r.consecutiveReconcileFails++
	count := r.consecutiveReconcileFails
	r.lastReconcileError = err
	r.lastReconcileDuration = dur
	alerter := r.alerter
	r.reconcileMu.Unlock()

	const alertThreshold = 3
	if count >= alertThreshold {
		log.Printf("[CRITICAL RECONCILER THRESHOLD EXCEEDED] event=reconcile_failure_threshold_exceeded consecutive_failures=%d threshold=%d error=%q",
			count, alertThreshold, err.Error())
		if alerter != nil && alerter.IsConfigured() {
			r.dispatchAlertWithRetry(alerter, alert.Event{
				Type:      alert.EventTypeReconcilerThresholdExceeded,
				Severity:  alert.SeverityCritical,
				Title:     fmt.Sprintf("Cache Reconciler Threshold Exceeded (%d failures)", count),
				Message:   fmt.Sprintf("Edge config-controller cache reconciliation has failed %d consecutive times. Last error: %s", count, err.Error()),
				Timestamp: time.Now().UTC(),
				Details: map[string]string{
					"consecutive_failures": strconv.FormatInt(count, 10),
					"threshold":            strconv.Itoa(alertThreshold),
					"last_error":           err.Error(),
				},
			})
		}
	}
}

// ReconcileAlertFailures returns the count of failed alert delivery attempts.
func (r *PostgresRepository) ReconcileAlertFailures() int64 {
	r.reconcileMu.RLock()
	defer r.reconcileMu.RUnlock()
	return r.reconcileAlertFailures
}

// ConsecutiveReconcileFailures returns the current count of consecutive failed cache reconciliations.
func (r *PostgresRepository) ConsecutiveReconcileFailures() int64 {
	r.reconcileMu.RLock()
	defer r.reconcileMu.RUnlock()
	return r.consecutiveReconcileFails
}

// LastReconcileError returns the last error encountered during cache reconciliation, if any.
func (r *PostgresRepository) LastReconcileError() error {
	r.reconcileMu.RLock()
	defer r.reconcileMu.RUnlock()
	return r.lastReconcileError
}

// LastReconcileSuccess returns the timestamp of the last successful cache reconciliation.
func (r *PostgresRepository) LastReconcileSuccess() time.Time {
	r.reconcileMu.RLock()
	defer r.reconcileMu.RUnlock()
	return r.lastReconcileSuccess
}

// LastReconcileDuration returns the duration of the last cache reconciliation attempt.
func (r *PostgresRepository) LastReconcileDuration() time.Duration {
	r.reconcileMu.RLock()
	defer r.reconcileMu.RUnlock()
	return r.lastReconcileDuration
}

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

// NewPostgresRepositoryFromDB initializes migrations, warms up the local cache,
// and starts the periodic background cache reconciliation loop.
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

	repo.StartReconciler(context.Background(), 1*time.Second)
	return repo, nil
}

// Close closes the underlying database pool and terminates any active background reconciler.
func (r *PostgresRepository) Close() error {
	if r.reconcilerCancel != nil {
		r.reconcilerCancel()
		r.reconcilerWg.Wait()
	}
	return r.db.Close()
}

// DB returns the underlying *sql.DB instance (primarily for tests and health verification).
func (r *PostgresRepository) DB() *sql.DB {
	return r.db
}

// Cache returns the internal in-memory *Store projection (primarily for tests and state inspection).
func (r *PostgresRepository) Cache() *Store {
	return r.cache
}

func (r *PostgresRepository) migrateSchema(ctx context.Context) error {
	// Serialize schema migrations across concurrent replicas using a dedicated connection with session advisory lock
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire dedicated migration connection: %w", err)
	}
	defer conn.Close()

	const migrationAdvisoryLockID int64 = 74291048201
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockID)
	}()

	// 0. Ensure schema_migrations table exists for versioned tracking
	_, err = conn.ExecContext(ctx, `
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
					event_id VARCHAR(128) PRIMARY KEY,
					aggregate_type VARCHAR(64) NOT NULL,
					aggregate_id VARCHAR(128) NOT NULL,
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
		{
			version: "0006_outbox_lease_and_audit_head",
			stmts: []string{
				`ALTER TABLE outbox_events ADD COLUMN IF NOT EXISTS locked_by VARCHAR(128) NOT NULL DEFAULT '';`,
				`ALTER TABLE outbox_events ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;`,
				`ALTER TABLE outbox_events ADD COLUMN IF NOT EXISTS error_message TEXT NOT NULL DEFAULT '';`,
				`CREATE INDEX IF NOT EXISTS idx_outbox_lease ON outbox_events(status, locked_until);`,
				`CREATE TABLE IF NOT EXISTS audit_chain_head (
					id INT PRIMARY KEY DEFAULT 1,
					last_hash VARCHAR(128) NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_unique_prev_hash
				 ON audit_logs(prev_hash)
				 WHERE prev_hash != '' AND prev_hash != '0000000000000000000000000000000000000000000000000000000000000000';`,
			},
		},
		{
			version: "0007_outbox_lease_token_and_audit_sequence",
			stmts: []string{
				`ALTER TABLE outbox_events ADD COLUMN IF NOT EXISTS lease_token VARCHAR(64) NOT NULL DEFAULT '';`,
				`CREATE INDEX IF NOT EXISTS idx_outbox_lease_token ON outbox_events(event_id, lease_token);`,
				`INSERT INTO audit_chain_head (id, last_hash, updated_at)
				 VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000', NOW())
				 ON CONFLICT (id) DO NOTHING;`,
				`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS sequence_num BIGSERIAL;`,
			},
		},
		{
			version: "0008_expand_outbox_identifiers",
			stmts: []string{
				`ALTER TABLE outbox_events ALTER COLUMN event_id TYPE VARCHAR(128);`,
				`ALTER TABLE outbox_events ALTER COLUMN aggregate_id TYPE VARCHAR(128);`,
			},
		},
		{
			version: "0009_edge_convergence_engine",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS edge_convergence_head (
					id INT PRIMARY KEY DEFAULT 1,
					target_version BIGINT NOT NULL DEFAULT 1,
					target_checksum VARCHAR(64) NOT NULL DEFAULT '',
					updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
				`INSERT INTO edge_convergence_head (id, target_version, target_checksum, updated_at)
				 VALUES (1, 1, '', NOW())
				 ON CONFLICT (id) DO NOTHING;`,
				`CREATE TABLE IF NOT EXISTS gateway_sync_state (
					gateway_id VARCHAR(128) PRIMARY KEY,
					pop_id VARCHAR(64) NOT NULL,
					applied_version BIGINT NOT NULL,
					applied_checksum VARCHAR(64) NOT NULL,
					target_version BIGINT NOT NULL,
					target_checksum VARCHAR(64) NOT NULL,
					status VARCHAR(32) NOT NULL,
					last_error TEXT NOT NULL DEFAULT '',
					last_ack_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					convergence_lag_ms BIGINT NOT NULL DEFAULT 0
				);`,
				`CREATE INDEX IF NOT EXISTS idx_gateway_sync_pop ON gateway_sync_state(pop_id);`,
				`CREATE INDEX IF NOT EXISTS idx_gateway_sync_status ON gateway_sync_state(status);`,
			},
		},
		{
			version: "0010_pop_snapshot_convergence",
			stmts: []string{
				`CREATE TABLE IF NOT EXISTS pop_snapshot_heads (
					pop_id VARCHAR(64) PRIMARY KEY,
					target_version BIGINT NOT NULL,
					target_checksum VARCHAR(64) NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);`,
			},
		},
	}

	for _, m := range migrations {
		var exists bool
		err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", m.version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration version %s: %w", m.version, err)
		}
		if exists {
			continue
		}

		tx, err := conn.BeginTx(ctx, nil)
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
	domRows, err := r.db.QueryContext(ctx, "SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains")
	if err != nil {
		return fmt.Errorf("query domains: %w", err)
	}
	defer domRows.Close()
	for domRows.Next() {
		var d model.Domain
		var pops pq.StringArray
		if err := domRows.Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version); err != nil {
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

	// 13. Edge Convergence Head
	var targetVersion int64
	var targetChecksum string
	var headUpdatedAt time.Time
	err = r.db.QueryRowContext(ctx, "SELECT target_version, target_checksum, updated_at FROM edge_convergence_head WHERE id = 1").Scan(&targetVersion, &targetChecksum, &headUpdatedAt)
	if err == nil {
		_ = r.cache.SaveEdgeConvergenceHead(ctx, targetVersion, targetChecksum)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("query edge_convergence_head: %w", err)
	}

	// 14. Gateway Sync State
	gwRows, err := r.db.QueryContext(ctx, "SELECT gateway_id, pop_id, applied_version, applied_checksum, target_version, target_checksum, status, last_error, last_ack_at, convergence_lag_ms FROM gateway_sync_state")
	if err != nil {
		return fmt.Errorf("query gateway_sync_state: %w", err)
	}
	defer gwRows.Close()
	for gwRows.Next() {
		var rec model.GatewaySyncRecord
		var statusStr string
		if err := gwRows.Scan(&rec.GatewayID, &rec.PoPID, &rec.AppliedVersion, &rec.AppliedChecksum, &rec.TargetVersion, &rec.TargetChecksum, &statusStr, &rec.LastError, &rec.LastAckAt, &rec.ConvergenceLagMs); err != nil {
			return fmt.Errorf("scan gateway_sync_state: %w", err)
		}
		rec.Status = model.GatewaySyncStatus(statusStr)
		if rec.TargetVersion > rec.AppliedVersion {
			rec.VersionLag = rec.TargetVersion - rec.AppliedVersion
		}
		_ = r.cache.SaveGatewaySyncRecord(ctx, &rec)
	}
	if err := gwRows.Err(); err != nil {
		return fmt.Errorf("iterate gateway_sync_state: %w", err)
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

	var newVersion int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO domains (id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1)
		 ON CONFLICT (id) DO UPDATE SET
		   hostname = EXCLUDED.hostname,
		   status = EXCLUDED.status,
		   onboarding_type = EXCLUDED.onboarding_type,
		   cname_target = EXCLUDED.cname_target,
		   allowed_pops = EXCLUDED.allowed_pops,
		   updated_at = EXCLUDED.updated_at,
		   version = domains.version + 1
		 RETURNING version`,
		d.ID, d.ProjectID, d.Hostname, string(d.Status), d.OnboardingType, d.CNAMETarget,
		pqStringArray(d.AllowedPoPs), createdAt, now,
	).Scan(&newVersion)
	if err != nil {
		return fmt.Errorf("upsert domain: %w", err)
	}
	d.Version = newVersion

	eventID := generateOutboxEventID("dom", d.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":       d.ID,
		"project_id":      d.ProjectID,
		"hostname":        d.Hostname,
		"status":          string(d.Status),
		"onboarding_type": d.OnboardingType,
		"cname_target":    d.CNAMETarget,
		"allowed_pops":    d.AllowedPoPs,
		"version":         d.Version,
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
	d, err := r.getDomainFromDB(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = r.cache.DeleteDomain(id)
		}
		return nil, err
	}
	return d, nil
}

func (r *PostgresRepository) GetDomainByHost(hostname string) (*model.Domain, error) {
	d, err := r.getDomainByHostFromDB(hostname)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if cached, _ := r.cache.GetDomainByHost(hostname); cached != nil {
				_ = r.cache.DeleteDomain(cached.ID)
			}
		}
		return nil, err
	}
	return d, nil
}

func (r *PostgresRepository) getDomainFromDB(id string) (*model.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var d model.Domain
	var pops pq.StringArray
	err := r.db.QueryRowContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains WHERE id = $1",
		id,
	).Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version)
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
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains WHERE hostname = $1",
		hostname,
	).Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains WHERE project_id = $1 ORDER BY created_at ASC",
		projectID,
	)
	if err != nil {
		return r.cache.ListDomainsByProject(projectID)
	}
	defer rows.Close()

	activeIDs := make(map[string]bool)
	domains := make([]*model.Domain, 0)
	for rows.Next() {
		var d model.Domain
		var pops pq.StringArray
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version); err != nil {
			return r.cache.ListDomainsByProject(projectID)
		}
		d.AllowedPoPs = []string(pops)
		domains = append(domains, &d)
		activeIDs[d.ID] = true
		_ = r.cache.SaveDomain(&d)
	}
	if err := rows.Err(); err != nil {
		return r.cache.ListDomainsByProject(projectID)
	}

	// Prune cached domains for this project that are no longer active in database
	for _, cd := range r.cache.ListDomainsByProject(projectID) {
		if !activeIDs[cd.ID] {
			_ = r.cache.DeleteDomain(cd.ID)
		}
	}

	return domains
}

func (r *PostgresRepository) ListDomains() []*model.Domain {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains ORDER BY created_at ASC",
	)
	if err != nil {
		return r.cache.ListDomains()
	}
	defer rows.Close()

	activeIDs := make(map[string]bool)
	domains := make([]*model.Domain, 0)
	for rows.Next() {
		var d model.Domain
		var pops pq.StringArray
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version); err != nil {
			return r.cache.ListDomains()
		}
		d.AllowedPoPs = []string(pops)
		domains = append(domains, &d)
		activeIDs[d.ID] = true
		_ = r.cache.SaveDomain(&d)
	}
	if err := rows.Err(); err != nil {
		return r.cache.ListDomains()
	}

	// Prune all cached domains that are no longer active in database
	for _, cd := range r.cache.ListDomains() {
		if !activeIDs[cd.ID] {
			_ = r.cache.DeleteDomain(cd.ID)
		}
	}

	return domains
}

func (r *PostgresRepository) UpdateDomainStatus(id string, status model.DomainStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var newVersion int
	err = tx.QueryRowContext(ctx,
		"UPDATE domains SET status = $1, version = version + 1, updated_at = NOW() WHERE id = $2 RETURNING version",
		string(status), id,
	).Scan(&newVersion)
	if err != nil {
		return fmt.Errorf("update domain status: %w", err)
	}

	eventID := generateOutboxEventID("status", id)
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

	eventID := generateOutboxEventID("del", domainID)
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

// CacheReconciliationStats captures metrics and observability telemetry from a cache synchronization pass.
type CacheReconciliationStats struct {
	ActiveDomains  int           `json:"active_domains"`
	EvictedDomains int           `json:"evicted_domains"`
	UpdatedDomains int           `json:"updated_domains"`
	Duration       time.Duration `json:"duration"`
	MaxLag         time.Duration `json:"max_lag"`
}

// ReconcileCache reconciles the local in-memory cache projection against authoritative
// PostgreSQL system-of-record state, evicting any stale domains deleted by other replicas
// and synchronizing version-advanced configurations.
func (r *PostgresRepository) ReconcileCache(ctx context.Context) (stats *CacheReconciliationStats, err error) {
	start := time.Now()
	defer func() {
		dur := time.Since(start)
		if err != nil {
			r.recordReconcileFailure(err, dur)
		} else {
			r.reconcileMu.Lock()
			previousFails := r.consecutiveReconcileFails
			r.consecutiveReconcileFails = 0
			r.lastReconcileError = nil
			r.lastReconcileSuccess = time.Now().UTC()
			r.lastReconcileDuration = dur
			alerter := r.alerter
			r.reconcileMu.Unlock()

			if previousFails >= 3 && alerter != nil && alerter.IsConfigured() {
				r.dispatchAlertWithRetry(alerter, alert.Event{
					Type:      alert.EventTypeReconcilerRecovered,
					Severity:  alert.SeverityInfo,
					Title:     "Cache Reconciler Recovered",
					Message:   fmt.Sprintf("Edge config-controller cache reconciliation recovered after %d consecutive failures", previousFails),
					Timestamp: time.Now().UTC(),
					Details: map[string]string{
						"previous_failures": strconv.FormatInt(previousFails, 10),
						"duration_ms":       strconv.FormatInt(dur.Milliseconds(), 10),
					},
				})
			}
		}
	}()

	// Use a single REPEATABLE READ read-only transaction to ensure an atomic, point-in-time
	// MVCC snapshot across all configuration tables (domains, routes, pools, origins, certs, policies).
	// Prevents cross-table inconsistencies caused by concurrent mutations during reconciliation.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile cache begin repeatable read tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Stage Active Domains
	rows, err := tx.QueryContext(ctx,
		"SELECT id, project_id, hostname, status, onboarding_type, cname_target, allowed_pops, created_at, updated_at, version FROM domains",
	)
	if err != nil {
		return nil, fmt.Errorf("reconcile cache query domains: %w", err)
	}
	defer rows.Close()

	activeDBMap := make(map[string]*model.Domain)
	var latestUpdate time.Time

	for rows.Next() {
		var d model.Domain
		var pops pq.StringArray
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.Hostname, &d.Status, &d.OnboardingType, &d.CNAMETarget, &pops, &d.CreatedAt, &d.UpdatedAt, &d.Version); err != nil {
			return nil, fmt.Errorf("reconcile cache scan domain: %w", err)
		}
		d.AllowedPoPs = []string(pops)
		activeDBMap[d.ID] = &d
		if d.UpdatedAt.After(latestUpdate) {
			latestUpdate = d.UpdatedAt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile cache iterate domains: %w", err)
	}

	// 2. Stage Routes for active domains
	stagedRoutesByDomain := make(map[string][]*model.Route)
	routeRows, err := tx.QueryContext(ctx, "SELECT id, domain_id, pool_id, path_prefix, priority, timeout_ms FROM routes ORDER BY priority DESC")
	if err != nil {
		return nil, fmt.Errorf("reconcile cache query routes: %w", err)
	}
	defer routeRows.Close()

	for routeRows.Next() {
		var rt model.Route
		if err := routeRows.Scan(&rt.ID, &rt.DomainID, &rt.PoolID, &rt.PathPrefix, &rt.Priority, &rt.TimeoutMs); err != nil {
			return nil, fmt.Errorf("reconcile cache scan route: %w", err)
		}
		stagedRoutesByDomain[rt.DomainID] = append(stagedRoutesByDomain[rt.DomainID], &rt)
	}
	if err := routeRows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile cache iterate routes: %w", err)
	}

	// 3. Stage Origin Pools and Origins
	poolRows, err := tx.QueryContext(ctx, "SELECT id, project_id, name, lb_algorithm, allowed_pops FROM origin_pools")
	if err != nil {
		return nil, fmt.Errorf("reconcile cache query origin pools: %w", err)
	}

	var stagedPools []*model.OriginPool
	for poolRows.Next() {
		var p model.OriginPool
		var pops pq.StringArray
		if err := poolRows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.LBAlgorithm, &pops); err != nil {
			poolRows.Close()
			return nil, fmt.Errorf("reconcile cache scan origin pool: %w", err)
		}
		p.AllowedPoPs = []string(pops)
		stagedPools = append(stagedPools, &p)
	}
	if err := poolRows.Err(); err != nil {
		poolRows.Close()
		return nil, fmt.Errorf("reconcile cache iterate origin pools: %w", err)
	}
	poolRows.Close()

	// Query all origins in a single bulk query on the same transaction connection
	origRows, errOrig := tx.QueryContext(ctx, "SELECT id, pool_id, address, port, protocol, weight, healthy, allowed_pops, sni, ca_bundle_path FROM origins")
	if errOrig != nil {
		return nil, fmt.Errorf("reconcile cache query origins: %w", errOrig)
	}

	originsByPool := make(map[string][]model.Origin)
	for origRows.Next() {
		var o model.Origin
		var opops pq.StringArray
		if err := origRows.Scan(&o.ID, &o.PoolID, &o.Address, &o.Port, &o.Protocol, &o.Weight, &o.Healthy, &opops, &o.SNI, &o.CABundlePath); err != nil {
			origRows.Close()
			return nil, fmt.Errorf("reconcile cache scan origin: %w", err)
		}
		o.AllowedPoPs = []string(opops)
		originsByPool[o.PoolID] = append(originsByPool[o.PoolID], o)
	}
	if err := origRows.Err(); err != nil {
		origRows.Close()
		return nil, fmt.Errorf("reconcile cache iterate origins: %w", err)
	}
	origRows.Close()

	for _, p := range stagedPools {
		if origins, ok := originsByPool[p.ID]; ok {
			p.Origins = origins
		}
	}

	// 4. Stage Active Certificates
	certRows, err := tx.QueryContext(ctx, "SELECT id, domain_id, status, issuer, cert_sn, cert_pem, private_key_pem, fingerprint_sha256, key_type, domains, auto_renew, issued_at, expires_at FROM certificates WHERE status = 'ACTIVE'")
	if err != nil {
		return nil, fmt.Errorf("reconcile cache query certificates: %w", err)
	}
	defer certRows.Close()

	var stagedCerts []*model.Certificate
	for certRows.Next() {
		var cert model.Certificate
		var domains pq.StringArray
		var encKey string
		var issuedAt, expiresAt sql.NullTime
		if err := certRows.Scan(&cert.ID, &cert.DomainID, &cert.Status, &cert.Issuer, &cert.SerialNumber, &cert.CertPEM, &encKey, &cert.FingerprintSHA256, &cert.KeyType, &domains, &cert.AutoRenew, &issuedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("reconcile cache scan certificate: %w", err)
		}
		cert.Domains = []string(domains)
		if issuedAt.Valid {
			cert.IssuedAt = issuedAt.Time
		}
		if expiresAt.Valid {
			cert.ExpiresAt = expiresAt.Time
		}
		if encKey != "" {
			dec, decErr := security.DecryptSecret(encKey)
			if decErr != nil {
				log.Printf("[SECURITY ALERT] event=secret_decryption_failure category=certificate_private_key domain_id=%s cert_id=%s error=%q", cert.DomainID, cert.ID, decErr.Error())
				return nil, fmt.Errorf("reconcile cache decrypt private key for certificate %s (domain %s): %w", cert.ID, cert.DomainID, decErr)
			}
			cert.PrivateKeyPEM = dec
		}
		stagedCerts = append(stagedCerts, &cert)
	}
	if err := certRows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile cache iterate certificates: %w", err)
	}

	// 5. Stage Active Security Policies
	spRows, err := tx.QueryContext(ctx, "SELECT id, domain_id, waf_enabled, waf_mode, rate_limit_enabled, rate_limit_rpm, waf_rules_json, rate_limit_rules_json FROM security_policies")
	if err != nil {
		return nil, fmt.Errorf("reconcile cache query security policies: %w", err)
	}
	defer spRows.Close()

	var stagedPolicies []*model.SecurityPolicy
	for spRows.Next() {
		var sp model.SecurityPolicy
		var wafJSON, rlJSON []byte
		if err := spRows.Scan(&sp.ID, &sp.DomainID, &sp.WAFEnabled, &sp.WAFMode, &sp.RateLimitEnabled, &sp.RateLimitRPM, &wafJSON, &rlJSON); err != nil {
			return nil, fmt.Errorf("reconcile cache scan security policy: %w", err)
		}
		if len(wafJSON) > 0 {
			if err := json.Unmarshal(wafJSON, &sp.WAFRules); err != nil {
				return nil, fmt.Errorf("reconcile cache unmarshal waf rules for domain %s: %w", sp.DomainID, err)
			}
		}
		if len(rlJSON) > 0 {
			if err := json.Unmarshal(rlJSON, &sp.RateLimitRules); err != nil {
				return nil, fmt.Errorf("reconcile cache unmarshal rate limit rules for domain %s: %w", sp.DomainID, err)
			}
		}
		stagedPolicies = append(stagedPolicies, &sp)
	}
	if err := spRows.Err(); err != nil {
		return nil, fmt.Errorf("reconcile cache iterate security policies: %w", err)
	}

	// Commit the read-only transaction to close the MVCC snapshot
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("reconcile cache commit tx: %w", err)
	}

	// =========================================================================
	// ATOMIC APPLY PHASE: All PostgreSQL queries and deserializations succeeded!
	// Swap the entire candidate state into in-memory cache under a single lock,
	// cleanly evicting deleted domains, routes, pools, certificates, and policies.
	// =========================================================================
	stagedPoolsMap := make(map[string]*model.OriginPool, len(stagedPools))
	for _, p := range stagedPools {
		stagedPoolsMap[p.ID] = p
	}
	stagedCertsMap := make(map[string]*model.Certificate, len(stagedCerts))
	for _, c := range stagedCerts {
		stagedCertsMap[c.DomainID] = c
	}
	stagedPoliciesMap := make(map[string]*model.SecurityPolicy, len(stagedPolicies))
	for _, sp := range stagedPolicies {
		stagedPoliciesMap[sp.DomainID] = sp
	}

	snap := &ReconciliationSnapshot{
		Domains:          activeDBMap,
		RoutesByDomain:   stagedRoutesByDomain,
		Pools:            stagedPoolsMap,
		Certificates:     stagedCertsMap,
		SecurityPolicies: stagedPoliciesMap,
	}

	// Calculate evicted and updated domains by comparing current cache with authoritative DB snapshot
	cachedDomains := r.cache.ListDomains()
	var evictedDomains int
	for _, cd := range cachedDomains {
		if _, exists := activeDBMap[cd.ID]; !exists {
			evictedDomains++
		}
	}

	var updatedDomains int
	for _, dbDom := range activeDBMap {
		cached, err := r.cache.GetDomain(dbDom.ID)
		if err != nil || cached == nil {
			updatedDomains++
		} else if dbDom.Version > cached.Version || dbDom.Status != cached.Status || dbDom.Hostname != cached.Hostname {
			updatedDomains++
		}
	}

	if err := r.cache.ApplyReconciliationSnapshot(snap); err != nil {
		return nil, fmt.Errorf("apply reconciliation snapshot to cache: %w", err)
	}

	stats = &CacheReconciliationStats{
		ActiveDomains:  len(activeDBMap),
		EvictedDomains: evictedDomains,
		UpdatedDomains: updatedDomains,
		Duration:       time.Since(start),
	}
	if !latestUpdate.IsZero() {
		stats.MaxLag = time.Since(latestUpdate)
	}

	return stats, nil
}

// StartReconciler launches a background synchronization loop that periodically reconciles
// local cache projections against authoritative PostgreSQL state at the specified interval.
// Returns a stop cancellation function.
func (r *PostgresRepository) StartReconciler(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	reconcileCtx, cancel := context.WithCancel(ctx)
	r.reconcilerCancel = cancel

	r.reconcilerWg.Add(1)
	go func() {
		defer r.reconcilerWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-reconcileCtx.Done():
				return
			case <-ticker.C:
				reconcileTimeoutCtx, tCancel := context.WithTimeout(reconcileCtx, 5*time.Second)
				if _, recErr := r.ReconcileCache(reconcileTimeoutCtx); recErr != nil {
					log.Printf("[RECONCILER ERROR] event=periodic_reconciliation_failed consecutive_failures=%d error=%q",
						r.ConsecutiveReconcileFailures(), recErr.Error())
				}
				tCancel()
			}
		}
	}()

	return cancel
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

	eventID := generateOutboxEventID("pool", p.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"pool_id":      p.ID,
		"project_id":   p.ProjectID,
		"name":         p.Name,
		"lb_algorithm": string(p.LBAlgorithm),
		"allowed_pops": p.AllowedPoPs,
		"origin_count": len(p.Origins),
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'pool', $2, 'pool.config.changed', $3, 'PENDING')`,
		eventID, p.ID, payloadJSON,
	)

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
	if p, err := r.cache.GetOriginPool(poolID); err == nil && p != nil {
		return p, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var p model.OriginPool
	var pops pq.StringArray
	err := r.db.QueryRowContext(ctx,
		"SELECT id, project_id, name, lb_algorithm, allowed_pops FROM origin_pools WHERE id = $1",
		poolID,
	).Scan(&p.ID, &p.ProjectID, &p.Name, &p.LBAlgorithm, &pops)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query origin pool %s: %w", poolID, err)
	}
	p.AllowedPoPs = []string(pops)

	origRows, err := r.db.QueryContext(ctx,
		"SELECT id, pool_id, address, port, protocol, weight, healthy, allowed_pops, sni, ca_bundle_path FROM origins WHERE pool_id = $1",
		poolID,
	)
	if err == nil {
		defer origRows.Close()
		for origRows.Next() {
			var o model.Origin
			var opops pq.StringArray
			if err := origRows.Scan(&o.ID, &o.PoolID, &o.Address, &o.Port, &o.Protocol, &o.Weight, &o.Healthy, &opops, &o.SNI, &o.CABundlePath); err == nil {
				o.AllowedPoPs = []string(opops)
				p.Origins = append(p.Origins, o)
			}
		}
	}

	var hm model.HealthMonitor
	var codes pq.Int64Array
	if err := r.db.QueryRowContext(ctx,
		"SELECT id, pool_id, protocol, path, port, interval_seconds, timeout_seconds, healthy_threshold, unhealthy_threshold, expected_status_codes FROM health_monitors WHERE pool_id = $1",
		poolID,
	).Scan(&hm.ID, &hm.PoolID, &hm.Protocol, &hm.Path, &hm.Port, &hm.IntervalSeconds, &hm.TimeoutSeconds, &hm.HealthyThreshold, &hm.UnhealthyThreshold, &codes); err == nil {
		for _, c := range codes {
			hm.ExpectedStatusCodes = append(hm.ExpectedStatusCodes, int(c))
		}
		p.HealthMonitor = &hm
		_ = r.cache.SaveHealthMonitor(&hm)
	}

	_ = r.cache.SaveOriginPool(&p)
	return &p, nil
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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
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

	eventID := generateOutboxEventID("route", rt.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"route_id":    rt.ID,
		"domain_id":   rt.DomainID,
		"pool_id":     rt.PoolID,
		"path_prefix": rt.PathPrefix,
		"priority":    rt.Priority,
		"timeout_ms":  rt.TimeoutMs,
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'route', $2, 'route.config.changed', $3, 'PENDING')`,
		eventID, rt.ID, payloadJSON,
	)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route tx: %w", err)
	}

	return r.cache.SaveRoute(rt)
}

func (r *PostgresRepository) GetRoutes(domainID string) []*model.Route {
	// First ensure domain exists authoritatively in PostgreSQL (P1 Multi-Replica Stale Eviction)
	if _, err := r.getDomainFromDB(domainID); err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = r.cache.DeleteDomain(domainID)
		}
		return nil
	}

	cached := r.cache.GetRoutes(domainID)
	if len(cached) > 0 {
		return cached
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, domain_id, pool_id, path_prefix, priority, timeout_ms FROM routes WHERE domain_id = $1 ORDER BY priority DESC",
		domainID,
	)
	if err != nil {
		return cached
	}
	defer rows.Close()

	var dbRoutes []*model.Route
	for rows.Next() {
		var rt model.Route
		if err := rows.Scan(&rt.ID, &rt.DomainID, &rt.PoolID, &rt.PathPrefix, &rt.Priority, &rt.TimeoutMs); err == nil {
			dbRoutes = append(dbRoutes, &rt)
		}
	}
	r.cache.SetRoutes(domainID, dbRoutes)
	return dbRoutes
}

// -------------------------------------------------------------------------
// Security Policies & WAF
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveSecurityPolicy(sp *model.SecurityPolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin security policy tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	wafJSON, err := json.Marshal(sp.WAFRules)
	if err != nil {
		return fmt.Errorf("marshal waf rules: %w", err)
	}
	rlJSON, err := json.Marshal(sp.RateLimitRules)
	if err != nil {
		return fmt.Errorf("marshal rate limit rules: %w", err)
	}

	_, err = tx.ExecContext(ctx,
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

	eventID := generateOutboxEventID("sec", sp.DomainID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"security_policy_id": sp.ID,
		"domain_id":          sp.DomainID,
		"waf_enabled":        sp.WAFEnabled,
		"waf_mode":           sp.WAFMode,
		"rate_limit_enabled": sp.RateLimitEnabled,
		"rate_limit_rpm":     sp.RateLimitRPM,
		"updated_at":         time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'security_policy', $2, 'security.policy.changed', $3, 'PENDING')`,
		eventID, sp.DomainID, payloadJSON,
	)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit security policy tx: %w", err)
	}

	return r.cache.SaveSecurityPolicy(sp)
}

func (r *PostgresRepository) GetSecurityPolicy(domainID string) *model.SecurityPolicy {
	if sp := r.cache.GetSecurityPolicy(domainID); sp != nil {
		return sp
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sp model.SecurityPolicy
	var wafJSON, rlJSON []byte
	err := r.db.QueryRowContext(ctx,
		"SELECT id, domain_id, waf_enabled, waf_mode, rate_limit_enabled, rate_limit_rpm, waf_rules_json, rate_limit_rules_json FROM security_policies WHERE domain_id = $1",
		domainID,
	).Scan(&sp.ID, &sp.DomainID, &sp.WAFEnabled, &sp.WAFMode, &sp.RateLimitEnabled, &sp.RateLimitRPM, &wafJSON, &rlJSON)
	if err != nil {
		return nil
	}

	if len(wafJSON) > 0 {
		_ = json.Unmarshal(wafJSON, &sp.WAFRules)
	}
	if len(rlJSON) > 0 {
		_ = json.Unmarshal(rlJSON, &sp.RateLimitRules)
	}
	_ = r.cache.SaveSecurityPolicy(&sp)
	return &sp
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

	eventID := generateOutboxEventID("cert", cert.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"certificate_id": cert.ID,
		"cert_id":        cert.ID,
		"domain_id":      cert.DomainID,
		"status":         string(cert.Status),
		"domains":        cert.Domains,
		"updated_at":     time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'certificate', $2, 'certificate.changed', $3, 'PENDING')`,
		eventID, cert.DomainID, payloadJSON,
	)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cert tx: %w", err)
	}

	return r.cache.SaveCertificate(cert)
}

func (r *PostgresRepository) GetCertificate(domainID string) *model.Certificate {
	if cert := r.cache.GetCertificate(domainID); cert != nil {
		return cert
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var cert model.Certificate
	var domains pq.StringArray
	var encKey string
	var issuedAt, expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx,
		"SELECT id, domain_id, status, issuer, cert_sn, cert_pem, private_key_pem, fingerprint_sha256, key_type, domains, auto_renew, issued_at, expires_at FROM certificates WHERE domain_id = $1 AND status = 'ACTIVE' ORDER BY expires_at DESC LIMIT 1",
		domainID,
	).Scan(
		&cert.ID, &cert.DomainID, &cert.Status, &cert.Issuer, &cert.SerialNumber,
		&cert.CertPEM, &encKey, &cert.FingerprintSHA256, &cert.KeyType,
		&domains, &cert.AutoRenew, &issuedAt, &expiresAt,
	)
	if err != nil {
		return nil
	}

	cert.Domains = []string(domains)
	if issuedAt.Valid {
		cert.IssuedAt = issuedAt.Time
	}
	if expiresAt.Valid {
		cert.ExpiresAt = expiresAt.Time
	}

	if encKey != "" {
		dec, decErr := security.DecryptSecret(encKey)
		if decErr != nil {
			log.Printf("[SECURITY ALERT] event=secret_decryption_failure category=certificate_private_key domain_id=%s cert_id=%s error=%q", domainID, cert.ID, decErr.Error())
			return nil
		}
		cert.PrivateKeyPEM = dec
	}
	_ = r.cache.SaveCertificate(&cert)
	return &cert
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
	if settings := r.cache.GetTLSSettings(domainID); settings != nil {
		return settings
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var st model.TLSSettings
	err := r.db.QueryRowContext(ctx,
		"SELECT enforce_https, min_tls_version, hsts, hsts_max_age FROM tls_settings WHERE domain_id = $1",
		domainID,
	).Scan(
		&st.EnforceHTTPS, &st.MinTLSVersion, &st.HSTS, &st.HSTSMaxAge,
	)
	if err != nil {
		return nil
	}
	_ = r.cache.SaveTLSSettings(domainID, &st)
	return &st
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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin ai provider tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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

	_, err = tx.ExecContext(ctx, `
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

	eventID := generateOutboxEventID("ai", p.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"provider_id":   p.ID,
		"project_id":    p.ProjectID,
		"name":          p.Name,
		"provider_type": string(p.ProviderType),
		"enabled":       p.Enabled,
		"updated_at":    now.Format(time.RFC3339),
	})
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO outbox_events (event_id, aggregate_type, aggregate_id, event_type, payload, status)
		 VALUES ($1, 'ai_provider', $2, 'ai_provider.changed', $3, 'PENDING')`,
		eventID, p.ID, payloadJSON,
	)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit ai provider tx: %w", err)
	}

	return r.cache.SaveAIProvider(p)
}

func (r *PostgresRepository) GetAIProvider(id string) (*model.AIProvider, error) {
	if p, err := r.cache.GetAIProvider(id); err == nil && p != nil {
		return p, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var p model.AIProvider
	var encryptedKey string
	err := r.db.QueryRowContext(ctx,
		"SELECT id, project_id, name, endpoint, provider_type, api_key, cost_per_m_tokens, priority, sovereignty_jurisdiction, failover_cooldown_secs, enabled, created_at, updated_at FROM ai_providers WHERE id = $1",
		id,
	).Scan(
		&p.ID, &p.ProjectID, &p.Name, &p.Endpoint, &p.ProviderType, &encryptedKey,
		&p.CostPerMTokens, &p.Priority, &p.SovereigntyJurisdiction,
		&p.FailoverCooldownSecs, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query ai_provider %s: %w", id, err)
	}

	if encryptedKey != "" {
		dec, decErr := security.DecryptSecret(encryptedKey)
		if decErr != nil {
			log.Printf("[SECURITY ALERT] event=secret_decryption_failure category=ai_provider_api_key provider_id=%s error=%q", id, decErr.Error())
			return nil, fmt.Errorf("decrypt ai_provider %s secret: %w", id, decErr)
		}
		p.APIKey = dec
	}
	_ = r.cache.SaveAIProvider(&p)
	return &p, nil
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	detailsJSON, err := json.Marshal(log.Details)
	if err != nil {
		return fmt.Errorf("marshal audit log details: %w", err)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit log tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the audit chain serialization head to serialize concurrent append transactions globally across all replicas
	const auditChainLockID int64 = 98234109281
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", auditChainLockID); err != nil {
		return fmt.Errorf("acquire audit chain lock: %w", err)
	}

	// 1. Idempotency check: check if record already exists by ID with FOR UPDATE lock
	// Doing this before INSERT avoids conflict between ON CONFLICT (id) and idx_audit_logs_unique_prev_hash
	var existingHash string
	err = tx.QueryRowContext(ctx, "SELECT hash FROM audit_logs WHERE id = $1 FOR UPDATE", log.ID).Scan(&existingHash)
	if err == nil {
		if existingHash != log.Hash {
			return fmt.Errorf("audit log %s conflict: existing record has different hash", log.ID)
		}
		// Idempotent duplicate: identical ID and identical cryptographic hash
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit idempotent audit tx: %w", err)
		}
		_ = r.cache.SaveAuditLog(log)
		return nil
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query existing audit log %s: %w", log.ID, err)
	}

	// 2. Read authoritative chain head from database under advisory lock
	var currentHead string
	headErr := tx.QueryRowContext(ctx, "SELECT last_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE").Scan(&currentHead)
	if headErr != nil {
		if headErr == sql.ErrNoRows {
			// Seed row id=1 with GenesisHash if table was uninitialized
			currentHead = security.GenesisHash
			_, insErr := tx.ExecContext(ctx, "INSERT INTO audit_chain_head (id, last_hash, updated_at) VALUES (1, $1, NOW()) ON CONFLICT (id) DO NOTHING", currentHead)
			if insErr != nil {
				return fmt.Errorf("initialize audit chain head: %w", insErr)
			}
		} else {
			return fmt.Errorf("read authoritative audit chain head under advisory lock: %w", headErr)
		}
	}

	// 3. Atomically re-link prev_hash and re-compute canonical HMAC hash if another replica advanced head
	if log.PrevHash != currentHead {
		if len(r.auditHMACKey) == 0 {
			return errors.New("audit log re-linking required due to concurrent head advancement but auditHMACKey is not configured: failing closed to prevent chain corruption")
		}
		log.PrevHash = currentHead
		tsStr := log.CreatedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		newHash, hashErr := security.ComputeCanonicalPayloadHash(
			r.auditHMACKey,
			log.ID,
			tsStr,
			log.Actor,
			log.OrgID,
			log.ProjectID,
			log.Action,
			log.ResourceType,
			log.ResourceID,
			log.ClientIP,
			log.Details,
			log.PrevHash,
		)
		if hashErr != nil {
			return fmt.Errorf("recompute canonical hash for audit log %s: %w", log.ID, hashErr)
		}
		log.Hash = newHash
	}

	// 4. Insert row into audit_logs
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, org_id, project_id, actor, action, resource_type,
			resource_id, client_ip, details, prev_hash, hash, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, log.ID, log.OrgID, log.ProjectID, log.Actor, log.Action, log.ResourceType,
		log.ResourceID, log.ClientIP, detailsJSON, log.PrevHash, log.Hash, log.CreatedAt)
	if err != nil {
		return fmt.Errorf("persist audit log %s: %w", log.ID, err)
	}

	// 5. Update audit chain head in database
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_chain_head (id, last_hash, updated_at)
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET last_hash = $1, updated_at = NOW()
	`, log.Hash)
	if err != nil {
		return fmt.Errorf("update audit chain head: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit log tx: %w", err)
	}

	_ = r.cache.SaveAuditLog(log)
	return nil
}

func (r *PostgresRepository) ListAuditLogs(projectID string, limit int, offset int) ([]*model.AuditLog, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var countQuery, selectQuery string
	var countArgs, selectArgs []interface{}

	if projectID != "" {
		countQuery = "SELECT COUNT(*) FROM audit_logs WHERE project_id = $1"
		countArgs = []interface{}{projectID}
		selectQuery = `
			SELECT id, COALESCE(org_id, ''), COALESCE(project_id, ''), actor, action,
			       resource_type, resource_id, COALESCE(client_ip, ''), details,
			       COALESCE(prev_hash, ''), COALESCE(hash, ''), created_at
			FROM audit_logs
			WHERE project_id = $1
			ORDER BY sequence_num DESC, created_at DESC, id DESC
			LIMIT $2 OFFSET $3
		`
		selectArgs = []interface{}{projectID, limit, offset}
	} else {
		countQuery = "SELECT COUNT(*) FROM audit_logs"
		countArgs = nil
		selectQuery = `
			SELECT id, COALESCE(org_id, ''), COALESCE(project_id, ''), actor, action,
			       resource_type, resource_id, COALESCE(client_ip, ''), details,
			       COALESCE(prev_hash, ''), COALESCE(hash, ''), created_at
			FROM audit_logs
			ORDER BY sequence_num DESC, created_at DESC, id DESC
			LIMIT $1 OFFSET $2
		`
		selectArgs = []interface{}{limit, offset}
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*model.AuditLog
	for rows.Next() {
		var l model.AuditLog
		var detailsJSON []byte
		if err := rows.Scan(&l.ID, &l.OrgID, &l.ProjectID, &l.Actor, &l.Action,
			&l.ResourceType, &l.ResourceID, &l.ClientIP, &detailsJSON,
			&l.PrevHash, &l.Hash, &l.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &l.Details); err != nil {
				return nil, 0, fmt.Errorf("unmarshal audit log %s details: %w", l.ID, err)
			}
		}
		logs = append(logs, &l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit logs: %w", err)
	}

	if logs == nil {
		logs = []*model.AuditLog{}
	}
	return logs, total, nil
}

func (r *PostgresRepository) GetAuditLog(id string) (*model.AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `
		SELECT id, COALESCE(org_id, ''), COALESCE(project_id, ''), actor, action,
		       resource_type, resource_id, COALESCE(client_ip, ''), details,
		       COALESCE(prev_hash, ''), COALESCE(hash, ''), created_at
		FROM audit_logs
		WHERE id = $1
	`
	var l model.AuditLog
	var detailsJSON []byte
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&l.ID, &l.OrgID, &l.ProjectID, &l.Actor, &l.Action,
		&l.ResourceType, &l.ResourceID, &l.ClientIP, &detailsJSON,
		&l.PrevHash, &l.Hash, &l.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query audit log %s: %w", id, err)
	}
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &l.Details); err != nil {
			return nil, fmt.Errorf("unmarshal audit log %s details: %w", l.ID, err)
		}
	}
	_ = r.cache.SaveAuditLog(&l)
	return &l, nil
}

func (r *PostgresRepository) GetLastAuditHash() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var headHash string
	err := r.db.QueryRowContext(ctx, "SELECT last_hash FROM audit_chain_head WHERE id = 1").Scan(&headHash)
	if err == nil && headHash != "" {
		return headHash
	}

	var latestHash string
	err = r.db.QueryRowContext(ctx, "SELECT hash FROM audit_logs ORDER BY sequence_num DESC, created_at DESC, id DESC LIMIT 1").Scan(&latestHash)
	if err == nil && latestHash != "" {
		return latestHash
	}

	return r.cache.GetLastAuditHash()
}

// -------------------------------------------------------------------------
// Transactional Outbox Events (Desired-State Configuration Synchronization)
// -------------------------------------------------------------------------

var _ OutboxStore = (*PostgresRepository)(nil)

// GetPendingOutboxEvents retrieves unapplied outbox events ordered by creation timestamp.
func (r *PostgresRepository) GetPendingOutboxEvents(ctx context.Context, limit int) ([]*OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT event_id, aggregate_type, aggregate_id, event_type, payload, status, retry_count, COALESCE(lease_token, ''), created_at, processed_at
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
		if err := rows.Scan(&ev.EventID, &ev.AggregateType, &ev.AggregateID, &ev.EventType, &ev.Payload, &ev.Status, &ev.RetryCount, &ev.LeaseToken, &ev.CreatedAt, &ev.ProcessedAt); err != nil {
			return nil, fmt.Errorf("scan outbox event: %w", err)
		}
		events = append(events, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate outbox events: %w", err)
	}
	return events, nil
}

// ClaimOutboxEvents claims up to limit unapplied outbox events using PostgreSQL FOR UPDATE SKIP LOCKED
// with a worker lease and a cryptographic lease token. This coordinates multiple concurrent workers
// with zero contention and provides lease-fenced safety against stale acknowledgements.
func (r *PostgresRepository) ClaimOutboxEvents(ctx context.Context, workerID string, limit int, leaseDuration time.Duration) ([]*OutboxEvent, error) {
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("workerID is required to claim outbox events")
	}
	if limit <= 0 {
		limit = 100
	}
	leaseSeconds := int(leaseDuration.Seconds())
	if leaseSeconds <= 0 {
		leaseSeconds = 30
	}

	tokenBytes := make([]byte, 16)
	if _, err := cryptorand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate outbox lease token: %w", err)
	}
	leaseToken := fmt.Sprintf("lease-%d-%s", time.Now().UnixNano(), hex.EncodeToString(tokenBytes))

	query := `
		UPDATE outbox_events
		SET status = 'PROCESSING',
		    locked_by = $1,
		    lease_token = $2,
		    locked_until = NOW() + ($3 || ' seconds')::INTERVAL,
		    retry_count = retry_count + 1
		WHERE event_id IN (
			SELECT event_id
			FROM outbox_events
			WHERE (status = 'PENDING')
			   OR (status = 'PROCESSING' AND locked_until < NOW())
			ORDER BY created_at ASC
			LIMIT $4
			FOR UPDATE SKIP LOCKED
		)
		RETURNING event_id, aggregate_type, aggregate_id, event_type, payload, status, retry_count, lease_token, created_at, processed_at
	`
	rows, err := r.db.QueryContext(ctx, query, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	defer rows.Close()

	var events []*OutboxEvent
	for rows.Next() {
		var ev OutboxEvent
		if err := rows.Scan(&ev.EventID, &ev.AggregateType, &ev.AggregateID, &ev.EventType, &ev.Payload, &ev.Status, &ev.RetryCount, &ev.LeaseToken, &ev.CreatedAt, &ev.ProcessedAt); err != nil {
			return nil, fmt.Errorf("scan claimed outbox event: %w", err)
		}
		events = append(events, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed outbox events: %w", err)
	}
	return events, nil
}

// MarkOutboxEventFailed marks an outbox event as FAILED or DEAD_LETTER after repeated retry exhaustion,
// fenced by worker lease ownership AND lease token to prevent stale workers from overwriting active events.
func (r *PostgresRepository) MarkOutboxEventFailed(ctx context.Context, eventID string, workerID string, leaseToken string, reason string) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("workerID is required for outbox lease fencing")
	}
	if strings.TrimSpace(leaseToken) == "" {
		return errors.New("leaseToken is required for outbox lease fencing")
	}
	const maxRetries = 5
	query := `
		UPDATE outbox_events
		SET status = CASE 
		        WHEN $2 LIKE 'QUARANTINE:%' OR $2 LIKE 'DEAD_LETTER:%' OR retry_count >= $1 THEN 'DEAD_LETTER' 
		        ELSE 'PENDING' 
		    END,
		    error_message = $2,
		    locked_by = '',
		    lease_token = '',
		    locked_until = NULL
		WHERE event_id = $3
		  AND locked_by = $4
		  AND lease_token = $5
		  AND locked_until >= NOW()
	`
	res, err := r.db.ExecContext(ctx, query, maxRetries, reason, eventID, workerID, leaseToken)
	if err != nil {
		return fmt.Errorf("mark outbox event failed: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrOutboxLeaseLost
	}
	return nil
}

// MarkOutboxEventProcessed marks an outbox event as PROCESSED,
// fenced by worker lease ownership AND lease token to prevent stale workers from overwriting active events.
func (r *PostgresRepository) MarkOutboxEventProcessed(ctx context.Context, eventID string, workerID string, leaseToken string) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("workerID is required for outbox lease fencing")
	}
	if strings.TrimSpace(leaseToken) == "" {
		return errors.New("leaseToken is required for outbox lease fencing")
	}
	now := time.Now().UTC()
	query := `
		UPDATE outbox_events
		SET status = 'PROCESSED',
		    processed_at = $1,
		    locked_by = '',
		    lease_token = '',
		    locked_until = NULL
		WHERE event_id = $2
		  AND locked_by = $3
		  AND lease_token = $4
		  AND locked_until >= NOW()
	`
	res, err := r.db.ExecContext(ctx, query, now, eventID, workerID, leaseToken)
	if err != nil {
		return fmt.Errorf("mark outbox event processed: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrOutboxLeaseLost
	}
	return nil
}

// -------------------------------------------------------------------------
// Edge Configuration Convergence
// -------------------------------------------------------------------------

func (r *PostgresRepository) SaveEdgeConvergenceHead(ctx context.Context, targetVersion int64, targetChecksum string) error {
	query := `
		INSERT INTO edge_convergence_head (id, target_version, target_checksum, updated_at)
		VALUES (1, $1, $2, NOW())
		ON CONFLICT (id) DO UPDATE
		SET target_version = EXCLUDED.target_version,
		    target_checksum = EXCLUDED.target_checksum,
		    updated_at = EXCLUDED.updated_at
	`
	if _, err := r.db.ExecContext(ctx, query, targetVersion, targetChecksum); err != nil {
		return fmt.Errorf("save edge convergence head: %w", err)
	}
	return r.cache.SaveEdgeConvergenceHead(ctx, targetVersion, targetChecksum)
}

func (r *PostgresRepository) GetEdgeConvergenceHead(ctx context.Context) (int64, string, time.Time, error) {
	ver, chk, t, err := r.cache.GetEdgeConvergenceHead(ctx)
	if err == nil && ver > 0 {
		return ver, chk, t, nil
	}
	var dbVer int64
	var dbChk string
	var dbTime time.Time
	err = r.db.QueryRowContext(ctx, "SELECT target_version, target_checksum, updated_at FROM edge_convergence_head WHERE id = 1").Scan(&dbVer, &dbChk, &dbTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 1, "", time.Now().UTC(), nil
		}
		return 0, "", time.Time{}, fmt.Errorf("get edge convergence head: %w", err)
	}
	_ = r.cache.SaveEdgeConvergenceHead(ctx, dbVer, dbChk)
	return dbVer, dbChk, dbTime, nil
}

func (r *PostgresRepository) AllocateEdgeConvergenceHead(ctx context.Context, checksum string) (int64, string, error) {
	query := `
		INSERT INTO edge_convergence_head (id, target_version, target_checksum, updated_at)
		VALUES (1, 1, $1, NOW())
		ON CONFLICT (id) DO UPDATE
		SET target_version = CASE
				WHEN edge_convergence_head.target_checksum = EXCLUDED.target_checksum THEN edge_convergence_head.target_version
				ELSE edge_convergence_head.target_version + 1
			END,
			target_checksum = EXCLUDED.target_checksum,
			updated_at = NOW()
		RETURNING target_version, target_checksum;
	`
	var targetVersion int64
	var targetChecksum string
	err := r.db.QueryRowContext(ctx, query, checksum).Scan(&targetVersion, &targetChecksum)
	if err != nil {
		return 0, "", fmt.Errorf("allocate edge convergence head: %w", err)
	}
	_ = r.cache.SaveEdgeConvergenceHead(ctx, targetVersion, targetChecksum)
	return targetVersion, targetChecksum, nil
}

func (r *PostgresRepository) SaveGatewaySyncRecord(ctx context.Context, rec *model.GatewaySyncRecord) error {
	if rec == nil || rec.GatewayID == "" {
		return errors.New("gateway_id required")
	}
	query := `
		INSERT INTO gateway_sync_state (
			gateway_id, pop_id, applied_version, applied_checksum, target_version, target_checksum, status, last_error, last_ack_at, convergence_lag_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (gateway_id) DO UPDATE
		SET pop_id = EXCLUDED.pop_id,
		    applied_version = EXCLUDED.applied_version,
		    applied_checksum = EXCLUDED.applied_checksum,
		    target_version = EXCLUDED.target_version,
		    target_checksum = EXCLUDED.target_checksum,
		    status = EXCLUDED.status,
		    last_error = EXCLUDED.last_error,
		    last_ack_at = EXCLUDED.last_ack_at,
		    convergence_lag_ms = EXCLUDED.convergence_lag_ms
	`
	lastAck := rec.LastAckAt
	if lastAck.IsZero() {
		lastAck = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx, query,
		rec.GatewayID,
		rec.PoPID,
		rec.AppliedVersion,
		rec.AppliedChecksum,
		rec.TargetVersion,
		rec.TargetChecksum,
		string(rec.Status),
		rec.LastError,
		lastAck,
		rec.ConvergenceLagMs,
	)
	if err != nil {
		return fmt.Errorf("save gateway sync record: %w", err)
	}
	return r.cache.SaveGatewaySyncRecord(ctx, rec)
}

func (r *PostgresRepository) GetGatewaySyncRecord(ctx context.Context, gatewayID string) (*model.GatewaySyncRecord, error) {
	if rec, err := r.cache.GetGatewaySyncRecord(ctx, gatewayID); err == nil {
		return rec, nil
	}
	query := `SELECT gateway_id, pop_id, applied_version, applied_checksum, target_version, target_checksum, status, last_error, last_ack_at, convergence_lag_ms FROM gateway_sync_state WHERE gateway_id = $1`
	var rec model.GatewaySyncRecord
	var statusStr string
	err := r.db.QueryRowContext(ctx, query, gatewayID).Scan(
		&rec.GatewayID, &rec.PoPID, &rec.AppliedVersion, &rec.AppliedChecksum, &rec.TargetVersion, &rec.TargetChecksum, &statusStr, &rec.LastError, &rec.LastAckAt, &rec.ConvergenceLagMs,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get gateway sync record: %w", err)
	}
	rec.Status = model.GatewaySyncStatus(statusStr)
	if rec.TargetVersion > rec.AppliedVersion {
		rec.VersionLag = rec.TargetVersion - rec.AppliedVersion
	}
	_ = r.cache.SaveGatewaySyncRecord(ctx, &rec)
	return &rec, nil
}

func (r *PostgresRepository) ListGatewaySyncRecords(ctx context.Context) ([]*model.GatewaySyncRecord, error) {
	list, err := r.cache.ListGatewaySyncRecords(ctx)
	if err == nil && len(list) > 0 {
		return list, nil
	}
	query := `SELECT gateway_id, pop_id, applied_version, applied_checksum, target_version, target_checksum, status, last_error, last_ack_at, convergence_lag_ms FROM gateway_sync_state ORDER BY gateway_id ASC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list gateway sync records: %w", err)
	}
	defer rows.Close()

	var records []*model.GatewaySyncRecord
	for rows.Next() {
		var rec model.GatewaySyncRecord
		var statusStr string
		if err := rows.Scan(&rec.GatewayID, &rec.PoPID, &rec.AppliedVersion, &rec.AppliedChecksum, &rec.TargetVersion, &rec.TargetChecksum, &statusStr, &rec.LastError, &rec.LastAckAt, &rec.ConvergenceLagMs); err != nil {
			return nil, fmt.Errorf("scan gateway sync record: %w", err)
		}
		rec.Status = model.GatewaySyncStatus(statusStr)
		if rec.TargetVersion > rec.AppliedVersion {
			rec.VersionLag = rec.TargetVersion - rec.AppliedVersion
		}
		_ = r.cache.SaveGatewaySyncRecord(ctx, &rec)
		records = append(records, &rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate gateway sync records: %w", err)
	}
	return records, nil
}

func (r *PostgresRepository) SavePoPSnapshotHead(ctx context.Context, popID string, targetVersion int64, targetChecksum string) error {
	if strings.TrimSpace(popID) == "" {
		return errors.New("pop_id required")
	}
	query := `
		INSERT INTO pop_snapshot_heads (pop_id, target_version, target_checksum, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (pop_id) DO UPDATE
		SET target_version = EXCLUDED.target_version,
		    target_checksum = EXCLUDED.target_checksum,
		    updated_at = NOW()
		WHERE pop_snapshot_heads.target_version < EXCLUDED.target_version
		   OR (pop_snapshot_heads.target_version = EXCLUDED.target_version AND pop_snapshot_heads.target_checksum = EXCLUDED.target_checksum)
	`
	res, err := r.db.ExecContext(ctx, query, popID, targetVersion, targetChecksum)
	if err != nil {
		return fmt.Errorf("save pop snapshot head: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected for pop snapshot head: %w", err)
	}
	if rows == 0 {
		existingVer, existingChk, _, err := r.GetPoPSnapshotHead(ctx, popID)
		if err != nil {
			return fmt.Errorf("stale or conflicting snapshot version %d rejected by database: %w", targetVersion, err)
		}
		if existingVer > targetVersion {
			return fmt.Errorf("stale snapshot version %d rejected: current authoritative version is %d", targetVersion, existingVer)
		}
		if existingVer == targetVersion && existingChk != targetChecksum {
			return fmt.Errorf("checksum mismatch conflict for version %d: existing checksum %s diverges from proposed %s", targetVersion, existingChk, targetChecksum)
		}
		return nil
	}
	_ = r.cache.SavePoPSnapshotHead(ctx, popID, targetVersion, targetChecksum)
	return nil
}

func (r *PostgresRepository) GetPoPSnapshotHead(ctx context.Context, popID string) (int64, string, time.Time, error) {
	query := `SELECT target_version, target_checksum, updated_at FROM pop_snapshot_heads WHERE pop_id = $1`
	var targetVersion int64
	var targetChecksum string
	var updatedAt time.Time
	err := r.db.QueryRowContext(ctx, query, popID).Scan(&targetVersion, &targetChecksum, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", time.Time{}, ErrNotFound
		}
		return 0, "", time.Time{}, fmt.Errorf("get pop snapshot head: %w", err)
	}
	_ = r.cache.SavePoPSnapshotHead(ctx, popID, targetVersion, targetChecksum)
	return targetVersion, targetChecksum, updatedAt, nil
}
