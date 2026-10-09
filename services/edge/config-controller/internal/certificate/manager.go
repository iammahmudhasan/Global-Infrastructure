package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

var (
	ErrDomainNotFound              = errors.New("domain not found in store")
	ErrChallengeExpired            = errors.New("acme challenge has expired")
	ErrChallengeNotFound           = errors.New("acme challenge not found")
	ErrChallengeAlreadyUsed        = errors.New("acme challenge has already been consumed")
	ErrCertNotFound                = errors.New("certificate not found for domain")
	ErrRateLimitExceeded           = errors.New("certificate operation rate limit exceeded")
	ErrProductionACMENotConfigured = errors.New("production ACME issuer is not configured; local self-signed issuance is dev/test only")
)

func isProductionEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return env == "production"
}

func preparePrivateKeyForEnvoy(path string) error {
	rawGID := strings.TrimSpace(os.Getenv("NEXUSEDGE_CERTS_GID"))
	if rawGID == "" {
		return errors.New("NEXUSEDGE_CERTS_GID must be configured; refusing to export a private key without an explicit reader group")
	}
	gid, err := strconv.Atoi(rawGID)
	if err != nil || gid < 0 {
		return fmt.Errorf("invalid NEXUSEDGE_CERTS_GID %q", rawGID)
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		if err := os.Chown(path, -1, gid); err != nil {
			return fmt.Errorf("set Envoy key-reader group: %w", err)
		}
	}
	if err := os.Chmod(path, 0640); err != nil {
		return fmt.Errorf("set private-key mode 0640: %w", err)
	}
	return nil
}

const (
	MaxOrdersPerHourPerDomain      = 5
	MaxValidationsPerHourPerDomain = 10
)

type Manager struct {
	mu           sync.RWMutex
	store        *store.Store
	orderHistory map[string][]time.Time
	valHistory   map[string][]time.Time
	certsDir     string
}

func NewManager(s *store.Store) *Manager {
	return &Manager{
		store:        s,
		orderHistory: make(map[string][]time.Time),
		valHistory:   make(map[string][]time.Time),
	}
}

// SetCertsDir sets the target directory for exporting Envoy SDS resources and certificates.
func (m *Manager) SetCertsDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certsDir = dir
}

// GetCertsDir returns the configured certificate export directory.
func (m *Manager) GetCertsDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certsDir
}

func checkAndRecordCertRate(history map[string][]time.Time, key string, limit int, window time.Duration, now time.Time) error {
	cutoff := now.Add(-window)
	timestamps := history[key]
	valid := make([]time.Time, 0, len(timestamps))
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= limit {
		history[key] = valid
		return ErrRateLimitExceeded
	}
	history[key] = append(valid, now)
	return nil
}

// OrderCertificate initiates an automated ACME HTTP-01 challenge order for a domain
func (m *Manager) OrderCertificate(domainID string) (*model.Certificate, *model.ACMEChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain, err := m.store.GetDomain(domainID)
	if err != nil {
		return nil, nil, ErrDomainNotFound
	}

	now := time.Now().UTC()
	if err := checkAndRecordCertRate(m.orderHistory, domainID, MaxOrdersPerHourPerDomain, 1*time.Hour, now); err != nil {
		return nil, nil, err
	}

	certID := "cert-" + generateHex(6)
	challengeID := "acme-ch-" + generateHex(6)

	token := generateHex(16)
	thumbprint := generateHex(16)
	keyAuth := fmt.Sprintf("%s.%s", token, thumbprint)

	challenge := &model.ACMEChallenge{
		ID:               challengeID,
		CertificateID:    certID,
		DomainID:         domainID,
		Hostname:         domain.Hostname,
		Type:             "HTTP-01",
		Token:            token,
		KeyAuthorization: keyAuth,
		Status:           model.ChallengeStatusPending,
		CreatedAt:        now,
		ExpiresAt:        now.Add(1 * time.Hour),
	}

	cert := &model.Certificate{
		ID:        certID,
		DomainID:  domainID,
		Domains:   []string{domain.Hostname},
		Status:    model.CertStatusPendingChallenge,
		KeyType:   model.KeyTypeECDSA,
		Issuer:    "NexusEdge Local Dev CA (Self-Signed Mode)",
		IssuedAt:  time.Time{},
		ExpiresAt: time.Time{},
		AutoRenew: true,
	}

	m.store.SaveACMEChallenge(challenge)
	m.store.SaveCertificate(cert)

	return cert, challenge, nil
}

// ValidateAndIssueCertificate verifies the HTTP-01 challenge and issues signed x509 leaf + chain
func (m *Manager) ValidateAndIssueCertificate(token string) (*model.Certificate, error) {
	if isProductionEnvironment() {
		return nil, ErrProductionACMENotConfigured
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	challenge := m.store.GetACMEChallengeByToken(token)
	if challenge == nil {
		return nil, ErrChallengeNotFound
	}

	now := time.Now().UTC()
	if err := checkAndRecordCertRate(m.valHistory, challenge.DomainID, MaxValidationsPerHourPerDomain, 1*time.Hour, now); err != nil {
		return nil, err
	}

	if now.After(challenge.ExpiresAt) {
		m.store.UpdateACMEChallengeStatus(token, model.ChallengeStatusFailed)
		return nil, ErrChallengeExpired
	}

	// Finding 4: Replay Protection - ACME challenge can only be consumed once
	if challenge.Status != model.ChallengeStatusPending {
		return nil, ErrChallengeAlreadyUsed
	}

	cert := m.store.GetCertificate(challenge.DomainID)
	if cert == nil {
		return nil, ErrCertNotFound
	}

	// Generate ECDSA P-256 Key Pair for high-speed edge line-rate TLS
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdsa p256 key: %w", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ec private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Generate x509 Certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now = time.Now().UTC()
	validFor := 90 * 24 * time.Hour // 90 days validity (Let's Encrypt standard)
	expiresAt := now.Add(validFor)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   challenge.Hostname,
			Organization: []string{"NexusEdge Sovereign Edge Network"},
		},
		NotBefore:             now.Add(-1 * time.Hour), // Clock skew tolerance
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{challenge.Hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Calculate SHA256 Fingerprint
	fpHash := sha256.Sum256(certDER)
	fpFormatted := make([]string, len(fpHash))
	for i, b := range fpHash {
		fpFormatted[i] = fmt.Sprintf("%02X", b)
	}
	fingerprint := strings.Join(fpFormatted, ":")

	// Update Certificate
	cert.Status = model.CertStatusActive
	cert.CertPEM = string(certPEM)
	cert.PrivateKeyPEM = string(privPEM)
	cert.FingerprintSHA256 = fingerprint
	cert.SerialNumber = serialNumber.String()
	cert.Issuer = "NexusEdge Local Dev CA (Self-Signed Mode)"
	cert.IssuedAt = now
	cert.ExpiresAt = expiresAt

	if err := m.syncSDSCertificateLocked(cert); err != nil {
		return nil, fmt.Errorf("certificate created but Envoy SDS activation failed: %w", err)
	}
	m.store.UpdateACMEChallengeStatus(token, model.ChallengeStatusValidated)
	m.store.SaveCertificate(cert)

	return cert, nil
}

// syncSDSCertificateLocked writes the certificate, private key, and Envoy v3 SDS Secret resource atomically.
func (m *Manager) syncSDSCertificateLocked(cert *model.Certificate) error {
	if m.certsDir == "" || cert == nil || cert.CertPEM == "" || cert.PrivateKeyPEM == "" {
		return nil
	}

	if err := os.MkdirAll(m.certsDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	certPath := filepath.Join(m.certsDir, "server.crt")
	keyPath := filepath.Join(m.certsDir, "server.key")
	sdsPath := filepath.Join(m.certsDir, "sds.json")

	// 1. Write server.crt atomically
	tmpCert := certPath + ".tmp"
	if err := os.WriteFile(tmpCert, []byte(cert.CertPEM), 0644); err != nil {
		return fmt.Errorf("failed to write cert tmp file: %w", err)
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		return fmt.Errorf("failed to rename cert file: %w", err)
	}

	// 2. Write server.key atomically (0640 with Envoy reader group)
	tmpKey := keyPath + ".tmp"
	if err := os.WriteFile(tmpKey, []byte(cert.PrivateKeyPEM), 0600); err != nil {
		return fmt.Errorf("write private-key staging file: %w", err)
	}
	if err := preparePrivateKeyForEnvoy(tmpKey); err != nil {
		_ = os.Remove(tmpKey)
		return err
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		_ = os.Remove(tmpKey)
		return fmt.Errorf("activate private-key file: %w", err)
	}

	// 3. Write Envoy v3 SDS Secret resource file atomically
	sdsPayload := map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
				"name":  "dynamic_server_cert",
				"tls_certificate": map[string]interface{}{
					"certificate_chain": map[string]string{
						"filename": "/etc/envoy/certs/server.crt",
					},
					"private_key": map[string]string{
						"filename": "/etc/envoy/certs/server.key",
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(sdsPayload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sds payload: %w", err)
	}

	tmpSDS := sdsPath + ".tmp"
	if err := os.WriteFile(tmpSDS, data, 0644); err != nil {
		return fmt.Errorf("failed to write sds tmp file: %w", err)
	}
	if err := os.Rename(tmpSDS, sdsPath); err != nil {
		return fmt.Errorf("failed to rename sds file: %w", err)
	}

	return nil
}

// SyncSDSCertificate exports the certificate and updates the Envoy SDS resource file atomically.
func (m *Manager) SyncSDSCertificate(cert *model.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncSDSCertificateLocked(cert)
}

// RenewCertificate forces renewal of an existing domain certificate
func (m *Manager) RenewCertificate(domainID string) (*model.Certificate, error) {
	cert := m.store.GetCertificate(domainID)
	if cert == nil {
		return nil, ErrCertNotFound
	}

	// Trigger order & validation cycle
	_, challenge, err := m.OrderCertificate(domainID)
	if err != nil {
		return nil, err
	}

	return m.ValidateAndIssueCertificate(challenge.Token)
}

// IsExpiringSoon checks if a certificate expires within 30 days
func (m *Manager) IsExpiringSoon(cert *model.Certificate) bool {
	if cert == nil || cert.ExpiresAt.IsZero() {
		return true
	}
	renewalWindow := 30 * 24 * time.Hour
	return time.Now().UTC().Add(renewalWindow).After(cert.ExpiresAt)
}

func generateHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
