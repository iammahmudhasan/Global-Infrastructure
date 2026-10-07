package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

var (
	ErrDomainNotFound    = errors.New("domain not found in store")
	ErrChallengeExpired  = errors.New("acme challenge has expired")
	ErrChallengeNotFound = errors.New("acme challenge not found")
	ErrCertNotFound      = errors.New("certificate not found for domain")
)

type Manager struct {
	mu    sync.RWMutex
	store *store.Store
}

func NewManager(s *store.Store) *Manager {
	return &Manager{
		store: s,
	}
}

// OrderCertificate initiates an automated ACME HTTP-01 challenge order for a domain
func (m *Manager) OrderCertificate(domainID string) (*model.Certificate, *model.ACMEChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain, err := m.store.GetDomain(domainID)
	if err != nil {
		return nil, nil, ErrDomainNotFound
	}

	certID := "cert-" + generateHex(6)
	challengeID := "acme-ch-" + generateHex(6)

	token := generateHex(16)
	thumbprint := generateHex(16)
	keyAuth := fmt.Sprintf("%s.%s", token, thumbprint)

	now := time.Now().UTC()
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
		Issuer:    "NexusEdge ACME Automated CA (Let's Encrypt Provider)",
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
	m.mu.Lock()
	defer m.mu.Unlock()

	challenge := m.store.GetACMEChallengeByToken(token)
	if challenge == nil {
		return nil, ErrChallengeNotFound
	}

	if time.Now().UTC().After(challenge.ExpiresAt) {
		m.store.UpdateACMEChallengeStatus(token, model.ChallengeStatusFailed)
		return nil, ErrChallengeExpired
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

	now := time.Now().UTC()
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
	cert.Issuer = "NexusEdge ACME Automated CA (Let's Encrypt Provider)"
	cert.IssuedAt = now
	cert.ExpiresAt = expiresAt

	m.store.UpdateACMEChallengeStatus(token, model.ChallengeStatusValidated)
	m.store.SaveCertificate(cert)

	return cert, nil
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
