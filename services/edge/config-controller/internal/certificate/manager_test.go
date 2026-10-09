package certificate_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/certificate"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestCertificateManager_Workflow(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)

	domain := &model.Domain{
		ID:        "dom-test-tls",
		ProjectID: "prj-1",
		Hostname:  "api.production.internal",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	// 1. Order Certificate
	cert, challenge, err := mgr.OrderCertificate("dom-test-tls")
	if err != nil {
		t.Fatalf("unexpected order error: %v", err)
	}

	if cert.Status != model.CertStatusPendingChallenge {
		t.Errorf("expected status PENDING_CHALLENGE, got %s", cert.Status)
	}
	if challenge.Token == "" || challenge.KeyAuthorization == "" {
		t.Errorf("expected valid token and key authorization in challenge, got %+v", challenge)
	}
	if challenge.Hostname != "api.production.internal" {
		t.Errorf("expected challenge hostname api.production.internal, got %s", challenge.Hostname)
	}

	// 2. Validate Challenge and Issue Certificate
	issuedCert, err := mgr.ValidateAndIssueCertificate(challenge.Token)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if issuedCert.Status != model.CertStatusActive {
		t.Errorf("expected status ACTIVE, got %s", issuedCert.Status)
	}
	if issuedCert.Issuer != "NexusEdge Local Dev CA (Self-Signed Mode)" {
		t.Errorf("expected issuer 'NexusEdge Local Dev CA (Self-Signed Mode)', got %s", issuedCert.Issuer)
	}
	if issuedCert.CertPEM == "" || issuedCert.PrivateKeyPEM == "" {
		t.Fatalf("expected non-empty CertPEM and PrivateKeyPEM")
	}

	// 2b. Replay Protection (Finding 4): Attempting to reuse already validated challenge must fail
	_, err = mgr.ValidateAndIssueCertificate(challenge.Token)
	if err != certificate.ErrChallengeAlreadyUsed {
		t.Fatalf("expected ErrChallengeAlreadyUsed on replay, got: %v", err)
	}

	// Cryptographic verification of PEM block
	block, _ := pem.Decode([]byte(issuedCert.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode valid CERTIFICATE PEM block")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse x509 certificate DER: %v", err)
	}

	if len(parsedCert.DNSNames) == 0 || parsedCert.DNSNames[0] != "api.production.internal" {
		t.Errorf("expected DNSNames to contain api.production.internal, got %v", parsedCert.DNSNames)
	}

	// Check validity duration (~90 days)
	daysRemaining := int(time.Until(issuedCert.ExpiresAt).Hours() / 24)
	if daysRemaining < 88 || daysRemaining > 91 {
		t.Errorf("expected approx 90 days validity, got %d days", daysRemaining)
	}

	// 3. Expiration Tracking
	if mgr.IsExpiringSoon(issuedCert) {
		t.Errorf("fresh certificate should not be expiring soon")
	}

	// Simulate old certificate expiring in 5 days
	issuedCert.ExpiresAt = time.Now().UTC().Add(5 * 24 * time.Hour)
	if !mgr.IsExpiringSoon(issuedCert) {
		t.Errorf("certificate expiring in 5 days must be marked as expiring soon")
	}

	// 4. Forced Renewal
	renewedCert, err := mgr.RenewCertificate("dom-test-tls")
	if err != nil {
		t.Fatalf("failed to renew certificate: %v", err)
	}
	renewedDays := int(time.Until(renewedCert.ExpiresAt).Hours() / 24)
	if renewedDays < 88 {
		t.Errorf("expected renewed cert to have ~90 days validity, got %d", renewedDays)
	}
}

func TestCertificateManager_Errors(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)

	// Order for non-existent domain
	_, _, err := mgr.OrderCertificate("dom-nonexistent")
	if err != certificate.ErrDomainNotFound {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}

	// Validate non-existent token
	_, err = mgr.ValidateAndIssueCertificate("invalid-token")
	if err != certificate.ErrChallengeNotFound {
		t.Errorf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestCertificateManager_RateLimits(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)

	domain := &model.Domain{
		ID:        "dom-ratelimit-tls",
		ProjectID: "prj-rl",
		Hostname:  "ratelimit.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	// Max 5 orders per hour per domain
	var lastChallenge *model.ACMEChallenge
	for i := 0; i < 5; i++ {
		_, ch, err := mgr.OrderCertificate("dom-ratelimit-tls")
		if err != nil {
			t.Fatalf("order %d failed unexpectedly: %v", i+1, err)
		}
		lastChallenge = ch
	}

	// 6th order should be rate limited
	_, _, err := mgr.OrderCertificate("dom-ratelimit-tls")
	if err != certificate.ErrRateLimitExceeded {
		t.Fatalf("expected ErrRateLimitExceeded on 6th order, got %v", err)
	}

	// Validate the last challenge
	_, err = mgr.ValidateAndIssueCertificate(lastChallenge.Token)
	if err != nil {
		t.Fatalf("validation failed unexpectedly: %v", err)
	}
}

func TestCertificateManager_SyncSDS(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)

	tempDir := t.TempDir()
	mgr.SetCertsDir(tempDir)

	if mgr.GetCertsDir() != tempDir {
		t.Fatalf("expected certs dir %s, got %s", tempDir, mgr.GetCertsDir())
	}

	domain := &model.Domain{
		ID:        "dom-sds-test",
		ProjectID: "prj-sds",
		Hostname:  "sds.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	gid := os.Getgid()
	if gid < 0 {
		gid = 101
	}
	t.Setenv("NEXUSEDGE_CERTS_GID", strconv.Itoa(gid))

	// 1. Order and Issue Certificate - must automatically export files to tempDir
	_, ch, err := mgr.OrderCertificate("dom-sds-test")
	if err != nil {
		t.Fatalf("order certificate failed: %v", err)
	}

	cert, err := mgr.ValidateAndIssueCertificate(ch.Token)
	if err != nil {
		t.Fatalf("validate and issue failed: %v", err)
	}

	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")
	sdsPath := filepath.Join(tempDir, "sds.json")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("expected %s to exist on disk", certPath)
	}
	keyInfo, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		t.Fatalf("expected %s to exist on disk", keyPath)
	}
	if _, err := os.Stat(sdsPath); os.IsNotExist(err) {
		t.Fatalf("expected %s to exist on disk", sdsPath)
	}

	// Verify private key mode enforces 0640 and does not leak permissions to others
	if runtime.GOOS != "windows" {
		mode := keyInfo.Mode().Perm()
		if mode&0007 != 0 {
			t.Fatalf("private key is accessible to others: mode=%04o", mode)
		}
		if mode != 0640 {
			t.Fatalf("expected private key mode 0640, got %04o", mode)
		}
	}

	sdsContent, err := os.ReadFile(sdsPath)
	if err != nil {
		t.Fatalf("failed to read sds.json: %v", err)
	}
	if !strings.Contains(string(sdsContent), "dynamic_server_cert") {
		t.Fatalf("expected sds.json to contain dynamic_server_cert, got %s", string(sdsContent))
	}

	// 2. Renew Certificate - must update files atomically
	initialSerial := cert.SerialNumber
	renewed, err := mgr.RenewCertificate("dom-sds-test")
	if err != nil {
		t.Fatalf("renewal failed: %v", err)
	}
	if renewed.SerialNumber == initialSerial {
		t.Fatalf("expected new serial number on renewal")
	}

	updatedCertBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read updated cert: %v", err)
	}
	if string(updatedCertBytes) != renewed.CertPEM {
		t.Fatalf("expected cert on disk to match renewed cert PEM")
	}
}

func TestCertificateManager_ProductionGuard(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)

	domain := &model.Domain{
		ID:        "dom-prod-guard",
		ProjectID: "prj-prod",
		Hostname:  "api.production.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	_, ch, err := mgr.OrderCertificate("dom-prod-guard")
	if err != nil {
		t.Fatalf("order certificate failed: %v", err)
	}

	t.Setenv("NEXUSEDGE_ENV", "production")
	_, err = mgr.ValidateAndIssueCertificate(ch.Token)
	if !errors.Is(err, certificate.ErrProductionACMENotConfigured) {
		t.Fatalf("expected ErrProductionACMENotConfigured in production, got: %v", err)
	}
}
