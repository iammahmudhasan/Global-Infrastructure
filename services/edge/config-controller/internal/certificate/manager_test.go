package certificate_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
	mgr.SetCertsDir(t.TempDir())
	t.Setenv("NEXUSEDGE_CERTS_GID", "101")

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
	mgr.SetCertsDir(t.TempDir())
	t.Setenv("NEXUSEDGE_CERTS_GID", "101")

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

	certPath := filepath.Join(tempDir, "versions", cert.ID, "server.crt")
	keyPath := filepath.Join(tempDir, "versions", cert.ID, "server.key")
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
	if !strings.Contains(string(sdsContent), cert.ID) {
		t.Fatalf("expected sds.json to reference versioned cert %s, got %s", cert.ID, string(sdsContent))
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

	renewedCertPath := filepath.Join(tempDir, "versions", renewed.ID, "server.crt")
	updatedCertBytes, err := os.ReadFile(renewedCertPath)
	if err != nil {
		t.Fatalf("failed to read updated cert: %v", err)
	}
	if string(updatedCertBytes) != renewed.CertPEM {
		t.Fatalf("expected cert on disk to match renewed cert PEM")
	}

	renewedSDSBytes, err := os.ReadFile(sdsPath)
	if err != nil {
		t.Fatalf("failed to read renewed sds.json: %v", err)
	}
	if !strings.Contains(string(renewedSDSBytes), renewed.ID) {
		t.Fatalf("expected renewed sds.json to reference renewed version %s, got %s", renewed.ID, string(renewedSDSBytes))
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

	// In non-production, order succeeds
	_, ch, err := mgr.OrderCertificate("dom-prod-guard")
	if err != nil {
		t.Fatalf("order certificate failed: %v", err)
	}

	// In production, validation must fail closed
	t.Setenv("NEXUSEDGE_ENV", "production")
	_, err = mgr.ValidateAndIssueCertificate(ch.Token)
	if !errors.Is(err, certificate.ErrProductionACMENotConfigured) {
		t.Fatalf("expected ErrProductionACMENotConfigured in production on validation, got: %v", err)
	}

	// In production, ordering a new certificate must also fail closed immediately
	_, _, err = mgr.OrderCertificate("dom-prod-guard")
	if !errors.Is(err, certificate.ErrProductionACMENotConfigured) {
		t.Fatalf("expected ErrProductionACMENotConfigured in production on order, got: %v", err)
	}
}

func TestCertificateManager_ActiveCertificatePreservationDuringRenewal(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)
	mgr.SetCertsDir(t.TempDir())
	t.Setenv("NEXUSEDGE_CERTS_GID", "101")

	domain := &model.Domain{
		ID:        "dom-renewal-preservation",
		ProjectID: "prj-renewal",
		Hostname:  "renewal.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	// 1. Issue initial active certificate
	_, ch1, err := mgr.OrderCertificate("dom-renewal-preservation")
	if err != nil {
		t.Fatalf("first order failed: %v", err)
	}
	activeCert, err := mgr.ValidateAndIssueCertificate(ch1.Token)
	if err != nil {
		t.Fatalf("first validate failed: %v", err)
	}
	if activeCert.Status != model.CertStatusActive {
		t.Fatalf("expected active certificate, got %s", activeCert.Status)
	}

	// Verify active certificate is returned by GetCertificate
	current := st.GetCertificate("dom-renewal-preservation")
	if current == nil || current.Status != model.CertStatusActive || current.ID != activeCert.ID {
		t.Fatalf("expected active certificate in store, got %+v", current)
	}

	// 2. Start a renewal order - must NOT overwrite active certificate in store with pending placeholder
	pendingCert, ch2, err := mgr.OrderCertificate("dom-renewal-preservation")
	if err != nil {
		t.Fatalf("renewal order failed: %v", err)
	}
	if pendingCert.Status != model.CertStatusPendingChallenge {
		t.Fatalf("expected pending status for renewal order, got %s", pendingCert.Status)
	}

	// CRITICAL ASSERTION: The active certificate must still be preserved in store
	stillActive := st.GetCertificate("dom-renewal-preservation")
	if stillActive == nil || stillActive.Status != model.CertStatusActive || stillActive.ID != activeCert.ID {
		t.Fatalf("CRITICAL REGRESSION: active certificate was overwritten by pending placeholder in store: %+v", stillActive)
	}

	// The pending certificate must be retrievable via GetPendingCertificate
	pendingInStore := st.GetPendingCertificate("dom-renewal-preservation")
	if pendingInStore == nil || pendingInStore.ID != pendingCert.ID || pendingInStore.Status != model.CertStatusPendingChallenge {
		t.Fatalf("expected pending certificate in store, got %+v", pendingInStore)
	}

	// 3. Complete renewal - now active certificate should transition to new version
	renewedCert, err := mgr.ValidateAndIssueCertificate(ch2.Token)
	if err != nil {
		t.Fatalf("renewal validation failed: %v", err)
	}
	if renewedCert.Status != model.CertStatusActive || renewedCert.ID != pendingCert.ID {
		t.Fatalf("expected renewed certificate to become active, got %+v", renewedCert)
	}

	updatedActive := st.GetCertificate("dom-renewal-preservation")
	if updatedActive == nil || updatedActive.ID != renewedCert.ID || updatedActive.Status != model.CertStatusActive {
		t.Fatalf("expected updated active certificate in store, got %+v", updatedActive)
	}

	// Pending certificate should now be cleared
	if st.GetPendingCertificate("dom-renewal-preservation") != nil {
		t.Fatalf("expected pending certificate to be cleared after activation")
	}
}

func TestCertificateManager_KeypairMismatchRejection(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)
	mgr.SetCertsDir(t.TempDir())

	// Create mismatched certificate and private key
	mismatchedCert := &model.Certificate{
		ID:            "cert-mismatch",
		DomainID:      "dom-mismatch",
		Status:        model.CertStatusActive,
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzinvalid\n-----END CERTIFICATE-----",
		PrivateKeyPEM: "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIInvalidKey\n-----END EC PRIVATE KEY-----",
	}

	err := mgr.SyncSDSCertificate(mismatchedCert)
	if err == nil {
		t.Fatalf("expected SyncSDSCertificate to fail on mismatched/invalid keypair, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") && !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("expected keypair mismatch error message, got: %v", err)
	}
}

func TestCertificateManager_VersionedSDSRotation(t *testing.T) {
	st := store.NewStore()
	mgr := certificate.NewManager(st)
	tempDir := t.TempDir()
	mgr.SetCertsDir(tempDir)

	domain := &model.Domain{
		ID:        "dom-versioned-test",
		ProjectID: "prj-ver",
		Hostname:  "versioned.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	gid := os.Getgid()
	if gid < 0 {
		gid = 101
	}
	t.Setenv("NEXUSEDGE_CERTS_GID", strconv.Itoa(gid))

	_, ch, err := mgr.OrderCertificate("dom-versioned-test")
	if err != nil {
		t.Fatalf("order failed: %v", err)
	}

	cert, err := mgr.ValidateAndIssueCertificate(ch.Token)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	// Verify versioned directory exists
	versionDir := filepath.Join(tempDir, "versions", cert.ID)
	verCertPath := filepath.Join(versionDir, "server.crt")
	verKeyPath := filepath.Join(versionDir, "server.key")

	if _, err := os.Stat(verCertPath); os.IsNotExist(err) {
		t.Fatalf("expected versioned certificate file at %s", verCertPath)
	}
	if _, err := os.Stat(verKeyPath); os.IsNotExist(err) {
		t.Fatalf("expected versioned private key file at %s", verKeyPath)
	}

	// Verify sds.json references the versioned files directly
	sdsPath := filepath.Join(tempDir, "sds.json")
	if _, err := os.Stat(sdsPath); os.IsNotExist(err) {
		t.Fatalf("expected sds.json to exist at %s", sdsPath)
	}
	sdsData, err := os.ReadFile(sdsPath)
	if err != nil {
		t.Fatalf("failed to read sds.json: %v", err)
	}
	expectedCertRef := fmt.Sprintf("/etc/envoy/certs/versions/%s/server.crt", cert.ID)
	expectedKeyRef := fmt.Sprintf("/etc/envoy/certs/versions/%s/server.key", cert.ID)
	if !strings.Contains(string(sdsData), expectedCertRef) {
		t.Fatalf("expected sds.json to reference %s, got %s", expectedCertRef, string(sdsData))
	}
	if !strings.Contains(string(sdsData), expectedKeyRef) {
		t.Fatalf("expected sds.json to reference %s, got %s", expectedKeyRef, string(sdsData))
	}
}
