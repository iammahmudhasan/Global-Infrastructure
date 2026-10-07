package certificate_test

import (
	"encoding/pem"
	"crypto/x509"
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
	if issuedCert.CertPEM == "" || issuedCert.PrivateKeyPEM == "" {
		t.Fatalf("expected non-empty CertPEM and PrivateKeyPEM")
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
