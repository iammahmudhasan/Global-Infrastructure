package onboarding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestValidateHostname(t *testing.T) {
	valid := []string{
		"api.customer.com",
		"sub.domain.example.org",
		"my-app.cloud.io",
		"service.bdix.com.bd",
	}

	for _, host := range valid {
		if err := onboarding.ValidateHostname(host); err != nil {
			t.Errorf("expected %q to be valid, got: %v", host, err)
		}
	}

	invalid := []string{
		"",
		"localhost",
		"service.local",
		"node.internal",
		"192.168.1.1",
		"203.0.113.1",
		"bad..domain.com",
		"-invalid.com",
	}

	for _, host := range invalid {
		if err := onboarding.ValidateHostname(host); err == nil {
			t.Errorf("expected %q to be rejected, but passed validation", host)
		}
	}
}

func TestOnboardAndVerifyDomain(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	req := onboarding.OnboardRequest{
		ProjectID:      "prj-test-001",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	}

	resp, err := svc.OnboardDomain(req)
	if err != nil {
		t.Fatalf("failed to onboard domain: %v", err)
	}

	if resp.DomainID == "" {
		t.Errorf("expected non-empty domain ID")
	}
	if resp.Hostname != "api.customer.com" {
		t.Errorf("expected hostname %q, got %q", "api.customer.com", resp.Hostname)
	}
	if resp.Status != model.DomainStatusPendingVerification {
		t.Errorf("expected status %s, got %s", model.DomainStatusPendingVerification, resp.Status)
	}
	if resp.CNAMETarget == "" {
		t.Errorf("expected non-empty CNAME target")
	}

	// Verify duplicate domain is rejected
	_, err = svc.OnboardDomain(req)
	if err == nil {
		t.Errorf("expected duplicate domain error, got nil")
	}

	// Verify domain activation
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")
	verifiedDomain, err := svc.VerifyDomain(resp.DomainID)
	if err != nil {
		t.Fatalf("failed to verify domain: %v", err)
	}
	if verifiedDomain.Status != model.DomainStatusActive {
		t.Errorf("expected status ACTIVE after verification, got %s", verifiedDomain.Status)
	}
}

func TestValidateOriginAddress_SSRFProtection(t *testing.T) {
	blockedOrigins := []string{
		"127.0.0.1",
		"127.0.0.1:8080",
		"10.0.0.1",
		"172.16.0.5",
		"192.168.1.1",
		"169.254.169.254", // Cloud metadata
		"100.64.0.1",      // CGNAT
		"localhost",
		"backend.internal",
		"app.local",
		"::1",
		"",
		"origin.customer.com:443", // Port embedded in address (Finding 19)
	}

	for _, origin := range blockedOrigins {
		if err := onboarding.ValidateOriginAddress(origin); err == nil {
			t.Errorf("expected origin %q to be blocked by SSRF/port protection, but was allowed", origin)
		}
	}

	validOrigins := []string{
		"origin.customer.com",
		"203.0.113.15",
		"198.51.100.20",
		"api.upstream-partner.io",
	}

	for _, origin := range validOrigins {
		if err := onboarding.ValidateOriginAddress(origin); err != nil {
			t.Errorf("expected origin %q to be valid, got error: %v", origin, err)
		}
	}
}

func TestOnboardPortAndProtocolValidation(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	// Invalid port < 1
	_, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.com",
		OriginPort:     -1,
		OriginProtocol: "HTTPS",
	})
	if err == nil {
		t.Errorf("expected port -1 to be rejected")
	}

	// Invalid port > 65535
	_, err = svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.com",
		OriginPort:     70000,
		OriginProtocol: "HTTPS",
	})
	if err == nil {
		t.Errorf("expected port 70000 to be rejected")
	}

	// Invalid protocol
	_, err = svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.com",
		OriginPort:     443,
		OriginProtocol: "FTP",
	})
	if err == nil {
		t.Errorf("expected protocol FTP to be rejected")
	}
}

func TestVerifyDomain_DoesNotBypassDNSVerification(t *testing.T) {
	t.Setenv("NEXUSEDGE_DEV_MODE", "false")
	t.Setenv("NEXUSEDGE_ENV", "production")

	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	resp, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "unverified-random-12345.example.com",
		OriginAddress:  "198.51.100.20",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard failed: %v", err)
	}

	_, err = svc.VerifyDomain(resp.DomainID)
	if err == nil {
		t.Fatal("expected DNS verification failure when dev mode is disabled")
	}
}

func TestVerifyDomain_DefaultEnvironmentMustNotAutoActivate(t *testing.T) {
	t.Setenv("NEXUSEDGE_DEV_MODE", "false")
	t.Setenv("NEXUSEDGE_STRICT_DNS_VERIFY", "")

	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	resp, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "unverified-default-env-999.example.com",
		OriginAddress:  "198.51.100.20",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard failed: %v", err)
	}

	_, err = svc.VerifyDomain(resp.DomainID)
	if err == nil {
		t.Fatal("domain verification must fail closed when DNS proof is absent in default environment")
	}
}

func TestVerifyDomain_PositiveAllowlistDevGate(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	resp, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test",
		Hostname:       "dev-gate-check.example.com",
		OriginAddress:  "198.51.100.30",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard failed: %v", err)
	}

	// 1. NEXUSEDGE_DEV_MODE=true but NEXUSEDGE_ENV is empty -> MUST FAIL CLOSED
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "")
	_, err = svc.VerifyDomain(resp.DomainID)
	if err == nil {
		t.Fatal("expected failure when NEXUSEDGE_ENV is not explicitly development/test")
	}

	// 2. NEXUSEDGE_DEV_MODE=true and NEXUSEDGE_ENV=development -> Succeeds
	t.Setenv("NEXUSEDGE_ENV", "development")
	domain, err := svc.VerifyDomain(resp.DomainID)
	if err != nil {
		t.Fatalf("expected success with explicit development environment, got: %v", err)
	}
	if domain.Status != model.DomainStatusActive {
		t.Errorf("expected ACTIVE status, got %s", domain.Status)
	}
}

func TestOnboardDomain_ProjectQuotaEnforcement(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	projectID := "prj-quota-svc-test"
	st.SetProjectQuota(projectID, store.ProjectQuota{MaxDomains: 2})

	// 1st domain -> success
	_, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      projectID,
		Hostname:       "d1.quota.example.com",
		OriginAddress:  "198.51.100.1",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("d1 onboard failed: %v", err)
	}

	// 2nd domain -> success
	_, err = svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      projectID,
		Hostname:       "d2.quota.example.com",
		OriginAddress:  "198.51.100.2",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("d2 onboard failed: %v", err)
	}

	// 3rd domain -> quota exceeded
	_, err = svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      projectID,
		Hostname:       "d3.quota.example.com",
		OriginAddress:  "198.51.100.3",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if !errors.Is(err, store.ErrProjectQuotaExceeded) {
		t.Fatalf("expected ErrProjectQuotaExceeded, got: %v", err)
	}
}

func TestOnboardDomain_SweepExpiredPendingDomains(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)

	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-sweep-test",
		Hostname:       "sweep-target.example.com",
		OriginAddress:  "198.51.100.10",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard failed: %v", err)
	}

	// Manually set domain CreatedAt to 72 hours ago
	dom, _ := st.GetDomain(res.DomainID)
	dom.CreatedAt = time.Now().UTC().Add(-72 * time.Hour)
	_ = st.SaveDomain(dom) // Overwrite doesn't re-add to hostIndex since it's already there or we can sweep directly

	// Sweep older than 24 hours
	swept := svc.SweepExpiredPendingDomains(24 * time.Hour)
	if swept == 0 {
		t.Fatalf("expected at least 1 domain swept, got %d", swept)
	}

	if _, err := st.GetDomain(res.DomainID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("domain should have been swept")
	}
}
