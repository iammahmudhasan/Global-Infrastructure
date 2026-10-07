package onboarding_test

import (
	"testing"

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
		"100.64.0.1",     // CGNAT
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

