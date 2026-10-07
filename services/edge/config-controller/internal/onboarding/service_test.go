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
		OriginAddress:  "origin.customer.internal",
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
	verifiedDomain, err := svc.VerifyDomain(resp.DomainID)
	if err != nil {
		t.Fatalf("failed to verify domain: %v", err)
	}
	if verifiedDomain.Status != model.DomainStatusActive {
		t.Errorf("expected status ACTIVE after verification, got %s", verifiedDomain.Status)
	}
}
