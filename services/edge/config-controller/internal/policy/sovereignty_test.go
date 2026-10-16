package policy

import (
	"testing"
)

func TestSovereignEvaluator_Validation(t *testing.T) {
	eval := NewEvaluator()

	// Missing tenant ID
	req := &SovereignEvaluationRequest{
		ProjectID: "proj-01",
	}
	err := eval.ValidateRequest(req)
	if err != ErrEmptyTenantID {
		t.Fatalf("expected ErrEmptyTenantID, got %v", err)
	}

	// Missing project ID
	req = &SovereignEvaluationRequest{
		TenantID: "tenant-01",
	}
	err = eval.ValidateRequest(req)
	if err != ErrEmptyProjectID {
		t.Fatalf("expected ErrEmptyProjectID, got %v", err)
	}

	// Invalid classification
	req = &SovereignEvaluationRequest{
		TenantID:           "tenant-01",
		ProjectID:          "proj-01",
		DataClassification: "SUPER_SECRET",
	}
	err = eval.ValidateRequest(req)
	if err == nil {
		t.Fatal("expected error on invalid classification, got nil")
	}
}

func TestSovereignEvaluator_BangladeshNDMA2026(t *testing.T) {
	eval := NewEvaluator()

	// 1. BD CII to US without permit must be REJECTED
	req := &SovereignEvaluationRequest{
		TenantID:           "tenant-cbr-banking",
		ProjectID:          "proj-cbr",
		WorkloadID:         "core-banking-01",
		DataClassification: ClassificationCII,
		SourceJurisdiction: JurisdictionBD,
		TargetJurisdiction: JurisdictionUS,
		TargetNodeID:       "us-cw-h100-iad",
		StrictSovereignty:  true,
	}

	res, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected BD CII export to be rejected, but was allowed")
	}
	if res.DecisionCode != "BD_NDMA_2026_CII_BREACH" {
		t.Fatalf("expected decision BD_NDMA_2026_CII_BREACH, got %s", res.DecisionCode)
	}

	// 2. BD CII within BD must be ALLOWED
	req.TargetJurisdiction = JurisdictionBD
	req.TargetNodeID = "bd-dhaka-dgx01"
	res, err = eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected BD CII in-country processing to be allowed: %s", res.Reason)
	}
	if res.DecisionCode != "SOVEREIGN_POLICY_COMPLIANT" {
		t.Fatalf("expected SOVEREIGN_POLICY_COMPLIANT, got %s", res.DecisionCode)
	}

	// 3. BD CII export with authorized cryptographic permit hash must be ALLOWED
	req.TargetJurisdiction = JurisdictionSG
	req.TargetNodeID = "sg-aws-gpu01"
	req.ExportPermitHash = "sha256-permit-bd-gov-cbr-approved-2026"
	req.StrictSovereignty = false
	res, err = eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected permitted export to be allowed, got: %s", res.Reason)
	}
}

func TestSovereignEvaluator_EUGDPR(t *testing.T) {
	eval := NewEvaluator()

	// EU confidential data exported to US without SCCs must be REJECTED
	req := &SovereignEvaluationRequest{
		TenantID:           "tenant-eu-health",
		ProjectID:          "proj-health",
		DataClassification: ClassificationConfidential,
		SourceJurisdiction: JurisdictionEU,
		TargetJurisdiction: JurisdictionUS,
	}

	res, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected EU confidential data transfer to US to be rejected under GDPR Chapter V")
	}
	if res.DecisionCode != "EU_GDPR_CHAPTER_V_VIOLATION" {
		t.Fatalf("expected EU_GDPR_CHAPTER_V_VIOLATION, got %s", res.DecisionCode)
	}

	// EU confidential data to Iceland (EEA member) must be ALLOWED
	req.TargetJurisdiction = "IS"
	res, err = eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected EEA transfer to be allowed, got: %s", res.Reason)
	}
}

func TestSovereignEvaluator_USIsolation(t *testing.T) {
	eval := NewEvaluator()

	// US CII data exported to non-US must be REJECTED
	req := &SovereignEvaluationRequest{
		TenantID:           "tenant-gov-us",
		ProjectID:          "proj-fed",
		DataClassification: ClassificationCII,
		SourceJurisdiction: JurisdictionUS,
		TargetJurisdiction: JurisdictionSG,
	}

	res, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected US CII transfer abroad to be rejected")
	}
	if res.DecisionCode != "US_SOVEREIGN_ISOLATION_VIOLATION" {
		t.Fatalf("expected US_SOVEREIGN_ISOLATION_VIOLATION, got %s", res.DecisionCode)
	}
}
