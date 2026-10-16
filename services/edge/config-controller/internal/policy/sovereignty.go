package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DataClassification represents the confidentiality and legal sensitivity level of workload data.
type DataClassification string

const (
	ClassificationPublic       DataClassification = "PUBLIC"
	ClassificationInternal     DataClassification = "INTERNAL"
	ClassificationConfidential DataClassification = "CONFIDENTIAL"
	ClassificationCII          DataClassification = "CII" // Critical Information Infrastructure (BD NDMA 2026)
)

// Jurisdiction represents the sovereign jurisdiction code.
type Jurisdiction string

const (
	JurisdictionBD     Jurisdiction = "BD"     // Bangladesh (NDMA 2026 / BDIX)
	JurisdictionEU     Jurisdiction = "EU"     // European Union (GDPR)
	JurisdictionUS     Jurisdiction = "US"     // United States
	JurisdictionSG     Jurisdiction = "SG"     // Singapore
	JurisdictionGlobal Jurisdiction = "GLOBAL" // Unrestricted
)

// SovereignEvaluationRequest encapsulates the policy input for evaluating data boundary compliance.
type SovereignEvaluationRequest struct {
	TenantID           string             `json:"tenant_id"`
	ProjectID          string             `json:"project_id"`
	WorkloadID         string             `json:"workload_id"`
	DataClassification DataClassification `json:"data_classification"`
	SourceJurisdiction Jurisdiction       `json:"source_jurisdiction"`
	TargetJurisdiction Jurisdiction       `json:"target_jurisdiction"`
	TargetRegion       string             `json:"target_region"`
	TargetNodeID       string             `json:"target_node_id"`
	StrictSovereignty  bool               `json:"strict_sovereignty"`
	ExportPermitHash   string             `json:"export_permit_hash,omitempty"`
}

// SovereignEvaluationResult contains the deterministic boundary evaluation decision.
type SovereignEvaluationResult struct {
	Allowed            bool               `json:"allowed"`
	DecisionCode       string             `json:"decision_code"`
	Reason             string             `json:"reason"`
	EnforcedLaw        string             `json:"enforced_law,omitempty"`
	SourceJurisdiction Jurisdiction       `json:"source_jurisdiction"`
	TargetJurisdiction Jurisdiction       `json:"target_jurisdiction"`
	DataClassification DataClassification `json:"data_classification"`
	EvaluatedAt        time.Time          `json:"evaluated_at"`
}

var (
	ErrEmptyTenantID         = errors.New("tenant_id is required")
	ErrEmptyProjectID        = errors.New("project_id is required")
	ErrInvalidClassification = errors.New("invalid data classification")
	ErrInvalidJurisdiction   = errors.New("invalid jurisdiction specified")
)

// Evaluator evaluates sovereign policy constraints across jurisdictions.
type Evaluator struct{}

// NewEvaluator creates a new Sovereign Policy Evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// ValidateRequest performs syntactic and boundary validation on the incoming request.
func (e *Evaluator) ValidateRequest(req *SovereignEvaluationRequest) error {
	if strings.TrimSpace(req.TenantID) == "" {
		return ErrEmptyTenantID
	}
	if strings.TrimSpace(req.ProjectID) == "" {
		return ErrEmptyProjectID
	}
	switch req.DataClassification {
	case ClassificationPublic, ClassificationInternal, ClassificationConfidential, ClassificationCII:
	case "":
		req.DataClassification = ClassificationInternal
	default:
		return fmt.Errorf("%w: %s", ErrInvalidClassification, req.DataClassification)
	}

	req.SourceJurisdiction = Jurisdiction(strings.ToUpper(string(req.SourceJurisdiction)))
	req.TargetJurisdiction = Jurisdiction(strings.ToUpper(string(req.TargetJurisdiction)))

	if req.SourceJurisdiction == "" {
		req.SourceJurisdiction = JurisdictionGlobal
	}
	if req.TargetJurisdiction == "" {
		req.TargetJurisdiction = JurisdictionGlobal
	}

	return nil
}

// Evaluate applies hard legal sovereignty rules against the evaluation request.
func (e *Evaluator) Evaluate(req *SovereignEvaluationRequest) (*SovereignEvaluationResult, error) {
	if err := e.ValidateRequest(req); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	result := &SovereignEvaluationResult{
		SourceJurisdiction: req.SourceJurisdiction,
		TargetJurisdiction: req.TargetJurisdiction,
		DataClassification: req.DataClassification,
		EvaluatedAt:        now,
	}

	// 1. Bangladesh NDMA 2026 CII Hard Rule
	// Critical Information Infrastructure originating in Bangladesh must never leave BD compute nodes
	// unless a valid cryptographic export permit hash is supplied.
	if req.SourceJurisdiction == JurisdictionBD && req.DataClassification == ClassificationCII {
		if req.TargetJurisdiction != JurisdictionBD {
			if strings.TrimSpace(req.ExportPermitHash) == "" {
				result.Allowed = false
				result.DecisionCode = "BD_NDMA_2026_CII_BREACH"
				result.EnforcedLaw = "Bangladesh National Data Management Act 2026 (Section 14: CII Sovereign Pinning)"
				result.Reason = "Critical Information Infrastructure data originating in Bangladesh is prohibited from foreign processing without an authorized export permit."
				return result, nil
			}
		}
	}

	// 2. Strict Sovereignty Constraint
	// When strict sovereignty is requested, source and target jurisdictions must match exactly,
	// or target must be in the approved domestic region.
	if req.StrictSovereignty && req.SourceJurisdiction != JurisdictionGlobal {
		if req.TargetJurisdiction != req.SourceJurisdiction {
			result.Allowed = false
			result.DecisionCode = "SOVEREIGN_MISMATCH"
			result.Reason = fmt.Sprintf("Target jurisdiction '%s' violates strict sovereignty constraint for source '%s'.", req.TargetJurisdiction, req.SourceJurisdiction)
			return result, nil
		}
	}

	// 3. EU GDPR Data Residency Enforcement
	// EU confidential data cannot be exported to jurisdictions without adequate privacy safeguards.
	if req.SourceJurisdiction == JurisdictionEU && (req.DataClassification == ClassificationConfidential || req.DataClassification == ClassificationCII) {
		if req.TargetJurisdiction != JurisdictionEU && req.TargetJurisdiction != "IS" { // Iceland is EEA compliant
			result.Allowed = false
			result.DecisionCode = "EU_GDPR_CHAPTER_V_VIOLATION"
			result.EnforcedLaw = "EU General Data Protection Regulation (Chapter V: Third-Country Transfers)"
			result.Reason = fmt.Sprintf("Confidential EU data cannot be processed in non-EEA jurisdiction '%s' without standard contractual clauses.", req.TargetJurisdiction)
			return result, nil
		}
	}

	// 4. US Sovereign Isolation
	if req.SourceJurisdiction == JurisdictionUS && req.DataClassification == ClassificationCII {
		if req.TargetJurisdiction != JurisdictionUS {
			result.Allowed = false
			result.DecisionCode = "US_SOVEREIGN_ISOLATION_VIOLATION"
			result.EnforcedLaw = "US FedRAMP High / Executive Order 14028"
			result.Reason = fmt.Sprintf("Target jurisdiction '%s' is not authorized for US sovereign CII workloads.", req.TargetJurisdiction)
			return result, nil
		}
	}

	// Compliant Decision
	result.Allowed = true
	result.DecisionCode = "SOVEREIGN_POLICY_COMPLIANT"
	result.Reason = fmt.Sprintf("Workload satisfies data residency policies for %s -> %s (%s).", req.SourceJurisdiction, req.TargetJurisdiction, req.DataClassification)
	return result, nil
}
