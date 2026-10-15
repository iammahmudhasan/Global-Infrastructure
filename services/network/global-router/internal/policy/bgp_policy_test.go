package policy

import (
	"testing"
	"time"
)

func TestPrefixSanitizerRFC7454(t *testing.T) {
	sanitizer := NewPrefixSanitizer()

	tests := []struct {
		name         string
		cidr         string
		isSimulation bool
		wantErr      bool
		errMatch     string
	}{
		{
			name:         "Valid Public IPv4 /24",
			cidr:         "103.145.10.0/24",
			isSimulation: false,
			wantErr:      false,
		},
		{
			name:         "Valid Public IPv6 /48",
			cidr:         "2404:6800:4000::/48",
			isSimulation: false,
			wantErr:      false,
		},
		{
			name:         "Invalid IPv4 Too Specific (/25)",
			cidr:         "103.145.10.0/25",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "exceeds RFC 7454 limit",
		},
		{
			name:         "Invalid IPv4 Single Host (/32)",
			cidr:         "103.145.10.1/32",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "exceeds RFC 7454 limit",
		},
		{
			name:         "Invalid IPv6 Too Specific (/64)",
			cidr:         "2404:6800:4000::/64",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "exceeds RFC 7454 limit",
		},
		{
			name:         "Invalid IPv4 Too Broad (/7)",
			cidr:         "100.0.0.0/7",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "is broader than allowed",
		},
		{
			name:         "Bogon RFC 1918 Rejected in Prod",
			cidr:         "10.0.0.0/24",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "overlaps with reserved bogon",
		},
		{
			name:         "RFC 5737 TEST-NET-2 Permitted in Simulation",
			cidr:         "198.51.100.0/24",
			isSimulation: true,
			wantErr:      false,
		},
		{
			name:         "RFC 5737 TEST-NET-2 Rejected in Production",
			cidr:         "198.51.100.0/24",
			isSimulation: false,
			wantErr:      true,
			errMatch:     "overlaps with reserved bogon",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizer.ValidateAdvertisedPrefix(tc.cidr, tc.isSimulation)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateAdvertisedPrefix(%s) err = %v, wantErr %v", tc.cidr, err, tc.wantErr)
			}
			if tc.wantErr && tc.errMatch != "" {
				if err == nil || !containsSubstring(err.Error(), tc.errMatch) {
					t.Errorf("expected error containing %q, got %v", tc.errMatch, err)
				}
			}
		})
	}
}

func TestRPKIRouteOriginValidationRFC6811(t *testing.T) {
	validator := NewRPKIRouteOriginValidator()

	// Authorized: 103.145.10.0/24 up to /24 for AS64512
	err := validator.AddROA("103.145.10.0/24", 24, 64512)
	if err != nil {
		t.Fatalf("failed to add ROA: %v", err)
	}

	// 1. Valid Route (matches prefix, len <= maxLen, matches ASN)
	status, err := validator.ValidateRoute("103.145.10.0/24", 64512)
	if err != nil || status != RPKIValid {
		t.Fatalf("expected RPKIValid, got status=%s, err=%v", status, err)
	}

	// 2. Invalid Route: Hijacked ASN (origin AS99999)
	status, err = validator.ValidateRoute("103.145.10.0/24", 99999)
	if err != nil || status != RPKIInvalid {
		t.Fatalf("expected RPKIInvalid for hijacked ASN, got status=%s, err=%v", status, err)
	}

	// 3. Not Found: Unregistered Prefix
	status, err = validator.ValidateRoute("203.0.113.0/24", 64512)
	if err != nil || status != RPKINotFound {
		t.Fatalf("expected RPKINotFound for unknown prefix, got status=%s, err=%v", status, err)
	}
}

func TestRouteFlapDampingRFC2439(t *testing.T) {
	cfg := FlapDampingConfig{
		HalfLife:            10 * time.Minute,
		ReuseThreshold:      750.0,
		SuppressThreshold:   2000.0,
		MaxSuppressDuration: 30 * time.Minute,
		FlapPenalty:         1000.0,
	}

	guard, err := NewRouteFlapDampingGuard(cfg)
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}

	prefix := "103.145.10.0/24"
	now := time.Now()

	// Flap 1: Penalty = 1000 < 2000 -> ACTIVE
	state1, p1 := guard.RecordFlap(prefix, now)
	if state1 != RouteStateActive || p1 != 1000.0 {
		t.Fatalf("expected ACTIVE with 1000 penalty, got state=%s, p=%f", state1, p1)
	}

	// Flap 2 (5 seconds later): Penalty ≈ 1994 < 2000 -> ACTIVE
	now2 := now.Add(5 * time.Second)
	state2, p2 := guard.RecordFlap(prefix, now2)
	if state2 != RouteStateActive || p2 < 1990.0 {
		t.Fatalf("expected ACTIVE with ~1994 penalty, got state=%s, p=%f", state2, p2)
	}

	// Flap 3 (5 seconds later): Penalty ≈ 2988 >= 2000 -> DAMPED (Suppressed under RFC 2439)
	now3 := now2.Add(5 * time.Second)
	state3, p3 := guard.RecordFlap(prefix, now3)
	if state3 != RouteStateSuppressed || p3 < 2980.0 {
		t.Fatalf("expected DAMPED with ~2988 penalty, got state=%s, p=%f", state3, p3)
	}

	// Evaluate 10 minutes later (one half-life): Penalty decays from ~2988 to ~1494, still > 750 -> DAMPED
	now4 := now3.Add(10 * time.Minute)
	state4, p4 := guard.EvaluateState(prefix, now4)
	if state4 != RouteStateSuppressed || p4 > 1550.0 || p4 < 1450.0 {
		t.Fatalf("expected still DAMPED after 1 half life (~1494 penalty), got state=%s, p=%f", state4, p4)
	}

	// Evaluate 25 minutes later (2.5 half-lives): Penalty decays to ~528 <= 750 -> ACTIVE (Unsuppressed)
	now5 := now3.Add(25 * time.Minute)
	state5, p5 := guard.EvaluateState(prefix, now5)
	if state5 != RouteStateActive || p5 > 750.0 {
		t.Fatalf("expected ACTIVE after decay below 750, got state=%s, p=%f", state5, p5)
	}
}

func TestGracefulShutdownRFC8326(t *testing.T) {
	plan := GenerateGracefulShutdownPlan("peer-singapore-01", "frankfurt", 45*time.Second)

	if plan.CommunityTag != CommunityGracefulShutdown {
		t.Fatalf("expected community %s, got %s", CommunityGracefulShutdown, plan.CommunityTag)
	}
	if plan.LocalPreference != 0 {
		t.Fatalf("expected local_preference 0, got %d", plan.LocalPreference)
	}
	if plan.DwellDuration != 45*time.Second {
		t.Fatalf("expected dwell duration 45s, got %v", plan.DwellDuration)
	}
	if plan.TargetAlternative != "frankfurt" {
		t.Fatalf("expected target alternative frankfurt, got %s", plan.TargetAlternative)
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && searchSubstring(s, sub)))
}

func searchSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
