package security_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
)

func newTestRequest(method, target, clientIP, userAgent string) *http.Request {
	u, _ := url.Parse(target)
	req := &http.Request{
		Method:     method,
		URL:        u,
		Header:     make(http.Header),
		RemoteAddr: clientIP + ":34567",
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	return req
}

func TestWAF_OWASP_Attacks(t *testing.T) {
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-sec-test",
		WAFEnabled:       true,
		WAFMode:          "BLOCK",
		OWASPProtection:  true,
		RateLimitEnabled: false,
	}

	tests := []struct {
		name          string
		path          string
		userAgent     string
		expectBlocked bool
		expectRule    string
	}{
		{
			name:          "Clean normal request",
			path:          "/api/v1/products?category=electronics",
			userAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			expectBlocked: false,
		},
		{
			name:          "SQL Injection union select",
			path:          "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
			userAgent:     "Mozilla/5.0",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_SQL_INJECTION",
		},
		{
			name:          "SQL Injection auth bypass",
			path:          "/login?user=' OR 1=1--",
			userAgent:     "Mozilla/5.0",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_SQL_INJECTION",
		},
		{
			name:          "XSS script tag",
			path:          "/comments?text=<script>alert('pwned')</script>",
			userAgent:     "Mozilla/5.0",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_CROSS_SITE_SCRIPTING",
		},
		{
			name:          "Path Traversal etc passwd",
			path:          "/download?file=../../../../etc/passwd",
			userAgent:     "Mozilla/5.0",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_PATH_TRAVERSAL",
		},
		{
			name:          "Command Injection",
			path:          "/exec?cmd=; rm -rf /data",
			userAgent:     "Mozilla/5.0",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_COMMAND_INJECTION",
		},
		{
			name:          "Malicious Scanner User-Agent",
			path:          "/index.php",
			userAgent:     "sqlmap/1.5.2#stable (http://sqlmap.org)",
			expectBlocked: true,
			expectRule:    "OWASP_CRS_MALICIOUS_SCANNER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newTestRequest("GET", tt.path, "198.51.100.5", tt.userAgent)
			res := engine.EvaluateRequest(req, policy)

			if res.Blocked != tt.expectBlocked {
				t.Fatalf("expected blocked=%v, got=%v (reason: %s)", tt.expectBlocked, res.Blocked, res.Reason)
			}
			if tt.expectBlocked && res.RuleTriggered != tt.expectRule {
				t.Errorf("expected rule=%s, got=%s", tt.expectRule, res.RuleTriggered)
			}
		})
	}
}

func TestWAF_CustomRules(t *testing.T) {
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:   "dom-custom-test",
		WAFEnabled: true,
		WAFMode:    "BLOCK",
		WAFRules: []model.WAFRule{
			{
				ID:        "rule-block-admin",
				Name:      "block-admin",
				MatchType: model.WAFMatchPathPrefix,
				Pattern:   "/admin",
				Action:    model.WAFActionBlock,
				Enabled:   true,
			},
			{
				ID:        "rule-block-ip",
				Name:      "block-malicious-subnet",
				MatchType: model.WAFMatchIPCIDR,
				Pattern:   "203.0.113.0/24",
				Action:    model.WAFActionBlock,
				Enabled:   true,
			},
		},
	}

	// 1. Path block
	reqAdmin := newTestRequest("GET", "/admin/dashboard", "192.0.2.1", "Mozilla/5.0")
	res := engine.EvaluateRequest(reqAdmin, policy)
	if !res.Blocked || res.StatusCode != http.StatusForbidden {
		t.Errorf("expected /admin to be blocked, got blocked=%v", res.Blocked)
	}

	// 2. IP CIDR block
	reqIP := newTestRequest("GET", "/public", "203.0.113.50", "Mozilla/5.0")
	res = engine.EvaluateRequest(reqIP, policy)
	if !res.Blocked || res.StatusCode != http.StatusForbidden {
		t.Errorf("expected IP in 203.0.113.0/24 to be blocked, got blocked=%v", res.Blocked)
	}

	// 3. Allowed clean request
	reqClean := newTestRequest("GET", "/public", "192.0.2.1", "Mozilla/5.0")
	res = engine.EvaluateRequest(reqClean, policy)
	if res.Blocked {
		t.Errorf("expected clean request to be allowed, got blocked")
	}
}

func TestRateLimiter(t *testing.T) {
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-ratelimit-test",
		WAFEnabled:       true,
		RateLimitEnabled: true,
		RateLimitRPM:     2, // 2 requests per minute limit for testing
	}

	req := newTestRequest("GET", "/api/data", "198.51.100.99", "Go-Client")

	// Request 1: allowed
	res1 := engine.EvaluateRequest(req, policy)
	if res1.Blocked {
		t.Fatalf("expected request 1 to be allowed")
	}

	// Request 2: allowed
	res2 := engine.EvaluateRequest(req, policy)
	if res2.Blocked {
		t.Fatalf("expected request 2 to be allowed")
	}

	// Request 3: should be rate-limited (429 Too Many Requests)
	res3 := engine.EvaluateRequest(req, policy)
	if !res3.Blocked || res3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected request 3 to be rate-limited (429), got blocked=%v, code=%d", res3.Blocked, res3.StatusCode)
	}
}
