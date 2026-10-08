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

func TestWAF_PriorityAndAllowSemantics(t *testing.T) {
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-priority-test",
		WAFEnabled:       true,
		WAFMode:          "BLOCK",
		OWASPProtection:  true,
		RateLimitEnabled: true,
		RateLimitRPM:     1, // Only 1 request allowed per minute
		WAFRules: []model.WAFRule{
			{
				ID:        "rule-block-api",
				Name:      "block-api-broad",
				MatchType: model.WAFMatchPathPrefix,
				Pattern:   "/api",
				Action:    model.WAFActionBlock,
				Priority:  10, // Lower priority
				Enabled:   true,
			},
			{
				ID:        "rule-allow-public",
				Name:      "allow-public-specific",
				MatchType: model.WAFMatchPathPrefix,
				Pattern:   "/api/public",
				Action:    model.WAFActionAllow,
				Priority:  100, // Higher priority: overrides lower priority block
				Enabled:   true,
			},
		},
	}

	// 1. Higher-priority ALLOW rule overrides lower-priority BLOCK rule for clean request
	reqPublic := newTestRequest("GET", "/api/public/info", "198.51.100.10", "Mozilla/5.0")
	resPublic := engine.EvaluateRequest(reqPublic, policy)
	if resPublic.Blocked {
		t.Fatalf("expected /api/public/info to be allowed by high-priority rule, got blocked: %s", resPublic.Reason)
	}
	if resPublic.RuleTriggered != "custom_rule_allow-public-specific" {
		t.Errorf("expected rule triggered to be custom_rule_allow-public-specific, got %s", resPublic.RuleTriggered)
	}

	// 2. Lower-priority BLOCK rule catches other paths
	reqPrivate := newTestRequest("GET", "/api/private/secret", "198.51.100.11", "Mozilla/5.0")
	resPrivate := engine.EvaluateRequest(reqPrivate, policy)
	if !resPrivate.Blocked || resPrivate.StatusCode != http.StatusForbidden {
		t.Fatalf("expected /api/private/secret to be blocked, got blocked=%v", resPrivate.Blocked)
	}

	// 3. Custom ALLOW rule MUST NOT bypass OWASP attack signatures (SQLi, XSS, etc.)
	reqExploit := newTestRequest("GET", "/api/public/search?q=1%20UNION%20SELECT%201", "198.51.100.12", "Mozilla/5.0")
	resExploit := engine.EvaluateRequest(reqExploit, policy)
	if !resExploit.Blocked || resExploit.RuleTriggered != "OWASP_CRS_SQL_INJECTION" {
		t.Fatalf("expected SQL injection on allowed path to be blocked by OWASP CRS, got blocked=%v, rule=%s",
			resExploit.Blocked, resExploit.RuleTriggered)
	}

	// 4. Custom ALLOW rule MUST NOT bypass Rate Limiting
	// Client 198.51.100.10 already consumed 1 token above; 2nd request must be rate-limited (429)
	reqFlood := newTestRequest("GET", "/api/public/info", "198.51.100.10", "Mozilla/5.0")
	resFlood := engine.EvaluateRequest(reqFlood, policy)
	if !resFlood.Blocked || resFlood.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second request to /api/public to be rate limited (429), got blocked=%v, code=%d",
			resFlood.Blocked, resFlood.StatusCode)
	}
}

func TestRateLimiter_HeaderKeyTypeAndPathScoping(t *testing.T) {
	// P1/P2 Finding 4 Verification: Header-based rate limiting & path-scoped isolation
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-header-rl",
		WAFEnabled:       true,
		RateLimitEnabled: true,
		RateLimitRPM:     100, // Default broad RPM
		RateLimitRules: []model.RateLimitRule{
			{
				ID:                "rl-login",
				PathPrefix:        "/login",
				RequestsPerMinute: 1, // 1 RPM for /login
				KeyType:           "HEADER",
				HeaderName:        "X-Authenticated-User",
				Enabled:           true,
			},
			{
				ID:                "rl-api",
				PathPrefix:        "/api",
				RequestsPerMinute: 50, // 50 RPM for /api
				KeyType:           "CLIENT_IP",
				Enabled:           true,
			},
		},
	}

	trustedCtx := security.EvaluationContext{IdentityTrusted: true}

	// 1. User Alice requests /login twice -> 1st OK, 2nd blocked (1 RPM)
	reqAlice1 := newTestRequest("POST", "/login", "198.51.100.20", "TestAgent")
	reqAlice1.Header.Set("X-Authenticated-User", "alice")
	resAlice1 := engine.EvaluateRequestWithContext(reqAlice1, policy, trustedCtx)
	if resAlice1.Blocked {
		t.Fatalf("expected Alice 1st login request to be allowed")
	}

	reqAlice2 := newTestRequest("POST", "/login", "198.51.100.20", "TestAgent")
	reqAlice2.Header.Set("X-Authenticated-User", "alice")
	resAlice2 := engine.EvaluateRequestWithContext(reqAlice2, policy, trustedCtx)
	if !resAlice2.Blocked || resAlice2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected Alice 2nd login request to be rate-limited (429), got %d", resAlice2.StatusCode)
	}

	// 2. User Bob from SAME IP requests /login -> must be ALLOWED (trusted header isolation)
	reqBob1 := newTestRequest("POST", "/login", "198.51.100.20", "TestAgent")
	reqBob1.Header.Set("X-Authenticated-User", "bob")
	resBob1 := engine.EvaluateRequestWithContext(reqBob1, policy, trustedCtx)
	if resBob1.Blocked {
		t.Fatalf("expected Bob 1st login request to be allowed due to header isolation")
	}

	// 3. User Alice requests /api -> must be ALLOWED because /login scope does not throttle /api scope!
	reqAliceAPI := newTestRequest("GET", "/api/user/profile", "198.51.100.20", "TestAgent")
	reqAliceAPI.Header.Set("X-Authenticated-User", "alice")
	resAliceAPI := engine.EvaluateRequestWithContext(reqAliceAPI, policy, trustedCtx)
	if resAliceAPI.Blocked {
		t.Fatalf("expected /api request to be allowed; /login rate limit must not pollute /api bucket!")
	}
}

func TestRateLimiter_UntrustedClientHeaderSpoofingProtection(t *testing.T) {
	// P2 Finding 3 Verification: Client cannot spoof trusted identity or bypass rate limits by rotating headers or supplying forged markers
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-spoof-rl",
		WAFEnabled:       true,
		RateLimitEnabled: true,
		RateLimitRPM:     100,
		RateLimitRules: []model.RateLimitRule{
			{
				ID:                "rl-untrusted-header",
				PathPrefix:        "/login",
				RequestsPerMinute: 1, // 1 RPM limit
				KeyType:           "HEADER",
				HeaderName:        "X-User-ID", // Untrusted client-supplied header
				Enabled:           true,
			},
		},
	}

	clientIP := "198.51.100.99"

	// 1. Client sends request with X-User-ID: alice -> Allowed
	reqAlice := newTestRequest("POST", "/login", clientIP, "TestAgent")
	reqAlice.Header.Set("X-User-ID", "alice")
	resAlice := engine.EvaluateRequest(reqAlice, policy)
	if resAlice.Blocked {
		t.Fatalf("expected 1st request to be allowed")
	}

	// 2. Same client attempts to bypass rate limiting by changing header to X-User-ID: bob
	// AND injects spoofed verification markers (X-Gateway-Identity-Verified, X-Auth-Verified).
	// Because EvaluationContext.IdentityTrusted is false, client-supplied markers are completely ignored.
	// Therefore, the second request MUST be blocked (429)!
	reqBob := newTestRequest("POST", "/login", clientIP, "TestAgent")
	reqBob.Header.Set("X-User-ID", "bob")
	reqBob.Header.Set("X-Gateway-Identity-Verified", "true")
	reqBob.Header.Set("X-Auth-Verified", "true")
	resBob := engine.EvaluateRequest(reqBob, policy)
	if !resBob.Blocked || resBob.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("untrusted client header bypass vulnerability! Expected 429 Too Many Requests, got blocked=%v, code=%d",
			resBob.Blocked, resBob.StatusCode)
	}
}

func TestRateLimiter_BurstCapacity(t *testing.T) {
	// P2 Finding 5 Verification: BurstSize is functional and expands token bucket capacity
	engine := security.NewWAFEngine()
	policy := &model.SecurityPolicy{
		DomainID:         "dom-burst-rl",
		WAFEnabled:       true,
		RateLimitEnabled: true,
		RateLimitRules: []model.RateLimitRule{
			{
				ID:                "rl-burst",
				PathPrefix:        "/burst",
				RequestsPerMinute: 60, // 1 per sec
				BurstSize:         5,  // Allows immediate burst of 5
				KeyType:           "CLIENT_IP",
				Enabled:           true,
			},
		},
	}

	clientIP := "198.51.100.77"
	// 5 requests within burst capacity should all succeed
	for i := 1; i <= 5; i++ {
		req := newTestRequest("GET", "/burst/test", clientIP, "BurstAgent")
		res := engine.EvaluateRequest(req, policy)
		if res.Blocked {
			t.Fatalf("expected request %d within burst capacity 5 to be allowed", i)
		}
	}

	// 6th request exhausts burst capacity -> 429 Too Many Requests
	req6 := newTestRequest("GET", "/burst/test", clientIP, "BurstAgent")
	res6 := engine.EvaluateRequest(req6, policy)
	if !res6.Blocked || res6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 6th request exceeding burst capacity to be rate limited (429), got blocked=%v, code=%d",
			res6.Blocked, res6.StatusCode)
	}
}
