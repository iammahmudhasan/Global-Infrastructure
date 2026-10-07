package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	// OWASP CRS Core Attack Signatures
	sqliPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|drop\s+database)`),
		regexp.MustCompile(`(?i)('.*or.*'.*=|'.*or.*1\s*=\s*1|--\s*$|/\*.*\*/)`),
		regexp.MustCompile(`(?i)(exec(\s|\+)+(s|x)p\w+|benchmark\s*\(|sleep\s*\(\s*\d+\s*\))`),
	}

	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(<script[^>]*>.*?</script>|<script[^>]*>)`),
		regexp.MustCompile(`(?i)(javascript\s*:\s*|vbscript\s*:\s*|data\s*:\s*text/html)`),
		regexp.MustCompile(`(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|eval\s*\()`),
	}

	pathTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows|boot\.ini)`),
		regexp.MustCompile(`(?i)(/proc/self/|/WEB-INF/|/META-INF/)`),
	}

	rcePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(/bin/(ba)?sh|/bin/zsh|cmd\.exe|powershell(\.exe)?(\s+-enc)?)`),
		regexp.MustCompile(`(?i)(\|\s*(ba)?sh|;\s*cat\s+/|;\s*rm\s+-rf)`),
	}

	scannerUAPatterns = regexp.MustCompile(`(?i)(sqlmap|nikto|acunetix|nessus|masscan|zgrab|nmap)`)
)

type EvaluationResult struct {
	Blocked       bool
	StatusCode    int
	RuleTriggered string
	Action        model.WAFAction
	Reason        string
}

// WAFEngine executes line-rate security inspection
type WAFEngine struct {
	mu           sync.RWMutex
	rateLimiters map[string]*TokenBucket
}

func NewWAFEngine() *WAFEngine {
	return &WAFEngine{
		rateLimiters: make(map[string]*TokenBucket),
	}
}

// EvaluateRequest checks an incoming request against domain policy, OWASP CRS, and customer rules
func (e *WAFEngine) EvaluateRequest(req *http.Request, policy *model.SecurityPolicy) EvaluationResult {
	if policy == nil || !policy.WAFEnabled {
		return EvaluationResult{Blocked: false, Action: model.WAFActionAllow}
	}

	clientIP := extractClientIP(req)
	path := req.URL.Path
	rawQuery := req.URL.RawQuery
	userAgent := req.UserAgent()

	// 1. Check Customer WAF Rules (Highest Priority: IP, Path, Headers)
	for _, rule := range policy.WAFRules {
		if !rule.Enabled {
			continue
		}

		matched := false
		switch rule.MatchType {
		case model.WAFMatchIPCIDR:
			matched = matchIPCIDR(clientIP, rule.Pattern)
		case model.WAFMatchPathPrefix:
			matched = strings.HasPrefix(path, rule.Pattern)
		case model.WAFMatchHeader:
			parts := strings.SplitN(rule.Pattern, ":", 2)
			if len(parts) == 2 {
				headerVal := req.Header.Get(strings.TrimSpace(parts[0]))
				matched = strings.Contains(strings.ToLower(headerVal), strings.ToLower(strings.TrimSpace(parts[1])))
			}
		case model.WAFMatchQueryParam:
			matched = strings.Contains(strings.ToLower(rawQuery), strings.ToLower(rule.Pattern))
		}

		if matched {
			if rule.Action == model.WAFActionBlock {
				return EvaluationResult{
					Blocked:       true,
					StatusCode:    http.StatusForbidden,
					RuleTriggered: fmt.Sprintf("custom_rule_%s", rule.Name),
					Action:        model.WAFActionBlock,
					Reason:        fmt.Sprintf("blocked by custom rule: %s", rule.Name),
				}
			}
			if rule.Action == model.WAFActionAllow {
				return EvaluationResult{
					Blocked:       false,
					RuleTriggered: fmt.Sprintf("custom_rule_%s", rule.Name),
					Action:        model.WAFActionAllow,
				}
			}
		}
	}

	// 2. OWASP CRS Attack Signatures (if enabled or default WAF enabled)
	unescapedQuery, err := url.QueryUnescape(rawQuery)
	if err != nil {
		unescapedQuery = rawQuery
	}
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		unescapedPath = path
	}
	fullTarget := fmt.Sprintf("%s?%s %s %s?%s", path, rawQuery, userAgent, unescapedPath, unescapedQuery)

	// A. Scanner User-Agent check
	if scannerUAPatterns.MatchString(userAgent) {
		return EvaluationResult{
			Blocked:       policy.WAFMode == "BLOCK",
			StatusCode:    http.StatusForbidden,
			RuleTriggered: "OWASP_CRS_MALICIOUS_SCANNER",
			Action:        model.WAFActionBlock,
			Reason:        fmt.Sprintf("malicious security scanner detected in User-Agent: %s", userAgent),
		}
	}

	// B. Path Traversal check
	for _, p := range pathTraversalPatterns {
		if p.MatchString(fullTarget) {
			return EvaluationResult{
				Blocked:       policy.WAFMode == "BLOCK",
				StatusCode:    http.StatusForbidden,
				RuleTriggered: "OWASP_CRS_PATH_TRAVERSAL",
				Action:        model.WAFActionBlock,
				Reason:        "directory traversal attempt detected in request path/query",
			}
		}
	}

	// C. SQL Injection check
	for _, p := range sqliPatterns {
		if p.MatchString(fullTarget) {
			return EvaluationResult{
				Blocked:       policy.WAFMode == "BLOCK",
				StatusCode:    http.StatusForbidden,
				RuleTriggered: "OWASP_CRS_SQL_INJECTION",
				Action:        model.WAFActionBlock,
				Reason:        "SQL injection signature detected in request URI/parameters",
			}
		}
	}

	// D. Cross-Site Scripting (XSS) check
	for _, p := range xssPatterns {
		if p.MatchString(fullTarget) {
			return EvaluationResult{
				Blocked:       policy.WAFMode == "BLOCK",
				StatusCode:    http.StatusForbidden,
				RuleTriggered: "OWASP_CRS_CROSS_SITE_SCRIPTING",
				Action:        model.WAFActionBlock,
				Reason:        "XSS pattern detected in request URI/parameters",
			}
		}
	}

	// E. Remote Code Execution check
	for _, p := range rcePatterns {
		if p.MatchString(fullTarget) {
			return EvaluationResult{
				Blocked:       policy.WAFMode == "BLOCK",
				StatusCode:    http.StatusForbidden,
				RuleTriggered: "OWASP_CRS_COMMAND_INJECTION",
				Action:        model.WAFActionBlock,
				Reason:        "command injection / RCE signature detected",
			}
		}
	}

	// 3. Rate Limiting Check
	if policy.RateLimitEnabled {
		limitRPM := policy.RateLimitRPM
		if limitRPM <= 0 {
			limitRPM = 1000
		}

		// Check if a path-specific rate limit rule overrides the default
		for _, rlRule := range policy.RateLimitRules {
			if rlRule.Enabled && strings.HasPrefix(path, rlRule.PathPrefix) {
				limitRPM = rlRule.RequestsPerMinute
				break
			}
		}

		limiterKey := fmt.Sprintf("%s:%s", policy.DomainID, clientIP)
		if !e.allowRate(limiterKey, limitRPM) {
			return EvaluationResult{
				Blocked:       true,
				StatusCode:    http.StatusTooManyRequests,
				RuleTriggered: "RATE_LIMIT_EXCEEDED",
				Action:        model.WAFActionBlock,
				Reason:        fmt.Sprintf("rate limit of %d requests/min exceeded for client %s", limitRPM, clientIP),
			}
		}
	}

	return EvaluationResult{
		Blocked: false,
		Action:  model.WAFActionAllow,
	}
}

// TokenBucket implements sliding rate limiting per IP
type TokenBucket struct {
	tokens     float64
	capacity   float64
	ratePerSec float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func (e *WAFEngine) allowRate(key string, rpm int) bool {
	e.mu.Lock()
	tb, exists := e.rateLimiters[key]
	if !exists {
		capacity := float64(rpm)
		tb = &TokenBucket{
			tokens:     capacity,
			capacity:   capacity,
			ratePerSec: float64(rpm) / 60.0,
			lastUpdate: time.Now(),
		}
		e.rateLimiters[key] = tb
	}
	e.mu.Unlock()

	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	// Refill tokens
	tb.tokens += elapsed * tb.ratePerSec
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

func extractClientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}

func matchIPCIDR(clientIP, pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			ip := net.ParseIP(clientIP)
			return ip != nil && ipNet.Contains(ip)
		}
	}
	return clientIP == pattern
}

func GenerateEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("sec-ev-%s", hex.EncodeToString(b))
}
