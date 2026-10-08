package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

type CacheStatus string

const (
	CacheStatusHit     CacheStatus = "HIT"
	CacheStatusMiss    CacheStatus = "MISS"
	CacheStatusBypass  CacheStatus = "BYPASS"
	CacheStatusExpired CacheStatus = "EXPIRED"
)

// CachedResponse represents a cached HTTP response entry in memory or edge storage
type CachedResponse struct {
	Key        string            `json:"key"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
	CachedAt   time.Time         `json:"cached_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	TTLSeconds int               `json:"ttl_seconds"`
	ETag       string            `json:"etag"`
}

// Age returns the age in seconds since the response was cached
func (c *CachedResponse) Age() int {
	return int(time.Since(c.CachedAt).Seconds())
}

// CacheEngine manages edge caching, key normalization, evaluation, and invalidation
type CacheEngine struct {
	mu      sync.RWMutex
	storage map[string]*CachedResponse // cacheKey -> CachedResponse
	maxKeys int
}

func NewCacheEngine(maxKeys int) *CacheEngine {
	if maxKeys <= 0 {
		maxKeys = 100000
	}
	return &CacheEngine{
		storage: make(map[string]*CachedResponse),
		maxKeys: maxKeys,
	}
}

// GenerateCacheKey produces a deterministic, normalized cache key according to domain policy
func GenerateCacheKey(scheme, host, path, rawQuery string, reqHeaders http.Header, policy *model.CachePolicy, rule *model.CacheRule) string {
	scheme = strings.ToLower(scheme)
	if scheme == "" {
		scheme = "https"
	}
	host = strings.ToLower(strings.TrimSpace(host))
	path = "/" + strings.TrimPrefix(path, "/")

	// 1. Determine query string handling mode
	queryMode := model.QueryStringIncludeAll
	var ignoredParams []string
	var includedParams []string
	var customHeaders []string

	if policy != nil {
		if policy.QueryHandling != "" {
			queryMode = policy.QueryHandling
		}
	}

	if rule != nil {
		if rule.QueryHandling != "" {
			queryMode = rule.QueryHandling
		}
		ignoredParams = rule.IgnoredParams
		includedParams = rule.IncludedParams
		customHeaders = rule.CustomHeadersToInclude
	}

	// 2. Normalize Query String
	normalizedQuery := normalizeQueryString(rawQuery, queryMode, ignoredParams, includedParams)

	// 3. Base Key: scheme://host/path[?query]
	baseKey := fmt.Sprintf("%s://%s%s", scheme, host, path)
	if normalizedQuery != "" {
		baseKey = fmt.Sprintf("%s?%s", baseKey, normalizedQuery)
	}

	// 4. Custom Vary Headers in Key
	if len(customHeaders) > 0 {
		sort.Strings(customHeaders)
		var headerParts []string
		for _, h := range customHeaders {
			val, present := getHeaderPresence(reqHeaders, h)
			if !present {
				headerParts = append(headerParts, fmt.Sprintf("%s=__absent__", strings.ToLower(h)))
			} else {
				headerParts = append(headerParts, fmt.Sprintf("%s=%s", strings.ToLower(h), strings.TrimSpace(val)))
			}
		}
		if len(headerParts) > 0 {
			baseKey = fmt.Sprintf("%s#headers:%s", baseKey, strings.Join(headerParts, ";"))
		}
	}

	return baseKey
}

func getHeaderPresence(headers http.Header, name string) (string, bool) {
	if headers == nil {
		return "", false
	}
	if vals, ok := headers[http.CanonicalHeaderKey(name)]; ok {
		return strings.Join(vals, ","), true
	}
	lowerName := strings.ToLower(name)
	for k, vals := range headers {
		if strings.ToLower(k) == lowerName {
			return strings.Join(vals, ","), true
		}
	}
	return "", false
}

func normalizeQueryString(rawQuery string, mode model.QueryStringHandling, ignored, included []string) string {
	if rawQuery == "" || mode == model.QueryStringIgnoreAll {
		return ""
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}

	ignoreMap := make(map[string]bool)
	for _, k := range ignored {
		ignoreMap[strings.ToLower(k)] = true
	}

	includeMap := make(map[string]bool)
	for _, k := range included {
		includeMap[strings.ToLower(k)] = true
	}

	var keys []string
	for k := range values {
		lowerK := strings.ToLower(k)
		if mode == model.QueryStringIgnoreSelected && ignoreMap[lowerK] {
			continue // Drop ignored parameters (e.g. utm_source, gclid)
		}
		if mode == model.QueryStringIncludeSelected && !includeMap[lowerK] {
			continue // Only keep selected parameters
		}
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			pairs = append(pairs, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
		}
	}

	return strings.Join(pairs, "&")
}

// IsRequestCacheable verifies RFC 9111 request cacheability rules
func IsRequestCacheable(req *http.Request, policy *model.CachePolicy) (bool, string) {
	if policy == nil || !policy.CacheEnabled {
		return false, "caching is disabled in domain policy"
	}

	// 1. Method must be GET or HEAD
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false, fmt.Sprintf("HTTP method %s is not cacheable", req.Method)
	}

	// 2. Authorization-bearing request: never blindly shared (Section 15)
	if auth := req.Header.Get("Authorization"); auth != "" {
		return false, "request contains Authorization header"
	}

	// 3. Request Cache-Control: no-store
	if cc := req.Header.Get("Cache-Control"); strings.Contains(strings.ToLower(cc), "no-store") {
		return false, "request specifies Cache-Control: no-store"
	}

	return true, ""
}

// IsResponseCacheable verifies RFC 9111 & Cloudflare response cacheability rules
func IsResponseCacheable(statusCode int, respHeaders http.Header, policy *model.CachePolicy) (bool, int, string) {
	if policy == nil || !policy.CacheEnabled {
		return false, 0, "caching disabled"
	}

	// 1. Status Code Check (RFC 9111 cacheable status codes)
	cacheableCodes := map[int]bool{
		200: true, 203: true, 204: true, 206: true,
		300: true, 301: true, 404: true, 410: true,
	}
	if !cacheableCodes[statusCode] {
		return false, 0, fmt.Sprintf("HTTP status code %d is not cacheable", statusCode)
	}

	// 2. Cookie Check: responses setting cookies must not be cached (Section 15)
	if setCookie := respHeaders.Get("Set-Cookie"); setCookie != "" && !policy.StripCookies {
		return false, 0, "response contains Set-Cookie header"
	}

	// 3. Cache-Control Header Check
	cc := strings.ToLower(respHeaders.Get("Cache-Control"))
	if policy.RespectOriginHeaders {
		if strings.Contains(cc, "no-store") {
			return false, 0, "origin Cache-Control: no-store"
		}
		if strings.Contains(cc, "private") {
			return false, 0, "origin Cache-Control: private"
		}
	}

	// 4. Calculate TTL
	ttl := policy.DefaultTTLSeconds
	if ttl <= 0 {
		ttl = 3600 // 1 hour default
	}

	// Check origin s-maxage or max-age
	if policy.RespectOriginHeaders && cc != "" {
		if sMaxAge := parseDirectiveSeconds(cc, "s-maxage="); sMaxAge >= 0 {
			if sMaxAge == 0 {
				return false, 0, "origin Cache-Control: s-maxage=0"
			}
			ttl = sMaxAge
		} else if maxAge := parseDirectiveSeconds(cc, "max-age="); maxAge >= 0 {
			if maxAge == 0 {
				return false, 0, "origin Cache-Control: max-age=0"
			}
			ttl = maxAge
		}
	}

	return true, ttl, ""
}

func parseDirectiveSeconds(cc, directive string) int {
	idx := strings.Index(cc, directive)
	if idx == -1 {
		return -1
	}
	sub := cc[idx+len(directive):]
	end := strings.IndexAny(sub, ", ;")
	if end != -1 {
		sub = sub[:end]
	}
	val, err := strconv.Atoi(strings.TrimSpace(sub))
	if err != nil {
		return -1
	}
	return val
}

// FindMatchingRule matches request path against customer cache rules (wildcard/prefix support)
func FindMatchingRule(path string, rules []model.CacheRule) *model.CacheRule {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if matchPath(path, r.PathPattern) {
			return &r
		}
	}
	return nil
}

func matchPath(path, pattern string) bool {
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	if strings.HasPrefix(pattern, "*.") {
		ext := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(strings.ToLower(path), "."+strings.ToLower(ext))
	}
	return path == pattern
}

// Lookup queries the cache for a given key
func (e *CacheEngine) Lookup(key string) (*CachedResponse, CacheStatus) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	item, exists := e.storage[key]
	if !exists {
		return nil, CacheStatusMiss
	}

	if time.Now().After(item.ExpiresAt) {
		return item, CacheStatusExpired
	}

	return item, CacheStatusHit
}

// Store writes a response into the cache
func (e *CacheEngine) Store(key string, statusCode int, headers map[string]string, body []byte, ttlSeconds int) *CachedResponse {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.storage) >= e.maxKeys {
		evicted := false
		for k, v := range e.storage {
			if time.Now().After(v.ExpiresAt) {
				delete(e.storage, k)
				evicted = true
				break
			}
		}
		if !evicted {
			// Enforce hard bound: evict arbitrary key if none are expired (Finding 20)
			for k := range e.storage {
				delete(e.storage, k)
				break
			}
		}
	}

	now := time.Now().UTC()
	hash := sha256.Sum256(body)
	etag := fmt.Sprintf(`W/"%s"`, hex.EncodeToString(hash[:8]))

	cached := &CachedResponse{
		Key:        key,
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		CachedAt:   now,
		ExpiresAt:  now.Add(time.Duration(ttlSeconds) * time.Second),
		TTLSeconds: ttlSeconds,
		ETag:       etag,
	}

	e.storage[key] = cached
	return cached
}

// Purge invalidates cached entries matching a specific URL or prefix pattern (Finding 20)
func (e *CacheEngine) Purge(target string) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	purged := 0
	target = strings.TrimSpace(target)

	for k := range e.storage {
		if target == "*" || k == target || strings.HasPrefix(k, target) ||
			strings.HasPrefix(k, "https://"+target) || strings.HasPrefix(k, "http://"+target) {
			delete(e.storage, k)
			purged++
		}
	}

	return purged
}
