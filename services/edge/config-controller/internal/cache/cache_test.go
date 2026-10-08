package cache_test

import (
	"net/http"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/cache"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

func TestCacheKeyNormalization(t *testing.T) {
	policy := &model.CachePolicy{
		CacheEnabled: true,
	}

	// 1. Lexicographical Sorting: ?b=2&a=1 should equal ?a=1&b=2
	key1 := cache.GenerateCacheKey("https", "api.example.com", "/items", "b=2&a=1", nil, policy, nil)
	key2 := cache.GenerateCacheKey("https", "api.example.com", "/items", "a=1&b=2", nil, policy, nil)
	if key1 != key2 {
		t.Fatalf("expected keys to be identical after query sorting, got %q vs %q", key1, key2)
	}

	// 2. Ignore All Query Strings
	ruleIgnoreAll := &model.CacheRule{
		QueryHandling: model.QueryStringIgnoreAll,
	}
	keyWithQuery := cache.GenerateCacheKey("https", "api.example.com", "/logo.png", "v=1.2.3&token=xyz", nil, policy, ruleIgnoreAll)
	keyWithoutQuery := cache.GenerateCacheKey("https", "api.example.com", "/logo.png", "", nil, policy, ruleIgnoreAll)
	if keyWithQuery != keyWithoutQuery {
		t.Fatalf("expected query string to be ignored, got %q vs %q", keyWithQuery, keyWithoutQuery)
	}

	// 3. Ignore Selected Tracking Parameters (utm_source, gclid)
	ruleIgnoreTracking := &model.CacheRule{
		QueryHandling: model.QueryStringIgnoreSelected,
		IgnoredParams: []string{"utm_source", "utm_medium", "fbclid"},
	}
	keyTracking := cache.GenerateCacheKey("https", "api.example.com", "/product", "id=42&utm_source=twitter&utm_medium=social", nil, policy, ruleIgnoreTracking)
	keyClean := cache.GenerateCacheKey("https", "api.example.com", "/product", "id=42", nil, policy, ruleIgnoreTracking)
	if keyTracking != keyClean {
		t.Fatalf("expected tracking parameters to be stripped, got %q vs %q", keyTracking, keyClean)
	}

	// 4. Custom Header Vary in Cache Key
	ruleWithHeader := &model.CacheRule{
		CustomHeadersToInclude: []string{"Accept-Encoding"},
	}
	headersGzip := http.Header{"Accept-Encoding": []string{"gzip"}}
	headersBr := http.Header{"Accept-Encoding": []string{"br"}}
	headersEmpty := http.Header{"Accept-Encoding": []string{""}}
	headersAbsent := http.Header{}

	keyGzip := cache.GenerateCacheKey("https", "api.example.com", "/data", "", headersGzip, policy, ruleWithHeader)
	keyBr := cache.GenerateCacheKey("https", "api.example.com", "/data", "", headersBr, policy, ruleWithHeader)
	keyEmpty := cache.GenerateCacheKey("https", "api.example.com", "/data", "", headersEmpty, policy, ruleWithHeader)
	keyAbsent := cache.GenerateCacheKey("https", "api.example.com", "/data", "", headersAbsent, policy, ruleWithHeader)

	if keyGzip == keyBr {
		t.Fatalf("expected distinct cache keys for different Accept-Encoding headers")
	}
	if keyEmpty == keyAbsent {
		t.Fatalf("expected distinct cache keys for empty header (%q) vs absent header (%q)", keyEmpty, keyAbsent)
	}
	if keyEmpty == keyGzip || keyAbsent == keyGzip {
		t.Fatalf("expected empty/absent header keys to differ from value-bearing keys")
	}
}

func TestRequestCacheability(t *testing.T) {
	policy := &model.CachePolicy{CacheEnabled: true}

	// GET request is cacheable
	reqGet, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	ok, _ := cache.IsRequestCacheable(reqGet, policy)
	if !ok {
		t.Errorf("expected GET to be cacheable")
	}

	// POST is not cacheable
	reqPost, _ := http.NewRequest(http.MethodPost, "https://api.example.com/data", nil)
	ok, _ = cache.IsRequestCacheable(reqPost, policy)
	if ok {
		t.Errorf("expected POST to not be cacheable")
	}

	// Authorization header is not blindly shared (Golden rule)
	reqAuth, _ := http.NewRequest(http.MethodGet, "https://api.example.com/user/profile", nil)
	reqAuth.Header.Set("Authorization", "Bearer secret-token")
	ok, reason := cache.IsRequestCacheable(reqAuth, policy)
	if ok {
		t.Errorf("expected Authorization-bearing request to bypass cache, reason: %s", reason)
	}

	// Cache-Control: no-store
	reqNoStore, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	reqNoStore.Header.Set("Cache-Control", "no-store")
	ok, _ = cache.IsRequestCacheable(reqNoStore, policy)
	if ok {
		t.Errorf("expected request with no-store to bypass cache")
	}
}

func TestResponseCacheability(t *testing.T) {
	policy := &model.CachePolicy{
		CacheEnabled:         true,
		DefaultTTLSeconds:    1800,
		RespectOriginHeaders: true,
	}

	// 1. Standard 200 OK with public Cache-Control
	h1 := http.Header{"Cache-Control": []string{"public, max-age=600"}}
	ok, ttl, _ := cache.IsResponseCacheable(200, h1, policy)
	if !ok || ttl != 600 {
		t.Errorf("expected 200 with max-age=600 to be cacheable with ttl 600, got ok=%v, ttl=%d", ok, ttl)
	}

	// 2. Private Cache-Control must NOT be cached
	hPrivate := http.Header{"Cache-Control": []string{"private, max-age=3600"}}
	ok, _, _ = cache.IsResponseCacheable(200, hPrivate, policy)
	if ok {
		t.Errorf("expected Cache-Control: private to NOT be cached")
	}

	// 3. no-store Cache-Control must NOT be cached
	hNoStore := http.Header{"Cache-Control": []string{"no-store"}}
	ok, _, _ = cache.IsResponseCacheable(200, hNoStore, policy)
	if ok {
		t.Errorf("expected Cache-Control: no-store to NOT be cached")
	}

	// 4. Set-Cookie header must NOT be cached (Security risk) even with StripCookies=true
	hCookie := http.Header{"Set-Cookie": []string{"session_id=secret; Path=/; Secure"}}
	ok, _, _ = cache.IsResponseCacheable(200, hCookie, policy)
	if ok {
		t.Errorf("expected Set-Cookie response to NOT be cached")
	}

	policyStrip := &model.CachePolicy{
		CacheEnabled: true,
		StripCookies: true,
	}
	ok, _, _ = cache.IsResponseCacheable(200, hCookie, policyStrip)
	if ok {
		t.Errorf("expected Set-Cookie response to NOT be cached even with StripCookies=true")
	}

	// 5. 500 Internal Server Error must NOT be cached
	ok, _, _ = cache.IsResponseCacheable(500, http.Header{}, policy)
	if ok {
		t.Errorf("expected 500 error to NOT be cached")
	}
}

func TestRequestCacheability_CookieRejected(t *testing.T) {
	policy := &model.CachePolicy{CacheEnabled: true}
	reqCookie, _ := http.NewRequest(http.MethodGet, "https://api.example.com/dashboard", nil)
	reqCookie.Header.Set("Cookie", "session=user-A")
	ok, reason := cache.IsRequestCacheable(reqCookie, policy)
	if ok {
		t.Fatalf("expected Cookie-bearing request to be non-cacheable")
	}
	if reason != "request contains Cookie header" {
		t.Errorf("unexpected rejection reason: %s", reason)
	}
}

func TestCacheEngineLookupStorePurge(t *testing.T) {
	engine := cache.NewCacheEngine(100)
	key := "https://api.example.com/logo.png"

	// 1. Initial lookup -> MISS
	_, status := engine.Lookup(key)
	if status != cache.CacheStatusMiss {
		t.Fatalf("expected MISS on empty cache, got %s", status)
	}

	// 2. Store response with TTL 2 seconds
	headers := map[string]string{"Content-Type": "image/png"}
	body := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes
	engine.Store(key, 200, headers, body, 2)

	// 3. Immediate lookup -> HIT
	cached, status := engine.Lookup(key)
	if status != cache.CacheStatusHit {
		t.Fatalf("expected HIT after store, got %s", status)
	}
	if cached.StatusCode != 200 || len(cached.Body) != 4 {
		t.Fatalf("cached data mismatch: %+v", cached)
	}
	if cached.Age() < 0 {
		t.Errorf("invalid age")
	}

	// 4. Purge key
	purged := engine.Purge(key)
	if purged != 1 {
		t.Fatalf("expected 1 key purged, got %d", purged)
	}

	// 5. Lookup after purge -> MISS
	_, status = engine.Lookup(key)
	if status != cache.CacheStatusMiss {
		t.Fatalf("expected MISS after purge, got %s", status)
	}
}
