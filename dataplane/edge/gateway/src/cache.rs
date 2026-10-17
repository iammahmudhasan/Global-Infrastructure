use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::StatusCode;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached HTTP response entry conforming to RFC 9111.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub expires_at: Instant,
    /// Set of (lowercase_header_name, Option<request_header_value>) required by origin's Vary header.
    /// None distinguishes header absence from Some("") which represents an empty header value (RFC 9111 Section 4.1).
    pub vary_headers: Vec<(String, Option<String>)>,
}

impl CachedResponse {
    /// Calculate the memory footprint of this cached entry
    pub fn size_in_bytes(&self) -> usize {
        let headers_bytes: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 32)
            .sum();
        let vary_bytes: usize = self
            .vary_headers
            .iter()
            .map(|(k, v)| k.len() + v.as_ref().map_or(0, |s| s.len()) + 32)
            .sum();
        self.body.len() + headers_bytes + vary_bytes + 64
    }
}

/// Min-heap index entry for O(log N) earliest-expiry eviction (Finding 6)
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpiryIndexEntry {
    expires_at: Instant,
    key: String,
    vary_headers: Vec<(String, Option<String>)>,
}

impl Ord for ExpiryIndexEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering so BinaryHeap functions as a min-heap on expires_at
        other
            .expires_at
            .cmp(&self.expires_at)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for ExpiryIndexEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct CacheStore {
    current_bytes: usize,
    total_entries: usize,
    entries: HashMap<String, Vec<CachedResponse>>,
    expiry_heap: BinaryHeap<ExpiryIndexEntry>,
}

impl CacheStore {
    fn remove_variant(&mut self, candidate: &ExpiryIndexEntry) -> bool {
        let removed_bytes = self.entries.get_mut(&candidate.key).and_then(|variants| {
            variants
                .iter()
                .position(|v| {
                    v.expires_at == candidate.expires_at && v.vary_headers == candidate.vary_headers
                })
                .map(|idx| variants.remove(idx).size_in_bytes())
        });

        if let Some(bytes) = removed_bytes {
            self.current_bytes = self.current_bytes.saturating_sub(bytes);
            self.total_entries = self.total_entries.saturating_sub(1);
            if let Some(variants) = self.entries.get(&candidate.key) {
                if variants.is_empty() {
                    self.entries.remove(&candidate.key);
                }
            }
            true
        } else {
            false
        }
    }
}

/// Parsed representation of RFC 9111 Cache-Control directives
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheControlDirectives {
    pub no_cache: bool,
    pub no_store: bool,
    pub private: bool,
    pub public: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
}

/// Parses comma-separated and multi-line RFC 9111 Cache-Control directives in a structured manner.
/// Handles standalone tokens (e.g. `no-cache`, `no-store`) and parameterized tokens (e.g. `max-age=3600`, `no-cache="set-cookie"`).
pub fn parse_cache_control<I, S>(header_values: I) -> CacheControlDirectives
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut directives = CacheControlDirectives::default();

    for line in header_values {
        for part in line.as_ref().split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut kv = trimmed.splitn(2, '=');
            let name = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let val = kv.next().map(|v| v.trim().trim_matches('"'));

            match name.as_str() {
                "no-cache" => directives.no_cache = true,
                "no-store" => directives.no_store = true,
                "private" => directives.private = true,
                "public" => directives.public = true,
                "max-age" => {
                    if let Some(v_str) = val {
                        if let Ok(secs) = v_str.parse::<u64>() {
                            directives.max_age = Some(secs);
                        }
                    }
                }
                "s-maxage" => {
                    if let Some(v_str) = val {
                        if let Ok(secs) = v_str.parse::<u64>() {
                            directives.s_maxage = Some(secs);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    directives
}

/// Parses an HTTP date string according to RFC 9110 Section 5.6.7 formats:
/// 1. IMF-fixdate (e.g., "Sun, 06 Nov 1994 08:49:37 GMT")
/// 2. RFC 850 format (e.g., "Sunday, 06-Nov-94 08:49:37 GMT")
/// 3. ANSI C's asctime() format (e.g., "Sun Nov  6 08:49:37 1994")
pub fn parse_http_date(date_str: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = date_str.trim();
    if s.is_empty() {
        return None;
    }

    // 1. Preferred IMF-fixdate (RFC 2822 format)
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }

    // 2. Direct format match for "Sun, 06 Nov 1994 08:49:37 GMT"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%a, %d %b %Y %H:%M:%S GMT") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(
            naive,
            chrono::Utc,
        ));
    }

    // 3. Obsolete RFC 850 format "Sunday, 06-Nov-94 08:49:37 GMT"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%A, %d-%b-%y %H:%M:%S GMT") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(
            naive,
            chrono::Utc,
        ));
    }

    // 4. Obsolete ANSI C asctime() format "Sun Nov  6 08:49:37 1994"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%a %b %e %H:%M:%S %Y") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(
            naive,
            chrono::Utc,
        ));
    }

    None
}

/// Evaluates RFC 9111 Section 4.2 Freshness and Age calculation.
/// Returns Some(remaining_freshness_duration) if the response is fresh and cacheable,
/// or None if the response is stale, uncacheable, or expired past origin deadline.
pub fn compute_rfc9111_freshness(
    resp_headers: &HeaderMap,
    default_ttl: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Duration> {
    let resp_cc_lines = resp_headers
        .get_all("cache-control")
        .iter()
        .filter_map(|v| v.to_str().ok());
    let resp_cc = parse_cache_control(resp_cc_lines);

    // RFC 9111 Section 5.2.2.4 / 5.2.2.5 / 5.2.2.7:
    // Reject responses marked no-store, private, or no-cache
    if resp_cc.no_store || resp_cc.private || resp_cc.no_cache {
        return None;
    }

    // Parse Date header (RFC 9110 Section 6.6.1)
    let date_val = resp_headers
        .get("date")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date)
        .unwrap_or(now);

    // 1. Freshness Lifetime (RFC 9111 Section 4.2.1)
    let freshness_lifetime: Duration = if let Some(s_max) = resp_cc.s_maxage {
        Duration::from_secs(s_max)
    } else if let Some(max_age) = resp_cc.max_age {
        Duration::from_secs(max_age)
    } else if let Some(expires_raw) = resp_headers.get("expires").and_then(|v| v.to_str().ok()) {
        // Handle explicit "0" or invalid as already expired per RFC 9111 Section 5.3
        if expires_raw.trim() == "0" {
            return None;
        }
        match parse_http_date(expires_raw) {
            Some(expires_dt) => {
                if expires_dt <= date_val || expires_dt <= now {
                    // Stale / past expiration deadline
                    return None;
                }
                match (expires_dt - date_val).to_std() {
                    Ok(dur) => dur,
                    Err(_) => return None,
                }
            }
            None => {
                // Invalid date in Expires treated as past (RFC 9111 Section 5.3)
                return None;
            }
        }
    } else {
        default_ttl
    };

    // 2. Current Age (RFC 9111 Section 4.2.3)
    let age_header_secs = resp_headers
        .get("age")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let apparent_age = if now > date_val {
        (now - date_val).to_std().unwrap_or(Duration::ZERO)
    } else {
        Duration::ZERO
    };

    let corrected_initial_age = apparent_age.max(Duration::from_secs(age_header_secs));
    let current_age = corrected_initial_age;

    // Remaining freshness = freshness_lifetime - current_age
    if current_age >= freshness_lifetime {
        // Age already consumed entire freshness lifetime
        return None;
    }

    let remaining = freshness_lifetime - current_age;
    Some(remaining)
}

/// Bounded earliest-expiry eviction cache with RFC 9111 Vary header and byte limit support.
#[derive(Clone)]
pub struct EdgeCache {
    enabled: bool,
    default_ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    store: Arc<RwLock<CacheStore>>,
}

impl EdgeCache {
    pub fn new(enabled: bool, ttl_seconds: u64, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            enabled,
            default_ttl: Duration::from_secs(ttl_seconds),
            max_entries,
            max_bytes: if max_bytes == 0 {
                100 * 1024 * 1024
            } else {
                max_bytes
            },
            store: Arc::new(RwLock::new(CacheStore::default())),
        }
    }

    /// Retrieve cached response matching primary key and incoming request headers for Vary verification
    pub fn get(&self, key: &str, req_headers: Option<&HeaderMap>) -> Option<CachedResponse> {
        if !self.enabled {
            return None;
        }

        // RFC 9111 Section 5.2.1.4 / 5.2.1.5: If incoming request specifies no-cache or no-store,
        // do not serve from cache without origin validation
        if let Some(h) = req_headers {
            let req_cc_lines = h
                .get_all("cache-control")
                .iter()
                .filter_map(|v| v.to_str().ok());
            let req_cc = parse_cache_control(req_cc_lines);
            if req_cc.no_cache || req_cc.no_store {
                return None;
            }
        }

        let store = self.store.read().unwrap();
        if let Some(variants) = store.entries.get(key) {
            let now = Instant::now();
            for entry in variants {
                if now < entry.expires_at {
                    // Verify that all Vary-nominated request headers match (RFC 9111 Section 4.1)
                    let mut matches = true;
                    for (vary_name, expected_val) in &entry.vary_headers {
                        let actual_val: Option<String> = req_headers
                            .and_then(|h| h.get(vary_name))
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        if actual_val != *expected_val {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        return Some(entry.clone());
                    }
                }
            }
        }
        None
    }

    /// Store a response with RFC 9111 Vary extraction and bounded capacity enforcement
    pub fn put(
        &self,
        key: String,
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        custom_ttl: Option<Duration>,
        req_headers: Option<&HeaderMap>,
    ) {
        if !self.enabled || self.max_entries == 0 || self.max_bytes == 0 || !status.is_success() {
            return;
        }

        // RFC 9111 Section 5.2.2.4 / 5.2.2.5 / 5.2.2.7:
        // Reject responses marked no-store, private, or no-cache (unvalidated reuse is forbidden)
        let resp_cc_lines = headers
            .get_all("cache-control")
            .iter()
            .filter_map(|v| v.to_str().ok());
        let resp_cc = parse_cache_control(resp_cc_lines);
        if resp_cc.no_store || resp_cc.private || resp_cc.no_cache {
            return;
        }

        // Reject storing if request specified no-store
        if let Some(req_h) = req_headers {
            let req_cc_lines = req_h
                .get_all("cache-control")
                .iter()
                .filter_map(|v| v.to_str().ok());
            let req_cc = parse_cache_control(req_cc_lines);
            if req_cc.no_store {
                return;
            }
        }

        // RFC 9111 Section 3.5: Shared caches MUST NOT store responses to requests with Authorization
        // header field unless a directive is present in the response that explicitly permits it
        // (such as public or s-maxage).
        if let Some(req_h) = req_headers {
            if req_h.contains_key("authorization")
                && !(resp_cc.public || resp_cc.s_maxage.is_some())
            {
                return;
            }
        }

        // Never store Set-Cookie in shared edge cache to prevent session leakage across tenants (RFC 6265)
        let mut headers = headers;
        headers.remove("set-cookie");

        // RFC 9111 Section 4.1: Reject Vary: * responses across all Vary header lines
        for vary_val in headers.get_all("vary").iter() {
            if let Ok(v_str) = vary_val.to_str() {
                if v_str.split(',').any(|part| part.trim() == "*") {
                    return;
                }
            }
        }

        // Extract Vary nominated headers across all response Vary lines
        let mut vary_headers = Vec::new();
        for vary_val in headers.get_all("vary").iter() {
            if let Ok(v_str) = vary_val.to_str() {
                for part in v_str.split(',') {
                    let name = part.trim().to_lowercase();
                    if name.is_empty() {
                        continue;
                    }
                    if vary_headers
                        .iter()
                        .any(|(existing, _): &(String, _)| existing == &name)
                    {
                        continue;
                    }
                    let val: Option<String> = req_headers
                        .and_then(|h| h.get(&name))
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    vary_headers.push((name, val));
                }
            }
        }

        // RFC 9111 Section 4.2: Enforce freshness calculation
        // Security Invariant: Even if custom_ttl is provided by customer rule, RFC 9111 uncacheable mandates
        // (no-store, private, no-cache, Vary: *, and un-authenticated Authorization) ALWAYS take precedence
        // and are strictly rejected. Custom TTL only overrides origin freshness duration on otherwise cacheable responses.
        let ttl = match custom_ttl {
            Some(t) => t,
            None => match compute_rfc9111_freshness(&headers, self.default_ttl, chrono::Utc::now())
            {
                Some(fresh) => fresh,
                None => return, // Uncacheable or already expired per RFC 9111
            },
        };
        const MAX_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days
        let ttl = ttl.min(MAX_CACHE_TTL);
        if ttl == Duration::ZERO {
            return;
        }
        let expires_at = match Instant::now().checked_add(ttl) {
            Some(at) => at,
            None => return, // Defensively drop unrepresentable Instant expiries
        };
        let entry = CachedResponse {
            status,
            headers,
            body,
            expires_at,
            vary_headers,
        };

        let entry_bytes = entry.size_in_bytes();
        if entry_bytes > self.max_bytes {
            return; // Individual entry exceeds entire cache capacity
        }

        let mut store = self.store.write().unwrap();

        // 1. If an exact variant already exists for this key, update in-place
        let existing_match = store.entries.get(&key).and_then(|variants| {
            variants
                .iter()
                .position(|v| v.vary_headers == entry.vary_headers)
                .map(|idx| (idx, variants[idx].size_in_bytes()))
        });
        if let Some((idx, old_bytes)) = existing_match {
            store.entries.get_mut(&key).unwrap()[idx] = entry.clone();
            store.current_bytes = store.current_bytes.saturating_sub(old_bytes) + entry_bytes;
            store.expiry_heap.push(ExpiryIndexEntry {
                expires_at: entry.expires_at,
                key,
                vary_headers: entry.vary_headers,
            });
            return;
        }

        // 2. Proactive eviction of expired entries using min-heap peek (O(log N))
        let now = Instant::now();
        while let Some(top) = store.expiry_heap.peek() {
            if top.expires_at > now {
                break;
            }
            let candidate = store.expiry_heap.pop().unwrap();
            store.remove_variant(&candidate);
        }

        // 3. Hard capacity guarantee (both count and byte budget): Evict earliest expiring entries via min-heap (O(log N))
        while (store.total_entries >= self.max_entries
            || store.current_bytes + entry_bytes > self.max_bytes)
            && !store.expiry_heap.is_empty()
        {
            if let Some(candidate) = store.expiry_heap.pop() {
                store.remove_variant(&candidate);
            }
        }

        if store.total_entries >= self.max_entries
            || store.current_bytes + entry_bytes > self.max_bytes
        {
            return;
        }

        // 4. Insert new variant and increment byte/entry counts
        store.current_bytes += entry_bytes;
        store.total_entries += 1;
        store.expiry_heap.push(ExpiryIndexEntry {
            expires_at: entry.expires_at,
            key: key.clone(),
            vary_headers: entry.vary_headers.clone(),
        });
        let variants = store.entries.entry(key).or_default();
        variants.push(entry);

        // 5. Periodic heap hygiene: compact heap if dead entries significantly exceed live entries
        if store.expiry_heap.len() > 1000 && store.expiry_heap.len() > store.total_entries * 3 {
            let mut new_heap = BinaryHeap::with_capacity(store.total_entries);
            for (k, variants) in &store.entries {
                for v in variants {
                    new_heap.push(ExpiryIndexEntry {
                        expires_at: v.expires_at,
                        key: k.clone(),
                        vary_headers: v.vary_headers.clone(),
                    });
                }
            }
            store.expiry_heap = new_heap;
        }
    }

    #[allow(dead_code)]
    pub fn purge(&self, key: &str) {
        let mut store = self.store.write().unwrap();
        if let Some(variants) = store.entries.remove(key) {
            let count = variants.len();
            for v in variants {
                store.current_bytes = store.current_bytes.saturating_sub(v.size_in_bytes());
            }
            store.total_entries = store.total_entries.saturating_sub(count);
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.store.read().unwrap().total_entries
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(dead_code)]
    pub fn current_bytes(&self) -> usize {
        self.store.read().unwrap().current_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn test_zero_max_entries_guard() {
        let cache = EdgeCache::new(true, 3600, 0, 1024 * 1024);
        let headers = HeaderMap::new();
        let body = Bytes::from("payload");

        cache.put(
            "k1".to_string(),
            StatusCode::OK,
            headers,
            body,
            Some(Duration::from_secs(10)),
            None,
        );
        assert_eq!(cache.len(), 0, "max_entries == 0 must never insert entries");
        assert!(cache.get("k1", None).is_none());
    }

    #[test]
    fn test_hard_max_entries_eviction() {
        let cache = EdgeCache::new(true, 3600, 2, 1024 * 1024);
        let headers = HeaderMap::new();
        let body = Bytes::from("payload");

        cache.put(
            "k1".to_string(),
            StatusCode::OK,
            headers.clone(),
            body.clone(),
            Some(Duration::from_secs(10)),
            None,
        );
        cache.put(
            "k2".to_string(),
            StatusCode::OK,
            headers.clone(),
            body.clone(),
            Some(Duration::from_secs(30)),
            None,
        );
        assert_eq!(cache.len(), 2);

        // Insert 3rd entry when capacity is 2; k1 has earlier expiry (10s vs 30s) so k1 must be evicted
        cache.put(
            "k3".to_string(),
            StatusCode::OK,
            headers,
            body,
            Some(Duration::from_secs(20)),
            None,
        );
        assert_eq!(cache.len(), 2);
        assert!(
            cache.get("k1", None).is_none(),
            "k1 should have been evicted"
        );
        assert!(cache.get("k2", None).is_some(), "k2 should be retained");
        assert!(cache.get("k3", None).is_some(), "k3 should be present");
    }

    #[test]
    fn test_vary_header_isolation() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("vary", HeaderValue::from_static("Origin, Accept-Language"));

        let mut req_headers_a = HeaderMap::new();
        req_headers_a.insert("origin", HeaderValue::from_static("https://tenant-a.com"));
        req_headers_a.insert("accept-language", HeaderValue::from_static("en-US"));

        let mut req_headers_b = HeaderMap::new();
        req_headers_b.insert("origin", HeaderValue::from_static("https://tenant-b.com"));
        req_headers_b.insert("accept-language", HeaderValue::from_static("en-US"));

        let body_a = Bytes::from("body-for-tenant-a");
        let body_b = Bytes::from("body-for-tenant-b");

        // Cache response for Tenant A
        cache.put(
            "http://example.com/api".to_string(),
            StatusCode::OK,
            resp_headers.clone(),
            body_a.clone(),
            Some(Duration::from_secs(60)),
            Some(&req_headers_a),
        );

        // Request from Tenant A should HIT
        let hit_a = cache.get("http://example.com/api", Some(&req_headers_a));
        assert!(hit_a.is_some());
        assert_eq!(hit_a.unwrap().body, body_a);

        // Request from Tenant B should MISS due to Vary mismatch
        let miss_b = cache.get("http://example.com/api", Some(&req_headers_b));
        assert!(
            miss_b.is_none(),
            "Tenant B must not receive Tenant A's cached response"
        );

        // Now cache response for Tenant B as variant
        cache.put(
            "http://example.com/api".to_string(),
            StatusCode::OK,
            resp_headers,
            body_b.clone(),
            Some(Duration::from_secs(60)),
            Some(&req_headers_b),
        );

        assert_eq!(cache.len(), 2, "Both variants should be stored");

        // Both now HIT their respective variants
        let hit_b = cache.get("http://example.com/api", Some(&req_headers_b));
        assert!(hit_b.is_some());
        assert_eq!(hit_b.unwrap().body, body_b);

        let hit_a_again = cache.get("http://example.com/api", Some(&req_headers_a));
        assert!(hit_a_again.is_some());
        assert_eq!(hit_a_again.unwrap().body, body_a);
    }

    #[test]
    fn test_vary_star_rejected() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("vary", HeaderValue::from_static("*"));

        cache.put(
            "http://example.com/dynamic".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from("dynamic-data"),
            Some(Duration::from_secs(60)),
            None,
        );

        assert_eq!(cache.len(), 0, "Vary: * must never be cached");
        assert!(cache.get("http://example.com/dynamic", None).is_none());
    }

    #[test]
    fn test_vary_missing_vs_empty_and_multiple_headers() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        // Multiple Vary header lines
        resp_headers.append("vary", HeaderValue::from_static("X-Custom-Auth"));
        resp_headers.append("vary", HeaderValue::from_static("Accept-Encoding"));

        // Case 1: X-Custom-Auth is absent
        let req_missing = HeaderMap::new();
        cache.put(
            "http://example.com/resource".to_string(),
            StatusCode::OK,
            resp_headers.clone(),
            Bytes::from("body-absent"),
            Some(Duration::from_secs(60)),
            Some(&req_missing),
        );

        // Case 2: X-Custom-Auth is present but empty string
        let mut req_empty = HeaderMap::new();
        req_empty.insert("x-custom-auth", HeaderValue::from_static(""));
        cache.put(
            "http://example.com/resource".to_string(),
            StatusCode::OK,
            resp_headers.clone(),
            Bytes::from("body-empty-val"),
            Some(Duration::from_secs(60)),
            Some(&req_empty),
        );

        // Verify they are stored as two separate variants
        assert_eq!(
            cache.len(),
            2,
            "Missing header and empty-string header must form distinct variants"
        );

        // Verify exact hits
        let hit_missing = cache
            .get("http://example.com/resource", Some(&req_missing))
            .unwrap();
        assert_eq!(hit_missing.body, Bytes::from("body-absent"));

        let hit_empty = cache
            .get("http://example.com/resource", Some(&req_empty))
            .unwrap();
        assert_eq!(hit_empty.body, Bytes::from("body-empty-val"));
    }

    #[test]
    fn test_in_place_variant_replacement_does_not_evict_other_entries() {
        // Cache at capacity limit 2
        let cache = EdgeCache::new(true, 3600, 2, 1024 * 1024);

        // Insert key1
        cache.put(
            "key1".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("initial-payload-1"),
            Some(Duration::from_secs(60)),
            None,
        );

        // Insert key2
        cache.put(
            "key2".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("initial-payload-2"),
            Some(Duration::from_secs(60)),
            None,
        );

        assert_eq!(cache.len(), 2, "cache should be at capacity 2");

        // Update key1 in-place (same variant)
        cache.put(
            "key1".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("updated-payload-1"),
            Some(Duration::from_secs(60)),
            None,
        );

        // Cache length should remain 2 (no eviction of key2!)
        assert_eq!(
            cache.len(),
            2,
            "in-place update must not evict other entries"
        );

        // key2 must still be present and intact
        let hit_k2 = cache.get("key2", None);
        assert!(
            hit_k2.is_some(),
            "key2 must NOT be evicted when key1 is updated in-place"
        );
        assert_eq!(hit_k2.unwrap().body, Bytes::from("initial-payload-2"));

        // key1 must have the updated payload
        let hit_k1 = cache.get("key1", None);
        assert!(hit_k1.is_some());
        assert_eq!(hit_k1.unwrap().body, Bytes::from("updated-payload-1"));
    }

    #[test]
    fn test_byte_limit_eviction() {
        // P1 Finding 1: EdgeCache hard byte limit enforcement
        let dummy_resp = CachedResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"sample"),
            expires_at: Instant::now(),
            vary_headers: vec![],
        };
        let single_entry_bytes = dummy_resp.size_in_bytes();

        // Allow max 100 entries, but only enough bytes for 1 entry
        let max_bytes = single_entry_bytes + 20;
        let cache = EdgeCache::new(true, 3600, 100, max_bytes);

        cache.put(
            "key1".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"sample"),
            Some(Duration::from_secs(10)),
            None,
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.current_bytes() <= max_bytes);

        // Inserting key2 should exceed byte limit and evict key1
        cache.put(
            "key2".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"sample"),
            Some(Duration::from_secs(20)),
            None,
        );

        assert_eq!(cache.len(), 1, "key1 should be evicted due to byte limit");
        assert!(cache.get("key1", None).is_none());
        assert!(cache.get("key2", None).is_some());
        assert!(cache.current_bytes() <= max_bytes);
    }

    #[test]
    fn test_cache_ttl_u64_max_does_not_panic() {
        // P2 Finding 2: Malicious or misconfigured upstream max-age=u64::MAX
        let cache = EdgeCache::new(true, 60, 10, 1024 * 1024);
        cache.put(
            "key-huge-ttl".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"data"),
            Some(Duration::from_secs(u64::MAX)),
            None,
        );
        // Must safely insert without panicking and clamped to MAX_CACHE_TTL
        assert_eq!(cache.len(), 1);
        let hit = cache.get("key-huge-ttl", None);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().body, Bytes::from_static(b"data"));
    }

    #[test]
    fn test_parse_cache_control_structured() {
        let lines = vec![
            "public, max-age=3600",
            "s-maxage=7200, no-cache=\"Set-Cookie\"",
        ];
        let cc = parse_cache_control(&lines);
        assert!(cc.public);
        assert!(cc.no_cache);
        assert!(!cc.no_store);
        assert!(!cc.private);
        assert_eq!(cc.max_age, Some(3600));
        assert_eq!(cc.s_maxage, Some(7200));
    }

    #[test]
    fn test_rfc9111_no_cache_response_never_stored() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_static("no-cache"));

        cache.put(
            "http://example.com/live".to_string(),
            StatusCode::OK,
            headers,
            Bytes::from_static(b"unvalidated-data"),
            Some(Duration::from_secs(60)),
            None,
        );

        assert_eq!(
            cache.len(),
            0,
            "RFC 9111 response with no-cache must not be stored"
        );
        assert!(cache.get("http://example.com/live", None).is_none());
    }

    #[test]
    fn test_rfc9111_no_cache_qualified_and_multiline_never_stored() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut headers = HeaderMap::new();
        headers.append(
            "cache-control",
            HeaderValue::from_static("public, max-age=3600"),
        );
        headers.append(
            "cache-control",
            HeaderValue::from_static("no-cache=\"set-cookie\""),
        );

        cache.put(
            "http://example.com/dynamic".to_string(),
            StatusCode::OK,
            headers,
            Bytes::from_static(b"data"),
            Some(Duration::from_secs(60)),
            None,
        );

        assert_eq!(
            cache.len(),
            0,
            "Qualified no-cache directive must not be stored"
        );
        assert!(cache.get("http://example.com/dynamic", None).is_none());
    }

    #[test]
    fn test_rfc9111_no_store_and_private_never_stored() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut h1 = HeaderMap::new();
        h1.insert("cache-control", HeaderValue::from_static("no-store"));
        cache.put(
            "http://example.com/secret1".to_string(),
            StatusCode::OK,
            h1,
            Bytes::from_static(b"secret"),
            None,
            None,
        );
        assert_eq!(cache.len(), 0);

        let mut h2 = HeaderMap::new();
        h2.insert("cache-control", HeaderValue::from_static("private"));
        cache.put(
            "http://example.com/secret2".to_string(),
            StatusCode::OK,
            h2,
            Bytes::from_static(b"secret"),
            None,
            None,
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_rfc9111_request_no_cache_bypasses_cached_response() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=3600"),
        );

        cache.put(
            "http://example.com/asset".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"cached-asset"),
            Some(Duration::from_secs(60)),
            None,
        );

        assert_eq!(cache.len(), 1);

        // Standard request hits
        let hit = cache.get("http://example.com/asset", None);
        assert!(hit.is_some());

        // Request with Cache-Control: no-cache must bypass cached response
        let mut req_no_cache = HeaderMap::new();
        req_no_cache.insert("cache-control", HeaderValue::from_static("no-cache"));
        let bypass = cache.get("http://example.com/asset", Some(&req_no_cache));
        assert!(
            bypass.is_none(),
            "Request Cache-Control: no-cache must bypass cache"
        );
    }

    #[test]
    fn test_rfc9111_expires_in_past_rejected() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "date",
            HeaderValue::from_static("Sat, 17 Oct 2026 06:00:00 GMT"),
        );
        resp_headers.insert(
            "expires",
            HeaderValue::from_static("Sat, 17 Oct 2026 05:00:00 GMT"),
        );

        let now = chrono::DateTime::parse_from_rfc2822("Sat, 17 Oct 2026 06:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert!(
            freshness.is_none(),
            "Response with Expires in the past must be uncacheable / stale"
        );

        cache.put(
            "http://example.com/stale-expires".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"stale-content"),
            None,
            None,
        );
        assert_eq!(
            cache.len(),
            0,
            "Stale expired response must never enter cache"
        );
    }

    #[test]
    fn test_rfc9111_expires_in_future_freshness() {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "date",
            HeaderValue::from_static("Sat, 17 Oct 2026 06:00:00 GMT"),
        );
        resp_headers.insert(
            "expires",
            HeaderValue::from_static("Sat, 17 Oct 2026 08:00:00 GMT"),
        );

        let now = chrono::DateTime::parse_from_rfc2822("Sat, 17 Oct 2026 06:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert_eq!(
            freshness,
            Some(Duration::from_secs(7200)),
            "Freshness lifetime should exactly match (Expires - Date)"
        );
    }

    #[test]
    fn test_rfc9111_age_header_deduction() {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=3600"),
        );
        resp_headers.insert("age", HeaderValue::from_static("3500"));

        let now = chrono::Utc::now();
        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert_eq!(
            freshness,
            Some(Duration::from_secs(100)),
            "Remaining freshness must deduct Age header (3600 - 3500 = 100)"
        );
    }

    #[test]
    fn test_rfc9111_age_exceeds_max_age_rejected() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=3600"),
        );
        resp_headers.insert("age", HeaderValue::from_static("3700"));

        let now = chrono::Utc::now();
        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert!(
            freshness.is_none(),
            "Response whose Age >= max-age is already stale"
        );

        cache.put(
            "http://example.com/stale-age".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"stale-content"),
            None,
            None,
        );
        assert_eq!(
            cache.len(),
            0,
            "Response with Age >= max-age must not be stored"
        );
    }

    #[test]
    fn test_rfc9111_max_age_precedence_over_expires() {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "date",
            HeaderValue::from_static("Sat, 17 Oct 2026 06:00:00 GMT"),
        );
        resp_headers.insert(
            "expires",
            HeaderValue::from_static("Sun, 17 Oct 2027 06:00:00 GMT"),
        );
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );

        let now = chrono::DateTime::parse_from_rfc2822("Sat, 17 Oct 2026 06:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert_eq!(
            freshness,
            Some(Duration::from_secs(60)),
            "RFC 9111 Section 4.2.1 mandates max-age overrides Expires"
        );
    }

    #[test]
    fn test_rfc9111_s_maxage_precedence_over_max_age() {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, s-maxage=120, max-age=60"),
        );

        let now = chrono::Utc::now();
        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert_eq!(
            freshness,
            Some(Duration::from_secs(120)),
            "RFC 9111 Section 4.2.1 mandates s-maxage overrides max-age in shared caches"
        );
    }

    #[test]
    fn test_rfc9111_expires_zero_treated_as_past() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("expires", HeaderValue::from_static("0"));

        let now = chrono::Utc::now();
        let freshness = compute_rfc9111_freshness(&resp_headers, Duration::from_secs(3600), now);
        assert!(
            freshness.is_none(),
            "Expires: 0 must be treated as time in the past per RFC 9111 Section 5.3"
        );

        cache.put(
            "http://example.com/expires-zero".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"never-cache"),
            None,
            None,
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_rfc9111_custom_ttl_cannot_override_no_store() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("cache-control", HeaderValue::from_static("no-store"));

        cache.put(
            "http://example.com/no-store".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"sensitive"),
            Some(Duration::from_secs(600)),
            None,
        );
        assert_eq!(
            cache.len(),
            0,
            "Custom TTL must NEVER override RFC 9111 no-store mandate"
        );
    }

    #[test]
    fn test_rfc9111_custom_ttl_cannot_override_private() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("cache-control", HeaderValue::from_static("private"));

        cache.put(
            "http://example.com/private".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"user-profile"),
            Some(Duration::from_secs(600)),
            None,
        );
        assert_eq!(
            cache.len(),
            0,
            "Custom TTL must NEVER override RFC 9111 private directive in shared cache"
        );
    }

    #[test]
    fn test_rfc9111_custom_ttl_cannot_override_vary_star() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("vary", HeaderValue::from_static("*"));

        cache.put(
            "http://example.com/vary-star".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"dynamic"),
            Some(Duration::from_secs(600)),
            None,
        );
        assert_eq!(
            cache.len(),
            0,
            "Custom TTL must NEVER override RFC 9111 Vary: * rejection"
        );
    }

    #[test]
    fn test_rfc9111_authorization_rejected_without_public_or_s_maxage() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token-xyz"),
        );

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("cache-control", HeaderValue::from_static("max-age=300"));

        cache.put(
            "http://example.com/auth-resource".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"authenticated-content"),
            Some(Duration::from_secs(300)),
            Some(&req_headers),
        );
        assert_eq!(
            cache.len(),
            0,
            "Shared cache MUST NOT store response to request with Authorization unless public or s-maxage is present"
        );
    }

    #[test]
    fn test_rfc9111_authorization_allowed_with_public() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token-xyz"),
        );

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=300"),
        );

        cache.put(
            "http://example.com/public-auth-resource".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"publicly-shared-content"),
            None,
            Some(&req_headers),
        );
        assert_eq!(
            cache.len(),
            1,
            "Shared cache is permitted to store response to Authorization request if marked public"
        );
    }

    #[test]
    fn test_rfc9111_set_cookie_stripped_from_cached_response() {
        let cache = EdgeCache::new(true, 3600, 10, 1024 * 1024);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=300"),
        );
        resp_headers.insert(
            "set-cookie",
            HeaderValue::from_static("session_id=attacker_or_user_secret; Path=/; HttpOnly"),
        );

        cache.put(
            "http://example.com/set-cookie-page".to_string(),
            StatusCode::OK,
            resp_headers,
            Bytes::from_static(b"page-content"),
            None,
            None,
        );

        let cached = cache.get("http://example.com/set-cookie-page", None);
        assert!(cached.is_some(), "Page should be cached");
        let cached_resp = cached.unwrap();
        assert!(
            !cached_resp.headers.contains_key("set-cookie"),
            "Set-Cookie MUST be stripped from shared cache response to prevent credential leakage"
        );
    }
}
