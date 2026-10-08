use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::StatusCode;
use std::collections::HashMap;
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

#[derive(Default)]
struct CacheStore {
    current_bytes: usize,
    entries: HashMap<String, Vec<CachedResponse>>,
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
            max_bytes: if max_bytes == 0 { 100 * 1024 * 1024 } else { max_bytes },
            store: Arc::new(RwLock::new(CacheStore::default())),
        }
    }

    /// Retrieve cached response matching primary key and incoming request headers for Vary verification
    pub fn get(&self, key: &str, req_headers: Option<&HeaderMap>) -> Option<CachedResponse> {
        if !self.enabled {
            return None;
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

        let ttl = custom_ttl.unwrap_or(self.default_ttl);
        let entry = CachedResponse {
            status,
            headers,
            body,
            expires_at: Instant::now() + ttl,
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
            store.entries.get_mut(&key).unwrap()[idx] = entry;
            store.current_bytes = store.current_bytes.saturating_sub(old_bytes) + entry_bytes;
            return;
        }

        // 2. Count total active variants across all keys
        let mut total_entries: usize = store.entries.values().map(|v| v.len()).sum();

        // 3. Evict expired entries if approaching count or byte limit
        if total_entries >= self.max_entries || store.current_bytes + entry_bytes > self.max_bytes {
            let now = Instant::now();
            let mut expired_bytes = 0usize;
            for variants in store.entries.values_mut() {
                variants.retain(|v| {
                    if v.expires_at <= now {
                        expired_bytes += v.size_in_bytes();
                        false
                    } else {
                        true
                    }
                });
            }
            store.current_bytes = store.current_bytes.saturating_sub(expired_bytes);
            store.entries.retain(|_, v| !v.is_empty());
            total_entries = store.entries.values().map(|v| v.len()).sum();
        }

        // 4. Hard capacity guarantee (both count and byte budget): Evict earliest expiring entry until within limits
        while (total_entries >= self.max_entries || store.current_bytes + entry_bytes > self.max_bytes) && !store.entries.is_empty() {
            let mut earliest_expiry: Option<(String, usize, Instant)> = None;

            for (k, variants) in store.entries.iter() {
                for (idx, v) in variants.iter().enumerate() {
                    match earliest_expiry {
                        None => earliest_expiry = Some((k.clone(), idx, v.expires_at)),
                        Some((_, _, min_exp)) if v.expires_at < min_exp => {
                            earliest_expiry = Some((k.clone(), idx, v.expires_at));
                        }
                        _ => {}
                    }
                }
            }

            if let Some((victim_key, victim_idx, _)) = earliest_expiry {
                let mut victim_bytes = 0;
                if let Some(variants) = store.entries.get_mut(&victim_key) {
                    if victim_idx < variants.len() {
                        let victim = variants.remove(victim_idx);
                        victim_bytes = victim.size_in_bytes();
                    }
                }
                store.current_bytes = store.current_bytes.saturating_sub(victim_bytes);
                if let Some(variants) = store.entries.get(&victim_key) {
                    if variants.is_empty() {
                        store.entries.remove(&victim_key);
                    }
                }
                total_entries = store.entries.values().map(|v| v.len()).sum();
            } else {
                break;
            }
        }

        // 5. Insert new variant and increment byte count
        store.current_bytes += entry_bytes;
        let variants = store.entries.entry(key).or_default();
        variants.push(entry);
    }

    #[allow(dead_code)]
    pub fn purge(&self, key: &str) {
        let mut store = self.store.write().unwrap();
        if let Some(variants) = store.entries.remove(key) {
            for v in variants {
                store.current_bytes = store.current_bytes.saturating_sub(v.size_in_bytes());
            }
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.store.read().unwrap().entries.values().map(|v| v.len()).sum()
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
}
