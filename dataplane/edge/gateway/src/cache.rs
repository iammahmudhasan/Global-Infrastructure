use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::StatusCode;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct EdgeCache {
    enabled: bool,
    default_ttl: Duration,
    max_entries: usize,
    store: Arc<RwLock<HashMap<String, CachedResponse>>>,
}

impl EdgeCache {
    pub fn new(enabled: bool, ttl_seconds: u64, max_entries: usize) -> Self {
        Self {
            enabled,
            default_ttl: Duration::from_secs(ttl_seconds),
            max_entries,
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedResponse> {
        if !self.enabled {
            return None;
        }

        let store = self.store.read().unwrap();
        if let Some(entry) = store.get(key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.clone());
            }
        }
        None
    }

    pub fn put(
        &self,
        key: String,
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        custom_ttl: Option<Duration>,
    ) {
        if !self.enabled || !status.is_success() {
            return;
        }

        let ttl = custom_ttl.unwrap_or(self.default_ttl);
        let entry = CachedResponse {
            status,
            headers,
            body,
            expires_at: Instant::now() + ttl,
        };

        let mut store = self.store.write().unwrap();
        if store.len() >= self.max_entries {
            // 1. Evict expired entries
            let now = Instant::now();
            store.retain(|_, v| v.expires_at > now);

            // 2. Hard capacity guarantee (Finding 11): If still at capacity, evict earliest expiring entry
            if store.len() >= self.max_entries {
                let victim = store
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone());

                if let Some(victim_key) = victim {
                    store.remove(&victim_key);
                }
            }
        }

        store.insert(key, entry);
    }

    #[allow(dead_code)]
    pub fn purge(&self, key: &str) {
        let mut store = self.store.write().unwrap();
        store.remove(key);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.store.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hard_max_entries_eviction() {
        let cache = EdgeCache::new(true, 3600, 2);
        let headers = HeaderMap::new();
        let body = Bytes::from("payload");

        cache.put(
            "k1".to_string(),
            StatusCode::OK,
            headers.clone(),
            body.clone(),
            Some(Duration::from_secs(10)),
        );
        cache.put(
            "k2".to_string(),
            StatusCode::OK,
            headers.clone(),
            body.clone(),
            Some(Duration::from_secs(30)),
        );
        assert_eq!(cache.len(), 2);

        // Insert 3rd entry when capacity is 2; k1 has earlier expiry (10s vs 30s) so k1 must be evicted
        cache.put(
            "k3".to_string(),
            StatusCode::OK,
            headers,
            body,
            Some(Duration::from_secs(20)),
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.get("k1").is_none(), "k1 should have been evicted");
        assert!(cache.get("k2").is_some(), "k2 should be retained");
        assert!(cache.get("k3").is_some(), "k3 should be present");
    }
}
