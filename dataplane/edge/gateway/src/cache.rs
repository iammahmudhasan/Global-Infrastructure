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

    pub fn put(&self, key: String, status: StatusCode, headers: HeaderMap, body: Bytes, custom_ttl: Option<Duration>) {
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
            // Evict expired entries
            let now = Instant::now();
            store.retain(|_, v| v.expires_at > now);
        }

        store.insert(key, entry);
    }

    #[allow(dead_code)]
    pub fn purge(&self, key: &str) {
        let mut store = self.store.write().unwrap();
        store.remove(key);
    }
}
