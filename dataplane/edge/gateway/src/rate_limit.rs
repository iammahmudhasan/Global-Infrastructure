use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Instant;

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    refill_rate_per_sec: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate_per_sec,
        }
    }

    fn try_consume(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * self.refill_rate_per_sec).min(self.capacity);

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct BucketStore {
    buckets: HashMap<String, TokenBucket>,
    access_queue: VecDeque<(String, Instant)>,
}

impl Deref for BucketStore {
    type Target = HashMap<String, TokenBucket>;

    fn deref(&self) -> &Self::Target {
        &self.buckets
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    capacity: f64,
    refill_rate: f64,
    max_buckets: usize,
    buckets: Arc<RwLock<BucketStore>>,
}

impl RateLimiter {
    pub const MAX_RATE_LIMIT_BUCKETS: usize = 100_000;

    pub fn new(enabled: bool, rps: u32, capacity: u32) -> Self {
        Self::with_max_buckets(enabled, rps, capacity, Self::MAX_RATE_LIMIT_BUCKETS)
    }

    pub fn with_max_buckets(enabled: bool, rps: u32, capacity: u32, max_buckets: usize) -> Self {
        Self {
            enabled,
            capacity: capacity as f64,
            refill_rate: rps as f64,
            max_buckets,
            buckets: Arc::new(RwLock::new(BucketStore::default())),
        }
    }

    #[allow(dead_code)]
    pub fn check(&self, client_ip: IpAddr) -> bool {
        self.check_key(&client_ip.to_string(), None, None)
    }

    pub fn check_key(&self, key: &str, custom_rps: Option<u32>, custom_burst: Option<u32>) -> bool {
        if !self.enabled {
            return true;
        }

        let mut store = self.buckets.write().unwrap();
        if !store.buckets.contains_key(key) && store.buckets.len() >= self.max_buckets {
            // Amortized O(1) eviction via lazy LRU access queue (Finding 5)
            while let Some((candidate_key, candidate_ts)) = store.access_queue.pop_front() {
                if let Some(bucket) = store.buckets.get(&candidate_key) {
                    if bucket.last_update == candidate_ts {
                        store.buckets.remove(&candidate_key);
                        break;
                    }
                }
            }
        }

        let capacity = custom_burst.map(|c| c as f64).unwrap_or(self.capacity);
        let refill_rate = custom_rps.map(|r| r as f64).unwrap_or(self.refill_rate);
        let bucket = store
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        let allowed = bucket.try_consume(1.0);
        let update_time = bucket.last_update;
        store.access_queue.push_back((key.to_string(), update_time));

        // Periodic hygiene: trim dead items from access_queue if it grows significantly larger than capacity
        if store.access_queue.len() > self.max_buckets * 3 {
            let BucketStore {
                buckets,
                access_queue,
            } = &mut *store;
            access_queue.retain(|(k, ts)| buckets.get(k).is_some_and(|b| b.last_update == *ts));
        }

        allowed
    }

    pub fn cleanup_stale(&self) {
        let mut store = self.buckets.write().unwrap();
        let now = Instant::now();
        // Remove buckets not accessed in 10 minutes
        store
            .buckets
            .retain(|_, b| now.duration_since(b.last_update).as_secs() < 600);
    }

    #[allow(dead_code)]
    pub fn bucket_count(&self) -> usize {
        self.buckets.read().unwrap().buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_basic_consumption() {
        let limiter = RateLimiter::new(true, 10, 2);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip)); // Burst exceeded
    }

    #[test]
    fn test_max_bucket_cardinality_eviction() {
        // Limit to max 2 buckets
        let limiter = RateLimiter::with_max_buckets(true, 10, 10, 2);
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(limiter.check(ip1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.check(ip2));
        assert_eq!(limiter.bucket_count(), 2);

        // ip3 should trigger eviction of oldest bucket (ip1)
        assert!(limiter.check(ip3));
        assert_eq!(limiter.bucket_count(), 2);

        let buckets = limiter.buckets.read().unwrap();
        assert!(
            !buckets.contains_key(&ip1.to_string()),
            "ip1 should have been evicted"
        );
        assert!(buckets.contains_key(&ip2.to_string()));
        assert!(buckets.contains_key(&ip3.to_string()));
    }

    #[test]
    fn test_lru_bucket_eviction_order() {
        let limiter = RateLimiter::with_max_buckets(true, 10, 10, 2);
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(limiter.check(ip1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.check(ip2));
        std::thread::sleep(std::time::Duration::from_millis(5));
        // Access ip1 again, making ip2 the least recently used
        assert!(limiter.check(ip1));

        // ip3 should trigger eviction of LRU bucket (ip2)
        assert!(limiter.check(ip3));
        assert_eq!(limiter.bucket_count(), 2);

        let buckets = limiter.buckets.read().unwrap();
        assert!(
            buckets.contains_key(&ip1.to_string()),
            "ip1 was refreshed so it must remain"
        );
        assert!(
            !buckets.contains_key(&ip2.to_string()),
            "ip2 was LRU so it must be evicted"
        );
        assert!(
            buckets.contains_key(&ip3.to_string()),
            "ip3 must be present"
        );
    }
}
