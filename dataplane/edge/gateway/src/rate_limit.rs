use std::collections::HashMap;
use std::net::IpAddr;
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

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    capacity: f64,
    refill_rate: f64,
    max_buckets: usize,
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
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
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn check(&self, client_ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }

        let mut buckets = self.buckets.write().unwrap();
        if !buckets.contains_key(&client_ip) && buckets.len() >= self.max_buckets {
            // Evict oldest bucket by last_update to prevent memory exhaustion (Finding 3)
            if let Some((&oldest_ip, _)) = buckets
                .iter()
                .min_by_key(|(_, b)| b.last_update)
            {
                buckets.remove(&oldest_ip);
            }
        }

        let bucket = buckets
            .entry(client_ip)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));

        bucket.try_consume(1.0)
    }

    pub fn cleanup_stale(&self) {
        let mut buckets = self.buckets.write().unwrap();
        let now = Instant::now();
        // Remove buckets not accessed in 10 minutes
        buckets.retain(|_, b| now.duration_since(b.last_update).as_secs() < 600);
    }

    #[allow(dead_code)]
    pub fn bucket_count(&self) -> usize {
        self.buckets.read().unwrap().len()
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
        assert!(!buckets.contains_key(&ip1), "ip1 should have been evicted");
        assert!(buckets.contains_key(&ip2));
        assert!(buckets.contains_key(&ip3));
    }
}
