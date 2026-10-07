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
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
}

impl RateLimiter {
    pub fn new(enabled: bool, rps: u32, capacity: u32) -> Self {
        Self {
            enabled,
            capacity: capacity as f64,
            refill_rate: rps as f64,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn check(&self, client_ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }

        let mut buckets = self.buckets.write().unwrap();
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
}
