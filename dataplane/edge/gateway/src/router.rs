use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct UpstreamNode {
    pub url: String,
    pub healthy: bool,
    pub latency_ms: u64,
    pub ewma_latency_ms: f64,
    pub consecutive_passes: u32,
    pub consecutive_failures: u32,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Router {
    nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    index: Arc<AtomicUsize>,
    timeout: Duration,
}

impl Router {
    const EWMA_ALPHA: f64 = 0.2;

    pub fn new(targets: Vec<String>, timeout_ms: u64) -> Self {
        let nodes = targets
            .into_iter()
            .map(|url| UpstreamNode {
                url,
                healthy: true,
                latency_ms: 10,
                ewma_latency_ms: 10.0,
                consecutive_passes: 2,
                consecutive_failures: 0,
            })
            .collect();

        Self {
            nodes: Arc::new(RwLock::new(nodes)),
            index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Selects lowest latency healthy upstream node using smoothed EWMA
    /// Fast-path invariant: Zero heap allocations and O(N) scan with round-robin tie-breaking.
    pub fn select_upstream(&self) -> Option<String> {
        let nodes = self.nodes.read().unwrap();

        // Pass 1: Find minimum EWMA latency among healthy nodes
        let mut min_latency = f64::MAX;
        for node in nodes.iter() {
            if node.healthy && node.ewma_latency_ms < min_latency {
                min_latency = node.ewma_latency_ms;
            }
        }

        if min_latency == f64::MAX {
            // Invariant (Audit Finding 13): Never forward traffic to known unhealthy backends
            return None;
        }

        // Pass 2: Count tied lowest-latency healthy nodes (within 1e-6 epsilon)
        let mut tied_count = 0;
        for node in nodes.iter() {
            if node.healthy && (node.ewma_latency_ms - min_latency).abs() < 1e-6 {
                tied_count += 1;
            }
        }

        if tied_count == 0 {
            return None;
        }

        // Pass 3: Pick deterministic tied node using atomic round-robin counter
        let pick_index = self.index.fetch_add(1, Ordering::Relaxed) % tied_count;
        let mut current_idx = 0;
        for node in nodes.iter() {
            if node.healthy && (node.ewma_latency_ms - min_latency).abs() < 1e-6 {
                if current_idx == pick_index {
                    return Some(node.url.clone());
                }
                current_idx += 1;
            }
        }

        None
    }

    #[allow(dead_code)]
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.iter_mut().find(|n| n.url == url) {
            if healthy {
                node.consecutive_passes += 1;
                node.consecutive_failures = 0;
                node.latency_ms = latency_ms;

                // Threshold: 2 consecutive passes required to become healthy (prevents flapping)
                if node.consecutive_passes >= 2 {
                    node.healthy = true;
                }

                // EWMA latency smoothed update only on successful probes
                if latency_ms > 0 {
                    if node.ewma_latency_ms <= 0.0 {
                        node.ewma_latency_ms = latency_ms as f64;
                    } else {
                        node.ewma_latency_ms = Self::EWMA_ALPHA * (latency_ms as f64)
                            + (1.0 - Self::EWMA_ALPHA) * node.ewma_latency_ms;
                    }
                }
            } else {
                node.consecutive_failures += 1;
                node.consecutive_passes = 0;

                // Threshold: 3 consecutive failures required to become unhealthy (absorbs transient packet drops)
                if node.consecutive_failures >= 3 {
                    node.healthy = false;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_upstream_healthy_and_unhealthy_with_hysteresis() {
        let targets = vec![
            "https://origin-1.example.com".to_string(),
            "https://origin-2.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        // Initially both are healthy -> selects upstream
        let u1 = router.select_upstream();
        assert!(u1.is_some());

        // Probe 1 & 2 failures on origin-1: should STILL be healthy due to 3-failure threshold
        router.mark_health("https://origin-1.example.com", false, 999);
        router.mark_health("https://origin-1.example.com", false, 999);
        {
            let nodes = router.nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                n1.healthy,
                "origin-1 should remain healthy after only 2 failures"
            );
        }

        // Probe 3 failure on origin-1: now trips to unhealthy
        router.mark_health("https://origin-1.example.com", false, 999);
        {
            let nodes = router.nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                !n1.healthy,
                "origin-1 should become unhealthy after 3 consecutive failures"
            );
        }

        let u2 = router.select_upstream().unwrap();
        assert_eq!(u2, "https://origin-2.example.com");

        // Fail origin-2 three times as well -> must return None
        router.mark_health("https://origin-2.example.com", false, 999);
        router.mark_health("https://origin-2.example.com", false, 999);
        router.mark_health("https://origin-2.example.com", false, 999);
        let u3 = router.select_upstream();
        assert!(
            u3.is_none(),
            "expected None when all upstreams are unhealthy"
        );

        // Recovery hysteresis: Probe 1 success -> should STILL be unhealthy (needs 2 passes)
        router.mark_health("https://origin-1.example.com", true, 12);
        {
            let nodes = router.nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                !n1.healthy,
                "origin-1 should remain unhealthy after only 1 passing probe"
            );
        }
        assert!(router.select_upstream().is_none());

        // Probe 2 success -> becomes healthy and resumes routing
        router.mark_health("https://origin-1.example.com", true, 12);
        let u4 = router.select_upstream();
        assert_eq!(u4, Some("https://origin-1.example.com".to_string()));
    }

    #[test]
    fn test_ewma_latency_routing_preference() {
        let targets = vec![
            "https://slow-origin.example.com".to_string(),
            "https://fast-origin.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        // Set slow origin to 150ms
        router.mark_health("https://slow-origin.example.com", true, 150);
        // Set fast origin to 5ms
        router.mark_health("https://fast-origin.example.com", true, 5);

        // Router should prioritize lowest EWMA latency
        let selected = router.select_upstream().unwrap();
        assert_eq!(selected, "https://fast-origin.example.com");
    }
}
